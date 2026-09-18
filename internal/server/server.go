// Package server implements the relay SSH front door: one listener, three
// connection classes (device, status, client), auth pass-through to the
// device, and the request policy gates (ARCHITECTURE §5–§6).
package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/quangdz/ssh-relay/internal/config"
	"github.com/quangdz/ssh-relay/internal/devconn"
	"github.com/quangdz/ssh-relay/internal/guard"
	"github.com/quangdz/ssh-relay/internal/policy"
	"github.com/quangdz/ssh-relay/internal/registry"
)

// TCPForwardWarning is the exact refusal text required by the UX contract.
const TCPForwardWarning = "[WARNING] TCP forwarding is not supported."

const (
	handshakeTimeout = 30 * time.Second
	deviceDialWrap   = 10 * time.Second
	// maxConns caps total authenticated connections.
	maxConns = 1024
	// maxChannelsPerClientConn caps direct-tcpip fan-out (SOCKS-friendly).
	maxChannelsPerClientConn = 64
	// maxBridgesPerAlias caps concurrent end-user sessions per binding.
	maxBridgesPerAlias = 10
)

// PolicySource provides the current policy set (hot-reloadable).
type PolicySource interface {
	Current() *policy.PolicySet
}

// Deps wires the server to its collaborators.
type Deps struct {
	Cfg           *config.Config
	BasePolicy    policy.Effective // builtin + file default + explicit flags
	Policy        PolicySource
	Registry      *registry.Registry
	IPLimit       *guard.IPLimiter
	Ban           *guard.Fail2ban
	HostKey       ssh.Signer
	Log           *slog.Logger
	Version       string
	AdvertiseHost string
}

// Server is the relay front door.
type Server struct {
	deps Deps
	log  *slog.Logger

	authStash sync.Map // sessionID string → stashedAuth
	sem       chan struct{}
	wg        sync.WaitGroup
}

// stashedAuth is the end user's pass-through device login: either a ready
// device-side SSH client (none/password/keyboard-interactive paths, established
// during the client's authentication) or a pending public key that is
// completed lazily via the client's forwarded agent (M6 pubkey pass-through).
type stashedAuth struct {
	mu  sync.Mutex
	dev *ssh.Client
	// The device's sshd opens agent/x11 channels back toward its client
	// (which is us); the x/crypto mux only delivers opens for types
	// registered via HandleChannelOpen at dial time (§5.3), so they arrive
	// on these dedicated sources instead of a shared feeder.
	devAgentChans <-chan ssh.NewChannel
	devX11Chans   <-chan ssh.NewChannel
	devReqs       <-chan *ssh.Request
	binding       *registry.Binding
	deviceUser    string
	// pubkey != nil means the client authenticated with this key but the
	// device login is still pending; it completes in ensureUpstream through
	// the client's forwarded ssh-agent (the key never leaves the client).
	pubkey ssh.PublicKey
	// pubkeyAuth records that the login used a public key: agent forwarding
	// (§5.2.1 + session mirroring) activates only for these connections.
	pubkeyAuth bool
	at         time.Time
}

// New builds a Server.
func New(deps Deps) *Server {
	return &Server{deps: deps, log: deps.Log, sem: make(chan struct{}, maxConns)}
}

// Serve runs until ctx is cancelled or the listener fails.
func (s *Server) Serve(ctx context.Context, lis net.Listener) error {
	srvCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	s.wg.Add(1)
	go s.stashJanitor(srvCtx)

	go func() {
		<-srvCtx.Done()
		lis.Close()
	}()

	for {
		nc, err := lis.Accept()
		if err != nil {
			select {
			case <-srvCtx.Done():
				s.wg.Wait()
				return nil
			default:
			}
			return fmt.Errorf("accept: %w", err)
		}
		select {
		case s.sem <- struct{}{}:
		case <-srvCtx.Done():
			nc.Close()
			s.wg.Wait()
			return nil
		}
		s.wg.Add(1)
		go func() {
			defer func() { <-s.sem; s.wg.Done() }()
			defer nc.Close()
			s.handleConn(srvCtx, nc)
		}()
	}
}

// st is the per-connection state derived after the TCP accept.
type st struct {
	ip  string
	eff policy.Effective
}

func (s *Server) handleConn(ctx context.Context, nc net.Conn) {
	remote := nc.RemoteAddr().String()
	ip, ok := sourceIP(remote)
	if !ok {
		s.log.Warn("unparseable remote address, dropping", "remote", remote)
		return
	}
	eff := s.deps.BasePolicy
	if a, err := netip.ParseAddr(ip); err == nil {
		eff = s.deps.Policy.Current().EffectiveFor(s.deps.BasePolicy, a)
	}
	state := &st{ip: ip, eff: eff}

	if state.eff.Blocked {
		s.log.Info("connection blocked by policy", "ip", ip, "reason", state.eff.BlockReason)
		return
	}
	if banned, d := s.deps.Ban.Banned(ip); banned {
		s.log.Warn("banned source", "ip", ip, "remaining", d.String())
		return
	}

	// Pre-auth grace: force the handshake+auth to finish in time.
	nc.SetDeadline(time.Now().Add(handshakeTimeout))
	sc, chans, reqs, err := ssh.NewServerConn(nc, s.serverConfig())
	if err != nil {
		s.log.Debug("handshake failed", "ip", ip, "err", err)
		return
	}
	nc.SetDeadline(time.Time{}) // authenticated; rely on keepalives instead

	// Per-IP concurrent session accounting (device and client conns count
	// equally, ARCHITECTURE §7.1); released when the connection ends.
	if !s.deps.IPLimit.Acquire(state.ip, state.eff.MaxSessionsPerIP) {
		s.log.Info("connection over per-ip session limit", "ip", ip, "user", sc.User(), "used", s.deps.IPLimit.Used(ip), "allowed", state.eff.MaxSessionsPerIP)
		return
	}
	defer s.deps.IPLimit.Release(state.ip)

	cls, err := Classify(sc.User())
	if err != nil {
		s.log.Warn("classification failed post-auth", "ip", ip, "user", sc.User(), "err", err)
		sc.Close()
		return
	}
	s.log.Info("connection authenticated", "ip", ip, "user", sc.User(), "role", cls.Role.String())

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	switch cls.Role {
	case RoleDevice, RoleDeviceJSON:
		s.handleDevice(ctx, sc, chans, reqs, state, cls.Role == RoleDeviceJSON)
	case RoleStatus:
		s.handleStatus(ctx, sc, chans, reqs, state)
	case RoleClient:
		s.handleClient(ctx, sc, chans, reqs, state)
	}
}

func (s *Server) serverConfig() *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		MaxAuthTries: 6,
		// NoClientAuth=true + callback = per-connection "none" decisions
		// (x/crypto requires both): open roles pass instantly, client roles
		// probe the device for passwordless sshd before falling back to
		// password prompts.
		NoClientAuth: true,
		NoClientAuthCallback: func(md ssh.ConnMetadata) (*ssh.Permissions, error) {
			cls, err := Classify(md.User())
			if err != nil {
				return nil, err
			}
			switch cls.Role {
			case RoleDevice, RoleDeviceJSON, RoleStatus:
				return &ssh.Permissions{}, nil // open roles: no credentials needed
			case RoleClient:
				return s.authClient(md, cls, "") // device may accept "none"
			}
			return nil, fmt.Errorf("unsupported role")
		},
		PasswordCallback: func(md ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			cls, err := Classify(md.User())
			if err != nil {
				return nil, err
			}
			switch cls.Role {
			case RoleDevice, RoleDeviceJSON, RoleStatus:
				return &ssh.Permissions{}, nil
			case RoleClient:
				return s.authClient(md, cls, string(password))
			}
			return nil, fmt.Errorf("unsupported role")
		},
		KeyboardInteractiveCallback: func(md ssh.ConnMetadata, challenger ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			cls, err := Classify(md.User())
			if err != nil {
				return nil, err
			}
			switch cls.Role {
			case RoleDevice, RoleDeviceJSON, RoleStatus:
				return &ssh.Permissions{}, nil
			case RoleClient:
				answers, err := challenger(md.User(), "Device login required.", []string{"Password:"}, []bool{true})
				if err != nil || len(answers) == 0 {
					return nil, fmt.Errorf("no answer provided")
				}
				return s.authClient(md, cls, answers[0])
			}
			return nil, fmt.Errorf("unsupported role")
		},
		PublicKeyCallback: func(md ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			cls, err := Classify(md.User())
			if err != nil {
				return nil, err
			}
			switch cls.Role {
			case RoleDevice, RoleDeviceJSON, RoleStatus:
				return &ssh.Permissions{}, nil
			case RoleClient:
				return s.authClientPubkey(md, cls, key)
			}
			return nil, fmt.Errorf("unsupported role")
		},
	}
	cfg.AddHostKey(s.deps.HostKey)
	return cfg
}

// authClient performs the pass-through device login. password may be empty to
// probe "none" auth (passwordless device sshd). x/crypto's client handshake
// always sends "none" first, so a single dial covers both: passwordless
// devices succeed immediately, password devices fall through to the password
// attempt. The established device client is stashed for the session handler.
func (s *Server) authClient(md ssh.ConnMetadata, cls Classification, password string) (*ssh.Permissions, error) {
	binding, ok := s.deps.Registry.Lookup(cls.Alias)
	if !ok {
		return nil, fmt.Errorf("no live tunnel for %q", cls.Alias)
	}
	if !binding.AcquireBridge() {
		return nil, fmt.Errorf("tunnel %q is at its session capacity", cls.Alias)
	}
	released := false
	release := func() {
		if !released {
			released = true
			binding.ReleaseBridge()
		}
	}

	dev, devAgentChans, devX11Chans, devReqs, err := s.dialDevice(md, binding, cls.DeviceUser, password)
	if err != nil {
		release()
		if password != "" {
			if banned := s.deps.Ban.Failure(sourceIPString(md.RemoteAddr())); banned {
				s.log.Warn("ip banned after repeated auth failures", "ip", sourceIPString(md.RemoteAddr()), "alias", cls.Alias)
			} else {
				s.log.Info("device rejected credentials", "ip", sourceIPString(md.RemoteAddr()), "alias", cls.Alias, "user", cls.DeviceUser)
			}
		}
		return nil, fmt.Errorf("device login failed: %w", err)
	}
	s.deps.Ban.Success(sourceIPString(md.RemoteAddr()))

	id := base64.RawStdEncoding.EncodeToString(md.SessionID())
	s.authStash.Store(id, &stashedAuth{
		dev:           dev,
		devAgentChans: devAgentChans,
		devX11Chans:   devX11Chans,
		devReqs:       devReqs,
		binding:       binding,
		deviceUser:    cls.DeviceUser,
		at:            time.Now(),
	})
	// The bridge slot stays held for the whole connection; handleClient owns
	// the matching ReleaseBridge.
	return &ssh.Permissions{}, nil
}

// authClientPubkey accepts an end user's public key. Signatures bind the
// session ID, so the client's signature over the relay's session ID cannot be
// replayed to the device (ARCHITECTURE §5); instead the device login completes
// lazily through the client's forwarded ssh-agent: the agent signs the
// device's challenge, and the device still verifies the user's real key. The
// private key never leaves the client. No device dial happens here — the
// agent channel only exists once the client's session is set up — so the
// binding slot is reserved now and ensureUpstream finishes the login.
func (s *Server) authClientPubkey(md ssh.ConnMetadata, cls Classification, key ssh.PublicKey) (*ssh.Permissions, error) {
	binding, ok := s.deps.Registry.Lookup(cls.Alias)
	if !ok {
		return nil, fmt.Errorf("no live tunnel for %q", cls.Alias)
	}
	if !binding.AcquireBridge() {
		return nil, fmt.Errorf("tunnel %q is at its session capacity", cls.Alias)
	}
	s.log.Info("client public key accepted (device login deferred to agent)",
		"ip", sourceIPString(md.RemoteAddr()), "alias", cls.Alias,
		"fingerprint", ssh.FingerprintSHA256(key), "type", key.Type())
	id := base64.RawStdEncoding.EncodeToString(md.SessionID())
	s.authStash.Store(id, &stashedAuth{
		binding:    binding,
		deviceUser: cls.DeviceUser,
		pubkey:     key,
		pubkeyAuth: true,
		at:         time.Now(),
	})
	return &ssh.Permissions{}, nil
}

// popAuth takes the stashed device login for this connection.
func (s *Server) popAuth(sc *ssh.ServerConn) (*stashedAuth, bool) {
	id := base64.RawStdEncoding.EncodeToString(sc.SessionID())
	v, ok := s.authStash.LoadAndDelete(id)
	if !ok {
		return nil, false
	}
	return v.(*stashedAuth), true
}

// dialDevice runs the Phase-2 handshake: a forwarded-tcpip channel through
// the tunnel wrapped as net.Conn, then an SSH client handshake against the
// device's sshd. It returns the client plus its inbound channel/request
// streams (the caller must drain them or the mux stalls).
func (s *Server) dialDevice(md ssh.ConnMetadata, binding *registry.Binding, deviceUser, password string) (*ssh.Client, <-chan ssh.NewChannel, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	var auth []ssh.AuthMethod
	if password != "" {
		auth = append(auth, ssh.Password(password))
	}
	return s.dialDeviceAuth(md, binding, deviceUser, auth)
}

// dialDeviceAuth is dialDevice with explicit auth methods (agent-backed
// publickey signers for the deferred pubkey path). The returned channel
// sources are the HandleChannelOpen feeders for the types the device may
// open back (auth-agent/x11); the caller must drain them.
func (s *Server) dialDeviceAuth(md ssh.ConnMetadata, binding *registry.Binding, deviceUser string, auth []ssh.AuthMethod) (*ssh.Client, <-chan ssh.NewChannel, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	origin := "relay"
	if md != nil {
		origin = sourceIPString(md.RemoteAddr())
	}
	nc, err := devconn.DialThrough(binding.Owner, binding.ListenAddr, binding.VirtualPort, origin)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	nc.SetDeadline(time.Now().Add(deviceDialWrap))

	cfg := &ssh.ClientConfig{
		User: deviceUser,
		Auth: auth,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			s.log.Debug("device host key (accepted, logged)",
				"alias", binding.Alias, "fingerprint", ssh.FingerprintSHA256(key))
			return nil
		},
	}
	c, chans, reqs, err := ssh.NewClientConn(nc, "device", cfg)
	if err != nil {
		nc.Close()
		return nil, nil, nil, nil, err
	}
	nc.SetDeadline(time.Time{})
	dev := ssh.NewClient(c, chans, reqs)
	// Register the reverse channel types before the device's sshd uses
	// them: unregistered opens are rejected by the client mux itself with
	// "unknown channel type", which would silently break session agent
	// forwarding and x11 (ARCHITECTURE §5.3). Everything else stays
	// mux-rejected — the right default for a public relay.
	agentChans := dev.HandleChannelOpen("auth-agent@openssh.com")
	x11Chans := dev.HandleChannelOpen("x11")
	return dev, agentChans, x11Chans, reqs, nil
}

// stashJanitor removes auth stash entries whose handshake never completed
// (crashed clients between callback and handler).
func (s *Server) stashJanitor(ctx context.Context) {
	defer s.wg.Done()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cutoff := time.Now().Add(-5 * time.Minute)
			s.authStash.Range(func(key, v any) bool {
				e := v.(*stashedAuth)
				if e.at.Before(cutoff) {
					s.authStash.Delete(key)
					if e.dev != nil {
						e.dev.Close()
					}
					e.binding.ReleaseBridge()
				}
				return true
			})
		}
	}
}

// sourceIP extracts a normalizable IP string from a host:port address.
func sourceIP(addr string) (string, bool) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), true
	}
	return "", false
}

// ioCopy is io.Copy with a 32 KiB buffer sized for typical SSH channel windows.
func ioCopy(dst io.Writer, src io.Reader) (int64, error) {
	return io.CopyBuffer(dst, src, make([]byte, 32*1024))
}

func sourceIPString(addr net.Addr) string {
	if s, ok := sourceIP(addr.String()); ok {
		return s
	}
	return addr.String()
}
