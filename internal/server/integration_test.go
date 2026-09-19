package server

// In-process end-to-end tests: a fake device sshd (x/crypto/ssh server)
// registers into a live relay exactly like `ssh -R ...` does, then real flows
// run through the relay: registration, password pass-through bridges,
// direct-tcpip (allowed + gated), the exact TCP-forwarding warning, status
// JSON, per-IP limits and fail2ban.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/quangdz/ssh-relay/internal/config"
	"github.com/quangdz/ssh-relay/internal/devconn"
	"github.com/quangdz/ssh-relay/internal/guard"
	"github.com/quangdz/ssh-relay/internal/policy"
	"github.com/quangdz/ssh-relay/internal/registry"
)

// ---------- fake device sshd ----------

type fakeDevice struct {
	mu         sync.Mutex
	passwords  []string
	sessions   []string
	agentKeys  []string      // key types seen through the forwarded agent
	pubkey     ssh.PublicKey // when set, this client key authenticates
	pubkeyOnly bool          // when true, password auth is refused outright
}

func (f *fakeDevice) serverConfig(t *testing.T) *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		// Only "devpass" authenticates; everything else is recorded and
		// refused so pass-through failures and fail2ban can be exercised.
		PasswordCallback: func(md ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			f.mu.Lock()
			f.passwords = append(f.passwords, string(password))
			f.mu.Unlock()
			if f.pubkeyOnly {
				return nil, fmt.Errorf("password auth disabled on this device")
			}
			if string(password) == "devpass" {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("wrong password")
		},
	}
	if f.pubkey != nil {
		authorized := f.pubkey
		cfg.PublicKeyCallback = func(md ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), authorized.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("key not authorized")
		}
	}
	cfg.AddHostKey(testHostKey(t))
	return cfg
}

// serveControl plays the device side of a `ssh -R` control connection:
// forwarded-tcpip opens are accepted and become fresh sshd sessions
// (Phase-2 handshakes land here), everything else mirrors an OpenSSH client.
func (f *fakeDevice) serveControl(t *testing.T, conn ssh.Conn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	go func() {
		for req := range reqs {
			if req.Type == "keepalive@openssh.com" {
				req.Reply(true, nil)
				continue
			}
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}()
	for nch := range chans {
		switch nch.ChannelType() {
		case "forwarded-tcpip":
			ch, _, err := nch.Accept()
			if err != nil {
				continue
			}
			go func() {
				sc, chans2, reqs2, err := ssh.NewServerConn(devconn.Wrap(ch, "device", "relay"), f.serverConfig(t))
				if err != nil {
					ch.Close()
					return
				}
				go f.handle(sc, chans2, reqs2)
			}()
		default:
			nch.Reject(ssh.UnknownChannelType, "fake device: unsupported channel")
		}
	}
}

func (f *fakeDevice) handle(sc *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	defer sc.Close()
	go func() {
		for req := range reqs {
			if req.Type == "keepalive@openssh.com" {
				req.Reply(true, nil)
				continue
			}
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}()
	for nch := range chans {
		switch nch.ChannelType() {
		case "session":
			ch, chReqs, err := nch.Accept()
			if err != nil {
				continue
			}
			go f.session(sc, ch, chReqs)
		case "direct-tcpip":
			ch, _, err := nch.Accept()
			if err != nil {
				continue
			}
			go echoChannel(ch)
		default:
			nch.Reject(ssh.UnknownChannelType, "fake device: unsupported")
		}
	}
}

func (f *fakeDevice) session(sc *ssh.ServerConn, ch ssh.Channel, reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "auth-agent-req@openssh.com":
			// Play the device sshd: accept forwarding, then reach back for
			// the agent the way a real sshd does when the session uses it.
			req.Reply(true, nil)
			go func() {
				ach, _, err := sc.OpenChannel("auth-agent@openssh.com", nil)
				if err != nil {
					return
				}
				signers, err := agent.NewClient(ach).Signers()
				f.mu.Lock()
				if err == nil {
					for _, sgn := range signers {
						f.agentKeys = append(f.agentKeys, sgn.PublicKey().Type())
					}
				}
				f.mu.Unlock()
				ach.Close()
			}()
		case "pty-req", "env", "shell", "exec", "subsystem":
			if req.Type == "exec" || req.Type == "subsystem" {
				f.mu.Lock()
				f.sessions = append(f.sessions, req.Type+":"+string(req.Payload))
				f.mu.Unlock()
			}
			req.Reply(true, nil)
			switch req.Type {
			case "shell", "exec":
				fmt.Fprint(ch, "welcome-device\r\n")
				ch.SendRequest("exit-status", false, ssh.Marshal(exitStatusMsg{Status: 0}))
				ch.Close()
				return
			case "subsystem":
				fmt.Fprint(ch, "sftp-ready\r\n")
				ch.SendRequest("exit-status", false, ssh.Marshal(exitStatusMsg{Status: 0}))
				ch.Close()
				return
			}
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

func echoChannel(ch ssh.Channel) {
	defer ch.Close()
	io.Copy(ch, ch)
}

func testHostKey(t *testing.T) ssh.Signer {
	t.Helper()
	signer, err := LoadOrCreateHostKey(t.TempDir(), discardLogger())
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	return signer
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// debugLogger writes relay-side logs to stderr for test debugging.
func debugLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// ---------- harness ----------

type stubPolicySource struct{ set *policy.PolicySet }

func (s *stubPolicySource) Current() *policy.PolicySet { return s.set }

type harness struct {
	t        *testing.T
	srv      *Server
	lis      net.Listener
	registry *registry.Registry
	ban      *guard.Fail2ban
	limiter  *guard.IPLimiter
	set      *policy.PolicySet
}

func newHarness(t *testing.T, mutate func(*policy.Effective)) *harness {
	t.Helper()
	base := policy.Effective{
		AllowTCPForwarding: true,
		AllowSFTP:          true,
		AllowSCP:           true,
		AllowX11Forwarding: false,
		BWLimitPerSec:      0,
		MaxSessionsPerIP:   3,
	}
	set := policy.EmptySet()
	if mutate != nil {
		mutate(&base)
	}
	h := &harness{
		t:        t,
		registry: registry.New(),
		ban:      guard.NewFail2ban(true),
		limiter:  guard.NewIPLimiter(),
		set:      set,
	}
	h.srv = New(Deps{
		BasePolicy:    base,
		Policy:        &stubPolicySource{set: set},
		Registry:      h.registry,
		IPLimit:       h.limiter,
		Ban:           h.ban,
		HostKey:       testHostKey(t),
		Log:           debugLogger(),
		Version:       "test",
		AdvertiseHost: "relay.test",
	})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	h.lis = lis
	go h.srv.Serve(context.Background(), lis)
	t.Cleanup(func() { lis.Close() })
	return h
}

func (h *harness) addr() string { return h.lis.Addr().String() }

func (h *harness) clientDial(user, password string) (*ssh.Client, error) {
	return ssh.Dial("tcp", h.addr(), &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
}

// clientDialAuth dials with explicit auth methods (pubkey for the M6 tests).
func (h *harness) clientDialAuth(user string, auth []ssh.AuthMethod) (*ssh.Client, error) {
	return ssh.Dial("tcp", h.addr(), &ssh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
}

type tcpipForwardClientMsg struct {
	Addr string
	Port uint32
}

type boundPortClientMsg struct {
	Port uint32
}

// registerDevice emulates `ssh -R <listenAddr>:0:127.0.0.1:22 ssh@relay`:
// the control connection stays open (holding the tunnel) and its device side
// serves Phase-2 sshd handshakes through forwarded-tcpip.
// deviceControlConn opens a `ssh@relay` control connection whose device side
// is served by dev. The raw ssh.Conn is returned (no NewClient wrapper: its
// channel handlers would race serveControl for forwarded-tcpip opens).
func (h *harness) deviceControlConn(t *testing.T, dev *fakeDevice, user string) ssh.Conn {
	t.Helper()
	conn, chans, reqs, err := ssh.NewClientConn(dialTCP(t, h.addr()), "", &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{}, // "none" — open device role
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("device conn (%s): %v", user, err)
	}
	t.Cleanup(func() { conn.Close() })
	go dev.serveControl(t, conn, chans, reqs)
	return conn
}

// controlShell opens the control session and returns its stdout reader after
// the shell request has been answered by the relay.
func controlShell(t *testing.T, conn ssh.Conn) io.Reader {
	t.Helper()
	ch, chReqs, err := conn.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("control session: %v", err)
	}
	go func() {
		for req := range chReqs {
			if req.WantReply {
				req.Reply(true, nil)
			}
		}
	}()
	if _, err := ch.SendRequest("shell", true, nil); err != nil {
		t.Fatalf("shell request: %v", err)
	}
	return ch
}

func (h *harness) registerDevice(t *testing.T, dev *fakeDevice, listenAddr string) string {
	t.Helper()
	conn := h.deviceControlConn(t, dev, "ssh")

	ok, payload, err := conn.SendRequest("tcpip-forward", true, ssh.Marshal(tcpipForwardClientMsg{Addr: listenAddr, Port: 0}))
	if err != nil || !ok {
		t.Fatalf("tcpip-forward: ok=%v err=%v", ok, err)
	}
	var bp boundPortClientMsg
	if err := ssh.Unmarshal(payload, &bp); err != nil || bp.Port == 0 {
		t.Fatalf("bound port reply: err=%v port=%d", err, bp.Port)
	}

	stdout := controlShell(t, conn)
	re := regexp.MustCompile(`Tunnel online: (\S+)`)
	buf := make([]byte, 4096)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("never saw tunnel banner")
		}
		n, err := stdout.Read(buf)
		if n > 0 {
			if m := re.FindSubmatch(buf[:n]); m != nil {
				return string(m[1])
			}
		}
		if err != nil {
			t.Fatalf("banner read: %v", err)
		}
	}
}

func dialTCP(t *testing.T, addr string) net.Conn {
	t.Helper()
	nc, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	return nc
}

// ---------- tests ----------

func TestRegistrationAndBanner(t *testing.T) {
	h := newHarness(t, nil)
	dev := &fakeDevice{}

	alias := h.registerDevice(t, dev, "")
	if !strings.HasPrefix(alias, "d-") || len(alias) != 12 {
		t.Fatalf("alias = %q", alias)
	}
	if b, ok := h.registry.Lookup(alias); !ok || b.OwnerIP != "127.0.0.1" {
		t.Fatalf("binding not registered: %+v", b)
	}

	// Teardown frees the binding.
	// (control connections are closed by registerDevice's cleanup)
}

func TestCustomAliasAndRefusals(t *testing.T) {
	h := newHarness(t, nil)
	dev := &fakeDevice{}
	alias := h.registerDevice(t, dev, "myvps")
	if alias != "myvps" {
		t.Fatalf("custom alias not used: %q", alias)
	}
	if _, live := h.registry.Lookup("myvps"); !live {
		t.Fatalf("custom alias not registered")
	}

	control := h.deviceControlConn(t, dev, "ssh")

	// Duplicate alias refused.
	if ok, _, _ := control.SendRequest("tcpip-forward", true, ssh.Marshal(tcpipForwardClientMsg{Addr: "myvps", Port: 0})); ok {
		t.Fatalf("duplicate alias must be refused")
	}
	// Real-port forward toward the relay refused.
	if ok, _, _ := control.SendRequest("tcpip-forward", true, ssh.Marshal(tcpipForwardClientMsg{Addr: "", Port: 8080})); ok {
		t.Fatalf("real-port forward must be refused")
	}
	// Reserved alias refused.
	if ok, _, _ := control.SendRequest("tcpip-forward", true, ssh.Marshal(tcpipForwardClientMsg{Addr: "json", Port: 0})); ok {
		t.Fatalf("reserved alias must be refused")
	}

	// Bridge through the custom alias: same pass-through flow as generated
	// deviceIDs, proving the alias namespace is uniform end to end.
	client, err := h.clientDial("myvps", "devpass")
	if err != nil {
		t.Fatalf("custom alias client auth: %v", err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	out, err := sess.Output("probe")
	if err != nil {
		t.Fatalf("custom alias exec: %v", err)
	}
	if !strings.Contains(string(out), "welcome-device") {
		t.Fatalf("unexpected custom alias exec output %q", string(out))
	}

	// Teardown frees the binding: close the OWNING control connection.
	if b, ok := h.registry.Lookup("myvps"); ok {
		b.Owner.Close()
	}
	control.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, live := h.registry.Lookup("myvps"); !live {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("binding not released after disconnect")
}

func TestPasswordBridgeExec(t *testing.T) {
	h := newHarness(t, nil)
	dev := &fakeDevice{}
	alias := h.registerDevice(t, dev, "")

	client, err := h.clientDial("root+"+alias, "devpass")
	if err != nil {
		t.Fatalf("client auth: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	out, err := sess.Output("echo hi")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if !strings.Contains(string(out), "welcome-device") {
		t.Fatalf("unexpected exec output %q", string(out))
	}

	// Default user = root works without the user part.
	client2, err := h.clientDial(alias, "devpass")
	if err != nil {
		t.Fatalf("default-user auth: %v", err)
	}
	client2.Close()

	// Wrong password → auth failure; fail2ban window fills up but does not
	// ban a single miss.
	if _, err := h.clientDial("root+"+alias, "wrongpass"); err == nil {
		t.Fatalf("wrong password must fail")
	}
}

// TestPubkeyAgentBridgeExec: end-to-end M6 pubkey pass-through — the client
// authenticates to the relay with a key (x/crypto verifies the signature),
// forwards an agent, and the agent signs the device's challenge so the
// device sees and verifies the user's real key.
func TestPubkeyAgentBridgeExec(t *testing.T) {
	h := newHarness(t, nil)
	clientSigner, clientPriv := newEdSigner(t)
	dev := &fakeDevice{pubkey: clientSigner.PublicKey(), pubkeyOnly: true}
	alias := h.registerDevice(t, dev, "")

	client, err := h.clientDialAuth("root+"+alias, []ssh.AuthMethod{ssh.PublicKeys(clientSigner)})
	if err != nil {
		t.Fatalf("pubkey client auth: %v", err)
	}
	defer client.Close()
	serveAgent(t, client, clientPriv)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	out, err := sess.Output("echo hi")
	if err != nil {
		t.Fatalf("exec through agent bridge: %v", err)
	}
	if !strings.Contains(string(out), "welcome-device") {
		t.Fatalf("unexpected exec output %q", string(out))
	}
	if len(dev.passwords) != 0 {
		t.Fatalf("pubkey path must not touch password auth, saw %v", dev.passwords)
	}
}

// TestPubkeyWithoutAgent: no forwarded agent → the deferred device login
// cannot complete; the user gets exit 255 and actionable stderr.
func TestPubkeyWithoutAgent(t *testing.T) {
	h := newHarness(t, nil)
	clientSigner, _ := newEdSigner(t)
	dev := &fakeDevice{pubkey: clientSigner.PublicKey(), pubkeyOnly: true}
	alias := h.registerDevice(t, dev, "")

	client, err := h.clientDialAuth("root+"+alias, []ssh.AuthMethod{ssh.PublicKeys(clientSigner)})
	if err != nil {
		t.Fatalf("pubkey client auth: %v", err)
	}
	defer client.Close()

	// No agent handler registered → the relay's agent channel open is
	// refused → the session is accepted only to carry the explanation: the
	// reason lands on stderr and the command never reaches the device.
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	var stderr bytes.Buffer
	sess.Stderr = &stderr
	if _, err := sess.Output("echo hi"); err == nil {
		t.Fatalf("exec must fail without an agent")
	}
	if !strings.Contains(stderr.String(), "agent forwarding unavailable") {
		t.Fatalf("stderr must tell the user to use -A, got: %q", stderr.String())
	}
}

// TestPubkeyNotAuthorizedOnDevice: the relay accepts the key but the device
// refuses it (and every other agent key) — clean failure, fail2ban counted.
func TestPubkeyNotAuthorizedOnDevice(t *testing.T) {
	h := newHarness(t, nil)
	clientSigner, clientPriv := newEdSigner(t)
	deviceSigner, _ := newEdSigner(t) // the key the device actually accepts
	dev := &fakeDevice{pubkey: deviceSigner.PublicKey(), pubkeyOnly: true}
	alias := h.registerDevice(t, dev, "")

	client, err := h.clientDialAuth("root+"+alias, []ssh.AuthMethod{ssh.PublicKeys(clientSigner)})
	if err != nil {
		t.Fatalf("pubkey client auth: %v", err)
	}
	defer client.Close()
	serveAgent(t, client, clientPriv)

	// The agent offers only the client key, which the device refuses — the
	// session carries the device-rejection explanation on stderr.
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	var stderr bytes.Buffer
	sess.Stderr = &stderr
	if _, err := sess.Output("echo hi"); err == nil {
		t.Fatalf("exec must fail when the device rejects the key")
	}
	if !strings.Contains(stderr.String(), "device rejected your key") {
		t.Fatalf("stderr must explain the device rejection, got: %q", stderr.String())
	}
}

// TestPubkeyAgentDirectTCP: client -L/-D through a pubkey connection — the
// lazy device login also serves forwarding channels.
func TestPubkeyAgentDirectTCP(t *testing.T) {
	h := newHarness(t, nil)
	clientSigner, clientPriv := newEdSigner(t)
	dev := &fakeDevice{pubkey: clientSigner.PublicKey(), pubkeyOnly: true}
	alias := h.registerDevice(t, dev, "")

	client, err := h.clientDialAuth("root+"+alias, []ssh.AuthMethod{ssh.PublicKeys(clientSigner)})
	if err != nil {
		t.Fatalf("pubkey client auth: %v", err)
	}
	defer client.Close()
	serveAgent(t, client, clientPriv)

	type dtcp struct {
		A string
		B uint32
		C string
		D uint32
	}
	ch, _, err := client.OpenChannel("direct-tcpip", ssh.Marshal(dtcp{"target.internal", 80, "10.0.0.1", 5555}))
	if err != nil {
		t.Fatalf("direct-tcpip open through agent bridge: %v", err)
	}
	ch.Write([]byte("ping"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(ch, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo mismatch: %q err=%v", buf, err)
	}
	ch.Close()
}

// newEdSigner mints a fresh ed25519 keypair and its ssh.Signer.
func newEdSigner(t *testing.T) (ssh.Signer, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer, priv
}

// serveAgent registers a handler for the relay's auth-agent channel opens and
// serves the given key from them — the test stand-in for the user's
// ssh-agent behind `ssh -A`.
func serveAgent(t *testing.T, client *ssh.Client, priv ed25519.PrivateKey) {
	t.Helper()
	opens := client.HandleChannelOpen("auth-agent@openssh.com")
	if opens == nil {
		t.Fatalf("agent handler already registered")
	}
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
		t.Fatalf("agent keyring add: %v", err)
	}
	go func() {
		for nch := range opens {
			ch, _, err := nch.Accept()
			if err != nil {
				continue
			}
			go agent.ServeAgent(keyring, ch)
		}
	}()
}

// TestAgentForwardingInsideSession: for a public-key login the relay mirrors
// auth-agent-req to the device and pairs the device's agent channels back to
// the client, so programs inside the session reach the user's real agent.
func TestAgentForwardingInsideSession(t *testing.T) {
	h := newHarness(t, nil)
	clientSigner, clientPriv := newEdSigner(t)
	dev := &fakeDevice{pubkey: clientSigner.PublicKey()}
	alias := h.registerDevice(t, dev, "")

	client, err := h.clientDialAuth("root+"+alias, []ssh.AuthMethod{ssh.PublicKeys(clientSigner)})
	if err != nil {
		t.Fatalf("pubkey client auth: %v", err)
	}
	defer client.Close()
	serveAgent(t, client, clientPriv)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	if ok, err := sess.SendRequest("auth-agent-req@openssh.com", true, nil); err != nil || !ok {
		t.Fatalf("auth-agent-req must be mirrored and accepted (ok=%v err=%v)", ok, err)
	}
	out, err := sess.Output("echo hi")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if !strings.Contains(string(out), "welcome-device") {
		t.Fatalf("unexpected exec output %q", string(out))
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		dev.mu.Lock()
		n := len(dev.agentKeys)
		dev.mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("device never saw the forwarded agent keys")
		}
		time.Sleep(20 * time.Millisecond)
	}
	dev.mu.Lock()
	defer dev.mu.Unlock()
	if len(dev.agentKeys) != 1 || dev.agentKeys[0] != clientSigner.PublicKey().Type() {
		t.Fatalf("device saw wrong agent keys: %v", dev.agentKeys)
	}
}

// TestAgentRefusedForPassword: agent forwarding auto-disables for
// password/none logins — the request is refused with the reason and the
// device is never asked.
func TestAgentRefusedForPassword(t *testing.T) {
	h := newHarness(t, nil)
	dev := &fakeDevice{}
	alias := h.registerDevice(t, dev, "")

	client, err := h.clientDial("root+"+alias, "devpass")
	if err != nil {
		t.Fatalf("client auth: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	var stderr bytes.Buffer
	sess.Stderr = &stderr
	ok, err := sess.SendRequest("auth-agent-req@openssh.com", true, nil)
	if err != nil {
		t.Fatalf("auth-agent-req: %v", err)
	}
	if ok {
		t.Fatalf("auth-agent-req must be refused for password logins")
	}
	out, err := sess.Output("echo hi")
	if err != nil || !strings.Contains(string(out), "welcome-device") {
		t.Fatalf("session must still work after refusal (out=%q err=%v)", out, err)
	}
	if !strings.Contains(stderr.String(), "requires public key auth") {
		t.Fatalf("stderr must explain the refusal, got %q", stderr.String())
	}
	dev.mu.Lock()
	defer dev.mu.Unlock()
	if len(dev.agentKeys) != 0 {
		t.Fatalf("device must not see any agent on a password login: %v", dev.agentKeys)
	}
}

func TestDirectTCPIPAllowedAndGated(t *testing.T) {
	h := newHarness(t, nil)
	dev := &fakeDevice{}
	alias := h.registerDevice(t, dev, "")

	client, err := h.clientDial("root+"+alias, "devpass")
	if err != nil {
		t.Fatalf("client auth: %v", err)
	}
	defer client.Close()

	type dtcp struct {
		A string
		B uint32
		C string
		D uint32
	}
	ch, _, err := client.OpenChannel("direct-tcpip", ssh.Marshal(dtcp{"target.internal", 80, "10.0.0.1", 5555}))
	if err != nil {
		t.Fatalf("direct-tcpip open: %v", err)
	}
	ch.Write([]byte("ping"))
	buf := make([]byte, 4)
	readErr := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(ch, buf)
		readErr <- err
	}()
	select {
	case err := <-readErr:
		if err != nil || string(buf) != "ping" {
			t.Fatalf("echo mismatch: %q err=%v", buf, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("echo read timed out")
	}
	ch.Close()

	// Gate off (--allow-tcp-forwarding=false equivalent) and expect the
	// exact warning text.
	gated := newHarness(t, func(b *policy.Effective) { b.AllowTCPForwarding = false })
	alias2 := gated.registerDevice(t, &fakeDevice{}, "")
	client2, err := gated.clientDial("root+"+alias2, "devpass")
	if err != nil {
		t.Fatalf("gated client auth: %v", err)
	}
	defer client2.Close()
	_, _, err = client2.OpenChannel("direct-tcpip", ssh.Marshal(dtcp{"target.internal", 80, "10.0.0.1", 5555}))
	if err == nil {
		t.Fatalf("direct-tcpip must be refused when gated")
	}
	var openErr *ssh.OpenChannelError
	if !errorsAsOpenChannel(err, &openErr) || openErr.Message != TCPForwardWarning {
		t.Fatalf("wrong refusal: %v", err)
	}

	// Client-side -R (real port toward the relay) refused on gated conn too.
	if ok, _, _ := client2.SendRequest("tcpip-forward", true, ssh.Marshal(tcpipForwardClientMsg{Addr: "0.0.0.0", Port: 1234})); ok {
		t.Fatalf("client tcpip-forward must be refused")
	}
}

func errorsAsOpenChannel(err error, target **ssh.OpenChannelError) bool {
	oe, ok := err.(*ssh.OpenChannelError)
	if ok {
		*target = oe
	}
	return ok
}

func errorsAsExit(err error, target **ssh.ExitError) bool {
	ee, ok := err.(*ssh.ExitError)
	if ok {
		*target = ee
	}
	return ok
}

// TestControlShellCtrlC: with a PTY the banner arrives CRLF-terminated and
// Ctrl+C (0x03) tears the control connection — and the binding — down.
func TestControlShellCtrlC(t *testing.T) {
	h := newHarness(t, nil)
	dev := &fakeDevice{}
	conn := h.deviceControlConn(t, dev, "ssh")

	ok, payload, err := conn.SendRequest("tcpip-forward", true, ssh.Marshal(tcpipForwardClientMsg{Addr: "", Port: 0}))
	if err != nil || !ok {
		t.Fatalf("tcpip-forward: ok=%v err=%v", ok, err)
	}
	var bp boundPortClientMsg
	ssh.Unmarshal(payload, &bp)
	alias := "" // read from the banner below

	ch, chReqs, err := conn.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	go func() {
		for req := range chReqs {
			if req.WantReply {
				req.Reply(true, nil)
			}
		}
	}()
	// pty-req marks the session as interactive (raw terminal on the client).
	if _, err := ch.SendRequest("pty-req", true, ssh.Marshal(struct {
		Term                         string
		Columns, Rows, Width, Height uint32
		Modes                        []byte `ssh:"rest"`
	}{"xterm", 80, 24, 640, 480, nil})); err != nil {
		t.Fatalf("pty-req: %v", err)
	}
	if _, err := ch.SendRequest("shell", true, nil); err != nil {
		t.Fatalf("shell: %v", err)
	}

	buf := make([]byte, 4096)
	var banner []byte
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		n, err := ch.Read(buf)
		if n > 0 {
			banner = append(banner, buf[:n]...)
			if bytes.Contains(banner, []byte("Tunnel online: ")) {
				break
			}
		}
		if err != nil {
			t.Fatalf("banner read: %v", err)
		}
	}
	// PTY session → CRLF line endings (no staircase).
	if !bytes.Contains(banner, []byte("\r\n")) {
		t.Fatalf("pty banner must use CRLF: %q", banner)
	}
	if m := regexp.MustCompile(`Tunnel online: (\S+)`).FindSubmatch(banner); m != nil {
		alias = string(m[1])
	}
	if !strings.HasPrefix(alias, "d-") {
		t.Fatalf("alias = %q", alias)
	}

	// Ctrl+C → control conn closed → binding released.
	if _, err := ch.Write([]byte{0x03}); err != nil {
		t.Fatalf("write ctrl-c: %v", err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, live := h.registry.Lookup(alias); !live {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("Ctrl+C did not tear the tunnel down")
}

func TestStatusEndpoint(t *testing.T) {
	h := newHarness(t, nil)
	alias := h.registerDevice(t, &fakeDevice{}, "")

	client, err := h.clientDial("json", "") // status role: password ignored
	if err != nil {
		t.Fatalf("status auth: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	out, err := sess.Output("")
	if err != nil {
		t.Fatalf("status output: %v", err)
	}
	var doc struct {
		IP           string `json:"ip"`
		RelayVersion string `json:"relay_version"`
		Sessions     struct {
			Used    int `json:"used"`
			Allowed int `json:"allowed"`
		} `json:"sessions"`
		Bindings []struct {
			Alias      string `json:"alias"`
			SSHCommand string `json:"ssh_command"`
		} `json:"bindings"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("bad json: %v\n%s", err, out)
	}
	if doc.IP != "127.0.0.1" || doc.RelayVersion != "test" || doc.Sessions.Allowed != 3 {
		t.Fatalf("doc fields wrong: %+v", doc)
	}
	if len(doc.Bindings) != 1 || doc.Bindings[0].Alias != alias {
		t.Fatalf("bindings wrong: %+v", doc.Bindings)
	}
	if doc.Bindings[0].SSHCommand != "ssh "+alias+"@relay.test" {
		t.Fatalf("ssh_command wrong: %q", doc.Bindings[0].SSHCommand)
	}
	// The custom-user template must keep `<user>` literal — no HTML escaping
	// (\u003c) in the wire bytes.
	if !bytes.Contains(out, []byte("<user>+"+alias+"@relay.test")) {
		t.Fatalf("custom_user_template not literal: %s", out)
	}
	if bytes.Contains(out, []byte(`\u003c`)) || bytes.Contains(out, []byte(`\u003e`)) {
		t.Fatalf("HTML-escaped JSON: %s", out)
	}
	if doc.Sessions.Used < 1 || doc.Sessions.Used > 2 {
		t.Fatalf("used quota off (device + status minus self): %d", doc.Sessions.Used)
	}
}

func TestDeviceJSONMode(t *testing.T) {
	h := newHarness(t, nil)
	dev := &fakeDevice{}
	_ = h.registerDevice(t, dev, "myvps")

	// A second ssh+json device connection that registers and reads JSON.
	conn := h.deviceControlConn(t, dev, "ssh+json")

	if ok, _, _ := conn.SendRequest("tcpip-forward", true, ssh.Marshal(tcpipForwardClientMsg{Addr: "", Port: 0})); !ok {
		t.Fatalf("ssh+json must support forwards")
	}
	stdout := controlShell(t, conn)
	jbuf := make([]byte, 8192)
	var out []byte
	jdeadline := time.Now().Add(5 * time.Second)
	for {
		if time.Now().After(jdeadline) {
			t.Fatalf("never saw json document")
		}
		n, rerr := stdout.Read(jbuf)
		if n > 0 {
			out = append(out, jbuf[:n]...)
			if bytesContains(out, `"ssh_command"`) {
				break
			}
		}
		if rerr != nil {
			t.Fatalf("json read: %v", rerr)
		}
	}
	if !bytesContains(out, `"alias": "myvps"`) {
		t.Fatalf("json doc missing first binding: %s", out)
	}
}

func bytesContains(b []byte, sub string) bool {
	return strings.Contains(string(b), sub)
}

func TestPerIPSessionLimit(t *testing.T) {
	// 3 = device conn + 2 client conns; the 4th client is refused.
	h := newHarness(t, func(b *policy.Effective) { b.MaxSessionsPerIP = 3 })
	dev := &fakeDevice{}
	alias := h.registerDevice(t, dev, "")

	var keep [2]*ssh.Client
	for i := range keep {
		c, err := h.clientDial("root+"+alias, "devpass")
		if err != nil {
			t.Fatalf("conn %d: %v", i, err)
		}
		keep[i] = c
		defer c.Close()
	}
	third, err := h.clientDial("root+"+alias, "devpass")
	if err != nil {
		t.Fatalf("third conn auth passes (limit enforced at channel open): %v", err)
	}
	defer third.Close()
	if _, _, err := third.OpenChannel("session", nil); err == nil {
		t.Fatalf("third session must be refused")
	}
}

func TestFail2banBansPasswordGuessers(t *testing.T) {
	h := newHarness(t, nil)
	dev := &fakeDevice{}
	alias := h.registerDevice(t, dev, "")

	for i := 0; i < guard.F2BThreshold; i++ {
		if _, err := h.clientDial("root+"+alias, fmt.Sprintf("guess-%d", i)); err == nil {
			t.Fatalf("guess %d must fail", i)
		}
	}
	// Banned pre-auth: even the correct password is now refused.
	if _, err := h.clientDial("root+"+alias, "devpass"); err == nil {
		t.Fatalf("banned IP must not authenticate")
	}
}

// ---------- keyboard-interactive tunnel-state instruction ----------

type stubConnMeta struct{ user string }

func (m stubConnMeta) User() string          { return m.user }
func (m stubConnMeta) SessionID() []byte     { return []byte("sess") }
func (m stubConnMeta) ClientVersion() []byte { return []byte("SSH-2.0-test") }
func (m stubConnMeta) ServerVersion() []byte { return []byte("SSH-2.0-relay") }
func (m stubConnMeta) RemoteAddr() net.Addr  { return &net.TCPAddr{IP: net.IPv4(9, 9, 9, 9), Port: 5} }
func (m stubConnMeta) LocalAddr() net.Addr   { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22} }

// The keyboard-interactive instruction is the only text a plain ssh client
// shows during auth, so it must name the tunnel state instead of always
// asking for a device password.
func TestKbdInteractiveInstructionReflectsTunnelState(t *testing.T) {
	h := newHarness(t, nil)
	cfg := h.srv.serverConfig()
	challenge := func() (string, error) {
		var instruction string
		_, err := cfg.KeyboardInteractiveCallback(stubConnMeta{user: "root+box"}, func(name, instr string, questions []string, echos []bool) ([]string, error) {
			instruction = instr
			return nil, fmt.Errorf("user aborted") // never dial a device from this test
		})
		return instruction, err
	}

	instruction, _ := challenge()
	if !strings.Contains(instruction, `No live tunnel for "box"`) {
		t.Fatalf("dead-tunnel instruction = %q", instruction)
	}

	if _, err := h.registry.Bind("box", nil, "9.9.9.9", "127.0.0.1:22", 22, 1); err != nil {
		t.Fatalf("bind: %v", err)
	}
	instruction, _ = challenge()
	if !strings.Contains(instruction, "Device login required.") {
		t.Fatalf("live-tunnel instruction = %q", instruction)
	}

	binding, ok := h.registry.Lookup("box")
	if !ok || !binding.AcquireBridge() {
		t.Fatalf("acquire")
	}
	instruction, _ = challenge()
	if !strings.Contains(instruction, "session capacity") {
		t.Fatalf("capacity instruction = %q", instruction)
	}
}

// ---------- graceful shutdown (panel stop) ----------

// A stopping relay must tear down its live connections instead of waiting
// for them: idle tunnel owners never disconnect on their own, and a panel
// SIGKILLs the process after its own stop timeout.
func TestServeGracefulShutdownClosesLiveConnections(t *testing.T) {
	old := shutdownGrace
	shutdownGrace = 500 * time.Millisecond
	t.Cleanup(func() { shutdownGrace = old })

	s := New(Deps{
		Cfg:           &config.Config{ListenPort: 22},
		BasePolicy:    policy.Effective{},
		Policy:        &stubPolicySource{set: policy.EmptySet()},
		Registry:      registry.New(),
		IPLimit:       guard.NewIPLimiter(),
		Ban:           guard.NewFail2ban(true),
		HostKey:       testHostKey(t),
		Log:           discardLogger(),
		Version:       "test",
		AdvertiseHost: "relay.test",
	})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, lis) }()

	// A live connection parked mid-handshake (never completes SSH auth).
	nc, err := net.Dial("tcp", lis.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer nc.Close()
	time.Sleep(100 * time.Millisecond)

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("Serve did not return after stop")
	}
}
