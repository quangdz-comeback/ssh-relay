package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"

	"golang.org/x/crypto/ssh"

	"github.com/quangdz/ssh-relay/internal/throttle"
)

// pairedChannel closes both legs together (client↔device pipe unit).
type pairedChannel struct {
	ssh.Channel
	other ssh.Channel
}

func (p *pairedChannel) Close() error {
	p.other.Close()
	return p.Channel.Close()
}

// handleClient serves one end-user connection: the stashed device login from
// pass-through auth becomes the upstream for the session bridge and any
// direct-tcpip forwarding channels (ARCHITECTURE §5). For public-key
// authenticated connections the device login is still pending and completes
// on first use through the client's forwarded agent (ensureUpstream).
func (s *Server) handleClient(ctx context.Context, sc *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request, state *st) {
	ca, ok := s.popAuth(sc)
	if !ok {
		s.log.Warn("client connection without stashed device login", "ip", state.ip)
		sc.Close()
		return
	}
	defer func() {
		if ca.dev != nil {
			ca.dev.Close()
		}
		ca.binding.ReleaseBridge()
	}()

	// One shared token bucket per direction for the whole connection
	// (--bw-limit semantics, ARCHITECTURE §7.3).
	bwUp := throttle.New(state.eff.BWLimitPerSec)
	bwDown := throttle.New(state.eff.BWLimitPerSec)

	// The device-side channel/request streams only exist once the device
	// login completed; start the drain exactly once, after ensureUpstream.
	lazy := ca.pubkey != nil
	draining := false
	startDrain := func() {
		if !draining {
			draining = true
			go s.drainDeviceChannels(ctx, sc, ca, state, bwUp, bwDown)
		}
	}
	if !lazy {
		startDrain()
	}

	go s.handleClientRequests(reqs)

	var openChannels atomic.Int32
	sessionOpen := false
	for nch := range chans {
		switch nch.ChannelType() {
		case "session":
			if sessionOpen {
				nch.Reject(ssh.Prohibited, "only one session per connection")
				continue
			}
			// The device login must exist before the session opens — a
			// rejected open delivers the reason reliably (like direct-tcpip);
			// accepting first and failing later would race the client's
			// exec/shell request against the teardown.
			if err := s.ensureUpstream(sc, ca, state); err != nil {
				sessionOpen = true
				nch.Reject(ssh.Prohibited, err.Error())
				continue
			}
			startDrain()
			ch, chReqs, err := nch.Accept()
			if err != nil {
				continue
			}
			sessionOpen = true
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.mirrorSession(ctx, ch, chReqs, ca, state, bwUp, bwDown)
			}()

		case "direct-tcpip":
			if !state.eff.AllowTCPForwarding {
				nch.Reject(ssh.Prohibited, TCPForwardWarning)
				continue
			}
			if err := s.ensureUpstream(sc, ca, state); err != nil {
				nch.Reject(ssh.Prohibited, err.Error())
				continue
			}
			startDrain()
			if openChannels.Add(1) > maxChannelsPerClientConn {
				openChannels.Add(-1)
				nch.Reject(ssh.Prohibited, "too many forwarding channels on this connection")
				continue
			}
			clientCh, devCh, err := s.openDeviceDirectTCP(nch, ca)
			if err != nil {
				openChannels.Add(-1)
				continue // rejection already sent
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer openChannels.Add(-1)
				splice(ctx, clientCh, devCh, bwUp, bwDown)
			}()

		case "auth-agent@openssh.com":
			// Some clients open the agent channel themselves; drain it. The
			// pubkey path opens its own channel in ensureUpstream.
			ch, _, err := nch.Accept()
			if err == nil {
				go drainUntilClose(ch)
			}

		default:
			nch.Reject(ssh.UnknownChannelType, "unsupported channel type")
		}
	}
}

// ensureUpstream completes the device login for public-key authenticated
// connections: the client's forwarded agent signs the device's challenge, so
// the device still authenticates the user's real key. Password/none
// connections already have their upstream and return immediately. Safe for
// concurrent session/direct-tcpip use.
func (s *Server) ensureUpstream(sc *ssh.ServerConn, ca *stashedAuth, state *st) error {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if ca.pubkey == nil {
		return nil // established at auth time, or by a racing channel open
	}
	dev, devAgentChans, devX11Chans, devReqs, err := s.completeAgentLogin(sc, ca)
	if err != nil {
		var agentErr *agentLoginError
		if errors.As(err, &agentErr) {
			return err // user setup issue: never counts toward fail2ban
		}
		if banned := s.deps.Ban.Failure(state.ip); banned {
			s.log.Warn("ip banned after repeated device auth failures", "ip", state.ip, "alias", ca.binding.Alias)
		} else {
			s.log.Info("device rejected client key", "ip", state.ip, "alias", ca.binding.Alias, "user", ca.deviceUser)
		}
		return fmt.Errorf("device rejected your key(s) — authorize the key on the device (authorized_keys) or use password auth: %w", err)
	}
	s.deps.Ban.Success(state.ip)
	ca.dev, ca.devAgentChans, ca.devX11Chans, ca.devReqs = dev, devAgentChans, devX11Chans, devReqs
	ca.pubkey = nil
	s.log.Info("device login via forwarded agent", "ip", state.ip, "alias", ca.binding.Alias, "user", ca.deviceUser)
	return nil
}

// handleClientRequests refuses forwarding toward the relay and answers
// keepalives (ARCHITECTURE §6.1).
func (s *Server) handleClientRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "tcpip-forward":
			s.log.Debug("refused tcpip-forward from client")
			req.Reply(false, nil)
		case "cancel-tcpip-forward":
			req.Reply(true, nil)
		case "keepalive@openssh.com":
			req.Reply(true, nil)
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

// openDeviceDirectTCP mirrors a client direct-tcpip open onto the device.
// The open payload is passed verbatim (target host/port + originator), and
// device-side failures are relayed to the client verbatim (reason + message).
func (s *Server) openDeviceDirectTCP(nch ssh.NewChannel, ca *stashedAuth) (ssh.Channel, ssh.Channel, error) {
	devCh, devReqs, err := ca.dev.OpenChannel("direct-tcpip", nch.ExtraData())
	if err != nil {
		reason, msg := ssh.ConnectionFailed, err.Error()
		var openErr *ssh.OpenChannelError
		if errors.As(err, &openErr) {
			reason, msg = openErr.Reason, openErr.Message
		}
		nch.Reject(reason, msg)
		return nil, nil, err
	}
	go drainChannelRequests(devReqs)
	ch, _, err := nch.Accept()
	if err != nil {
		devCh.Close()
		return nil, nil, err
	}
	return ch, devCh, nil
}

// drainDeviceChannels consumes the device connection's inbound streams so
// the mux never stalls: session agent forwarding and x11 opens are paired
// back to the end user's client, everything else the mux already rejected
// (unregistered types never reach us — see dialDeviceAuth).
func (s *Server) drainDeviceChannels(ctx context.Context, sc *ssh.ServerConn, ca *stashedAuth, state *st, bwUp, bwDown *throttle.Limiter) {
	accept := func(nch ssh.NewChannel) {
		switch nch.ChannelType() {
		case "auth-agent@openssh.com":
			// The device's sshd opened the user's agent channel (session
			// agent forwarding). Only public-key logins have the mirrored
			// auth-agent-req that leads here; refuse anything else so a
			// stray device open never reaches a password-login client.
			s.log.Debug("device opened agent channel", "ip", state.ip, "pubkey_auth", ca.pubkeyAuth)
			if !ca.pubkeyAuth {
				nch.Reject(ssh.Prohibited, "agent forwarding requires public key auth")
				return
			}
			// Pair it back so programs inside the session reach the real
			// agent.
			clientCh, clientReqs, err := sc.OpenChannel("auth-agent@openssh.com", nch.ExtraData())
			if err != nil {
				s.log.Warn("agent channel open to client failed", "ip", state.ip, "err", err)
				nch.Reject(ssh.Prohibited, "could not open agent channel to client")
				return
			}
			go drainChannelRequests(clientReqs)
			devCh, devReqs, err := nch.Accept()
			if err != nil {
				clientCh.Close()
				return
			}
			go drainChannelRequests(devReqs)
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				splice(ctx, clientCh, devCh, bwUp, bwDown)
			}()
		case "x11":
			if !state.eff.AllowX11Forwarding {
				nch.Reject(ssh.Prohibited, "x11 forwarding is disabled on this relay")
				return
			}
			// The device's sshd opens x11 toward us; re-open toward the
			// end user's client, which owns the fake-cookie translation.
			// Payload (originator address/port) is forwarded verbatim.
			clientCh, clientReqs, err := sc.OpenChannel("x11", nch.ExtraData())
			if err != nil {
				nch.Reject(ssh.Prohibited, "could not open x11 channel to client")
				return
			}
			go drainChannelRequests(clientReqs)
			devCh, devReqs, err := nch.Accept()
			if err != nil {
				clientCh.Close()
				return
			}
			go drainChannelRequests(devReqs)
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				splice(ctx, clientCh, devCh, bwUp, bwDown)
			}()
		default:
			nch.Reject(ssh.UnknownChannelType, "unsupported channel type from device")
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case nch, ok := <-ca.devAgentChans:
			if !ok {
				return
			}
			accept(nch)
		case nch, ok := <-ca.devX11Chans:
			if !ok {
				return
			}
			accept(nch)
		case req, ok := <-ca.devReqs:
			if !ok {
				return
			}
			if req.Type == "keepalive@openssh.com" {
				req.Reply(true, nil)
				continue
			}
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

// splice pumps both directions of a paired channel until either side dies.
func splice(ctx context.Context, a, b ssh.Channel, aToB, bToA *throttle.Limiter) {
	defer a.Close()
	defer b.Close()
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(aToB.Writer(ctx, b), aToB.Reader(ctx, a))
		done <- struct{}{}
	}()
	go func() {
		ioCopy(bToA.Writer(ctx, a), bToA.Reader(ctx, b))
		done <- struct{}{}
	}()
	<-done
}

// drainChannelRequests consumes inbound requests on mirrored channels so the
// mux never stalls: keepalives are answered, everything else refused.
func drainChannelRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		if req.Type == "keepalive@openssh.com" {
			req.Reply(true, nil)
			continue
		}
		if req.WantReply {
			req.Reply(false, nil)
		}
	}
}

// drainUntilClose reads and discards a channel's data (agent channels in v1).
func drainUntilClose(ch ssh.Channel) {
	buf := make([]byte, 4096)
	for {
		if _, err := ch.Read(buf); err != nil {
			ch.Close()
			return
		}
	}
}
