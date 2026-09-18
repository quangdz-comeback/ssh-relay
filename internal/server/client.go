package server

import (
	"context"
	"errors"
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
// direct-tcpip forwarding channels (ARCHITECTURE §5).
func (s *Server) handleClient(ctx context.Context, sc *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request, state *st) {
	ca, ok := s.popAuth(sc)
	if !ok {
		s.log.Warn("client connection without stashed device login", "ip", state.ip)
		sc.Close()
		return
	}
	defer func() {
		ca.dev.Close()
		ca.binding.ReleaseBridge()
	}()

	// One shared token bucket per direction for the whole connection
	// (--bw-limit semantics, ARCHITECTURE §7.3).
	bwUp := throttle.New(state.eff.BWLimitPerSec)
	bwDown := throttle.New(state.eff.BWLimitPerSec)

	go s.handleClientRequests(reqs)
	go s.drainDeviceChannels(ctx, sc, ca, state, bwUp, bwDown)

	var openChannels atomic.Int32
	sessionOpen := false
	for nch := range chans {
		switch nch.ChannelType() {
		case "session":
			if sessionOpen {
				nch.Reject(ssh.Prohibited, "only one session per connection")
				continue
			}
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
			// Held for the M6 pubkey pass-through path; unused in v1.
			ch, _, err := nch.Accept()
			if err == nil {
				go drainUntilClose(ch)
			}

		default:
			nch.Reject(ssh.UnknownChannelType, "unsupported channel type")
		}
	}
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
func (s *Server) openDeviceDirectTCP(nch ssh.NewChannel, ca stashedAuth) (ssh.Channel, ssh.Channel, error) {
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

// drainDeviceChannels consumes the device connection's inbound streams so the
// mux never stalls. Today only x11 channel opens are meaningful (paired back
// to the client); everything else is politely rejected.
func (s *Server) drainDeviceChannels(ctx context.Context, sc *ssh.ServerConn, ca stashedAuth, state *st, bwUp, bwDown *throttle.Limiter) {
	for nch := range ca.devChans {
		switch nch.ChannelType() {
		case "x11":
			if !state.eff.AllowX11Forwarding {
				nch.Reject(ssh.Prohibited, "x11 forwarding is disabled on this relay")
				continue
			}
			// The device's sshd opens x11 toward us; re-open toward the
			// end user's client, which owns the fake-cookie translation.
			// Payload (originator address/port) is forwarded verbatim.
			clientCh, clientReqs, err := sc.OpenChannel("x11", nch.ExtraData())
			if err != nil {
				nch.Reject(ssh.Prohibited, "could not open x11 channel to client")
				continue
			}
			go drainChannelRequests(clientReqs)
			devCh, devReqs, err := nch.Accept()
			if err != nil {
				clientCh.Close()
				continue
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
	for req := range ca.devReqs {
		if req.Type == "keepalive@openssh.com" {
			req.Reply(true, nil)
			continue
		}
		if req.WantReply {
			req.Reply(false, nil)
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
