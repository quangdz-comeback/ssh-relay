package server

import (
	"context"
	"fmt"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/quangdz/ssh-relay/internal/registry"
)

// tcpipForwardMsg is RFC 4254 §7.1 "tcpip-forward" request data.
type tcpipForwardMsg struct {
	Addr string
	Port uint32
}

// boundPortMsg is the success reply payload when the device asked for an
// auto-assigned port (we hand back our virtual port; no socket is opened).
type boundPortMsg struct {
	Port uint32
}

// virtualPorts hands out per-connection fake bound ports. They are never
// bound to a socket — OpenSSH just matches them against the forward it
// registered (same trick as sshpiper's revtunnel).
type virtualPorts struct{ n uint32 }

func (v *virtualPorts) next() uint32 {
	v.n++
	return 61000 + v.n
}

func (s *Server) handleDevice(ctx context.Context, sc *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request, state *st, jsonMode bool) {
	defer sc.Close()
	vp := &virtualPorts{}

	go s.handleDeviceRequests(ctx, sc, reqs, vp)

	for nch := range chans {
		if nch.ChannelType() != "session" {
			nch.Reject(ssh.UnknownChannelType, "control connections support one session only")
			continue
		}
		ch, chReqs, err := nch.Accept()
		if err != nil {
			s.log.Warn("control session accept failed", "ip", state.ip, "err", err)
			continue
		}
		s.runControlShell(ctx, ch, chReqs, state, jsonMode)
	}

	if freed := s.deps.Registry.ReleaseByOwner(sc); len(freed) > 0 {
		s.log.Info("tunnels unregistered", "ip", state.ip, "aliases", freed)
	}
}

// handleDeviceRequests processes -R registrations and keepalives. Responses
// follow OpenSSH strictness: the bound-port payload is only included when the
// device requested port 0.
func (s *Server) handleDeviceRequests(ctx context.Context, sc *ssh.ServerConn, reqs <-chan *ssh.Request, vp *virtualPorts) {
	for {
		select {
		case <-ctx.Done():
			return
		case req, ok := <-reqs:
			if !ok {
				return
			}
			switch req.Type {
			case "tcpip-forward":
				var m tcpipForwardMsg
				if err := ssh.Unmarshal(req.Payload, &m); err != nil {
					s.log.Warn("malformed tcpip-forward", "ip", stateIP(sc), "err", err)
					req.Reply(false, nil)
					continue
				}
				if m.Port != 0 {
					// Real listener on the relay: unsupported by design.
					s.log.Info("refused real-port forward toward relay", "ip", stateIP(sc), "port", m.Port, "addr", m.Addr)
					req.Reply(false, nil)
					continue
				}
				alias, generated, err := registry.NormalizeRequestedAddr(m.Addr)
				if err != nil {
					s.log.Warn("invalid alias in -R", "ip", stateIP(sc), "addr", m.Addr, "err", err)
					req.Reply(false, nil)
					continue
				}
				port := vp.next()
				if _, err := s.deps.Registry.Bind(alias, sc, stateIP(sc), m.Addr, int(port), maxBridgesPerAlias); err != nil {
					s.log.Warn("binding refused", "ip", stateIP(sc), "alias", alias, "err", err)
					req.Reply(false, nil)
					continue
				}
				mode := "custom"
				if generated {
					mode = "generated"
				}
				s.log.Info("tunnel registered", "ip", stateIP(sc), "alias", alias, "mode", mode, "virtual_port", port)
				req.Reply(true, ssh.Marshal(boundPortMsg{Port: port}))

			case "cancel-tcpip-forward":
				var m tcpipForwardMsg
				if err := ssh.Unmarshal(req.Payload, &m); err == nil && m.Port == 0 {
					if alias, _, err := registry.NormalizeRequestedAddr(m.Addr); err == nil {
						if s.deps.Registry.ReleaseOne(alias, sc) {
							s.log.Info("tunnel unregistered", "ip", stateIP(sc), "alias", alias)
						}
					}
				}
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
}

// runControlShell keeps the tunnel alive and tells the operator how to use
// it. In JSON mode it prints the machine-readable status document instead of
// the human banner. Output is written when the shell/exec request arrives —
// after -R processing, so the document always contains the new bindings.
func (s *Server) runControlShell(ctx context.Context, ch ssh.Channel, reqs <-chan *ssh.Request, state *st, jsonMode bool) {
	var once sync.Once
	writeOutput := func() {
		if jsonMode {
			doc, err := s.buildStatusDoc(state.ip, true, state.eff)
			if err == nil {
				ch.Write(append(doc, '\n'))
			} else {
				fmt.Fprintf(ch, "error building status document: %v\r\n", err)
			}
			return
		}
		fmt.Fprint(ch, s.controlBanner(state.ip))
	}

	for req := range reqs {
		switch req.Type {
		case "pty-req", "env":
			req.Reply(true, nil)
		case "shell", "exec":
			req.Reply(true, nil)
			once.Do(writeOutput)
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}

	// Hold the session (and therefore the tunnel) until it dies.
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 512)
		for {
			if _, err := ch.Read(buf); err != nil {
				return
			}
		}
	}()
	select {
	case <-done:
	case <-ctx.Done():
		ch.Close()
	}
}

func (s *Server) controlBanner(ip string) string {
	bindings := s.deps.Registry.ByOwnerIP(ip)
	out := "─── relay ─────────────────────────────────────────────\n"
	if len(bindings) == 0 {
		out += "No tunnel registered yet.\n"
		out += "Reconnect with:  ssh -R 0:127.0.0.1:22 ssh@" + s.deps.AdvertiseHost + "\n"
	}
	for _, b := range bindings {
		out += "Tunnel online: " + b.Alias + "\n\n"
		out += "Connect:            ssh " + b.Alias + "@" + s.deps.AdvertiseHost + "\n"
		out += "Custom device user: ssh <user>+" + b.Alias + "@" + s.deps.AdvertiseHost + "\n\n"
	}
	out += "Keep this session open to keep the tunnel alive.\n"
	out += "───────────────────────────────────────────────────────\n"
	return out
}

// statusDocShape: construction lives in status.go; tests pin the schema.

func stateIP(sc *ssh.ServerConn) string {
	if s, ok := sourceIP(sc.RemoteAddr().String()); ok {
		return s
	}
	return sc.RemoteAddr().String()
}
