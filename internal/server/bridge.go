package server

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/quangdz/ssh-relay/internal/throttle"
)

// Minimal RFC 4254 payloads the relay must inspect for policy. Everything
// else is mirrored verbatim (sshpiper's lesson: don't decode what you don't
// need to police).
type execRequestMsg struct {
	Command string
}

type subsystemRequestMsg struct {
	Name string
}

type envRequestMsg struct {
	Name  string
	Value string
}

type exitStatusMsg struct {
	Status uint32
}

// envAllowlist is what survives the hop to the device (§5.3).
var envAllowlist = map[string]bool{"TERM": true, "LANG": true}

// mirrorSession splices one end-user session channel to a device-side
// session: requests are mirrored (with policy gates), data flows through
// throttled pumps, exit status maps back (255 when the device never sent
// one), and stderr keeps its extended-data type.
func (s *Server) mirrorSession(ctx context.Context, clientCh ssh.Channel, chReqs <-chan *ssh.Request, ca stashedAuth, state *st, bwUp, bwDown *throttle.Limiter) {
	// A raw session channel (not ssh.Session) so we can read the device's
	// exit-status/exit-signal requests ourselves.
	devCh, devReqs, err := ca.dev.OpenChannel("session", nil)
	if err != nil {
		fmt.Fprintf(clientCh.Stderr(), "relay: could not open device session: %v\r\n", err)
		clientCh.SendRequest("exit-status", false, ssh.Marshal(exitStatusMsg{Status: 255}))
		clientCh.Close()
		return
	}
	defer devCh.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Control goroutines (request mirroring + exit mapping).
	var wg sync.WaitGroup
	wg.Add(2)

	// Data pumps: exit ordering matters — after the device session ends we
	// send exit-status, then wait for stdout/stderr to drain before closing
	// the client channel, so no output is lost. The stdin pump ends when the
	// client closes its side (it does after seeing exit-status).
	var pumpWg sync.WaitGroup
	pumpWg.Add(3)

	// Client → device request mirroring (pty, shell, exec, env, x11, …).
	go func() {
		defer wg.Done()
		for req := range chReqs {
			forwarded, localOK, localMsg := s.evalRequest(req, state)
			if !forwarded {
				if localMsg != "" {
					fmt.Fprintf(clientCh.Stderr(), "relay: %s\r\n", localMsg)
				}
				if req.WantReply {
					req.Reply(localOK, nil)
				}
				continue
			}
			res, rerr := devCh.SendRequest(req.Type, req.WantReply, req.Payload)
			if req.WantReply {
				if rerr != nil {
					req.Reply(false, nil)
					return // device connection is gone; the pumps will notice too
				}
				req.Reply(res, nil)
			} else if rerr != nil {
				return
			}
		}
	}()

	// stdin (client → device, throttled).
	go func() {
		defer pumpWg.Done()
		ioCopy(bwUp.Writer(ctx, devCh), bwUp.Reader(ctx, clientCh))
	}()
	// stdout (device → client, throttled).
	go func() {
		defer pumpWg.Done()
		ioCopy(bwDown.Writer(ctx, clientCh), bwDown.Reader(ctx, devCh))
	}()
	// stderr keeps extended-data semantics.
	go func() {
		defer pumpWg.Done()
		ioCopy(clientCh.Stderr(), devCh.Stderr())
	}()

	// Device → client exit mapping: exit-status/exit-signal forwarded
	// verbatim; a device death without any exit request maps to 255. Cancel
	// first so a throttled stdin pump cannot stall the drain.
	go func() {
		defer wg.Done()
		exitSeen := false
		for req := range devReqs {
			switch req.Type {
			case "exit-status", "exit-signal":
				exitSeen = true
				clientCh.SendRequest(req.Type, false, req.Payload)
			default:
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}
		if !exitSeen {
			clientCh.SendRequest("exit-status", false, ssh.Marshal(exitStatusMsg{Status: 255}))
		}
		cancel()
		pumpWg.Wait()
		clientCh.Close()
	}()

	wg.Wait()
}

// evalRequest decides what happens to a client session request:
// forwarded (verbatim payload), or answered locally (ok, message).
func (s *Server) evalRequest(req *ssh.Request, state *st) (forwarded bool, ok bool, msg string) {
	switch req.Type {
	case "exec":
		var m execRequestMsg
		if err := ssh.Unmarshal(req.Payload, &m); err == nil {
			cmd := strings.TrimSpace(m.Command)
			if !state.eff.AllowSCP && (cmd == "scp" || strings.HasPrefix(cmd, "scp ")) {
				return false, false, "scp is disabled on this relay (--allow-scp=false)"
			}
		}
		return true, false, ""

	case "subsystem":
		var m subsystemRequestMsg
		if err := ssh.Unmarshal(req.Payload, &m); err == nil && m.Name == "sftp" && !state.eff.AllowSFTP {
			return false, false, "sftp is disabled on this relay (--allow-sftp=false)"
		}
		return true, false, ""

	case "env":
		var m envRequestMsg
		if err := ssh.Unmarshal(req.Payload, &m); err == nil && !envAllowlist[m.Name] {
			return false, true, "" // silently drop non-allow-listed env
		}
		return true, false, ""

	case "x11-req":
		if !state.eff.AllowX11Forwarding {
			return false, false, "x11 forwarding is disabled on this relay (--allow-x11-forwarding=false)"
		}
		return true, false, ""

	case "pty-req", "shell", "signal", "window-change":
		return true, false, ""

	case "auth-agent-req@openssh.com":
		// The agent channel itself is accepted in handleClient; v1 does not
		// use it (M6 pubkey pass-through will).
		return false, true, ""

	case "break":
		return false, true, ""

	default:
		return false, false, ""
	}
}
