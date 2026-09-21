package server

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"

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
// one), and stderr keeps its extended-data type. pre holds the setup
// requests the client sent before its start request (pty-req, env,
// auth-agent-req, …); they are replayed to the device first. pty carries the
// session's PTY state so locally generated messages get CRLF endings when a
// raw-mode terminal (Windows console) is on the other end.
func (s *Server) mirrorSession(ctx context.Context, clientCh ssh.Channel, chReqs <-chan *ssh.Request, ca *stashedAuth, state *st, bwUp, bwDown *throttle.Limiter, pre []*ssh.Request, pty *atomic.Bool) {
	// A raw session channel (not ssh.Session) so we can read the device's
	// exit-status/exit-signal requests ourselves.
	devCh, devReqs, err := ca.dev.OpenChannel("session", nil)
	if err != nil {
		clientCh.Stderr().Write(toTerminal([]byte("relay: could not open device session: "+err.Error()+"\n"), pty.Load()))
		clientCh.SendRequest("exit-status", false, ssh.Marshal(exitStatusMsg{Status: 255}))
		clientCh.Close()
		return
	}
	defer devCh.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Control goroutines (exit mapping) + data pumps.
	var wg sync.WaitGroup
	wg.Add(1)

	// Data pumps: exit ordering matters — after the device session ends we
	// send exit-status, then drain the output pumps before closing the
	// client channel, so no output is lost.
	var pumpWg sync.WaitGroup    // all pumps
	var outPumpWg sync.WaitGroup // device → client output pumps only
	pumpWg.Add(3)
	outPumpWg.Add(2)

	// mirrorOne evaluates one request against policy, forwards it to the
	// device, and relays the device's answer; refused requests get their
	// message on the client's stderr. Returns false once the device
	// connection is gone; the pumps will notice too.
	mirrorOne := func(req *ssh.Request) bool {
		forwarded, localOK, localMsg := s.evalRequest(req, ca, state)
		if !forwarded {
			if localMsg != "" {
				clientCh.Stderr().Write(toTerminal([]byte("relay: "+localMsg+"\n"), pty.Load()))
			}
			if req.WantReply {
				req.Reply(localOK, nil)
			}
			return true
		}
		res, rerr := devCh.SendRequest(req.Type, req.WantReply, req.Payload)
		if req.WantReply {
			if rerr != nil {
				req.Reply(false, nil)
				return false // device connection is gone; the pumps will notice too
			}
			req.Reply(res, nil)
		} else if rerr != nil {
			return false
		}
		return true
	}

	// Device → client exit mapping: the first exit-status/exit-signal is
	// relayed verbatim and ENDS the client session right away. The device
	// connection itself may linger, and the stdin pump blocks on the user's
	// idle terminal with no cancel path — waiting for either left openssh
	// terminals hanging after logout until one extra keystroke. A device
	// death without any exit request maps to 255. Ordering inside finish
	// matters: drain the output pumps while the client channel is still
	// open (no lost tail output), and only then close the client channel,
	// which is also what unblocks the stdin pump.
	var finishOnce sync.Once
	finish := func(exitSeen bool) {
		finishOnce.Do(func() {
			if !exitSeen {
				clientCh.SendRequest("exit-status", false, ssh.Marshal(exitStatusMsg{Status: 255}))
			}
			devCh.Close()    // ends the device stream; buffered output stays readable
			outPumpWg.Wait() // drain every buffered byte to the client first
			cancel()
			clientCh.Close()
			pumpWg.Wait()
		})
	}
	go func() {
		defer wg.Done()
		for req := range devReqs {
			switch req.Type {
			case "exit-status", "exit-signal":
				clientCh.SendRequest(req.Type, false, req.Payload)
				finish(true)
			default:
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}
		finish(false)
	}()

	// Replay the buffered setup requests. pty-req was already answered
	// locally (the client blocks on its reply), so only the device-side
	// allocation happens here; everything else behaves like a live request.
	for _, req := range pre {
		if req.Type == "pty-req" {
			if _, err := devCh.SendRequest("pty-req", true, req.Payload); err != nil {
				break
			}
			continue
		}
		if !mirrorOne(req) {
			break
		}
	}

	// Data pumps start only AFTER the replay: client stdin racing ahead of
	// the replayed shell request reached the device out of order and sshd
	// discarded it (typed input silently lost — visible with slow device
	// handshakes). The device's early output stays buffered on devCh until
	// the output pump drains it, so nothing is lost the other way either.
	//
	// stdin (client → device, throttled).
	go func() {
		defer pumpWg.Done()
		ioCopy(bwUp.Writer(ctx, devCh), bwUp.Reader(ctx, clientCh))
	}()
	// stdout (device → client, throttled).
	go func() {
		defer pumpWg.Done()
		defer outPumpWg.Done()
		ioCopy(bwDown.Writer(ctx, clientCh), bwDown.Reader(ctx, devCh))
	}()
	// stderr keeps extended-data semantics.
	go func() {
		defer pumpWg.Done()
		defer outPumpWg.Done()
		ioCopy(clientCh.Stderr(), devCh.Stderr())
	}()

	// Live requests from here on.
	for req := range chReqs {
		if !mirrorOne(req) {
			break
		}
	}

	wg.Wait()
}

// evalRequest decides what happens to a client session request:
// forwarded (verbatim payload), or answered locally (ok, message). The
// stashed login decides agent behaviour (public-key logins only, §5.2.1).
func (s *Server) evalRequest(req *ssh.Request, ca *stashedAuth, state *st) (forwarded bool, ok bool, msg string) {
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
		// The client asked for agent forwarding (-A). It activates only for
		// public-key logins, where the key is already in play; password/none
		// logins get an explicit refusal so the client disables forwarding
		// instead of silently missing the agent. A device that refuses the
		// mirrored request disables it on its side the same way.
		if !ca.pubkeyAuth {
			return false, false, "agent forwarding requires public key auth"
		}
		return true, false, ""

	case "break":
		return false, true, ""

	default:
		return false, false, ""
	}
}
