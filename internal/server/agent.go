package server

import (
	"bytes"
	"fmt"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// agentLoginError marks failures that happen before the device is reached
// (missing agent, empty keyring): user setup mistakes, not credential
// failures, so fail2ban must not count them.
type agentLoginError struct{ err error }

func (e *agentLoginError) Error() string { return e.err.Error() }
func (e *agentLoginError) Unwrap() error { return e.err }

// agentRequest records whether the client's session signaled agent
// forwarding (`auth-agent-req@openssh.com`, i.e. `ssh -A`). The relay must
// not open the agent channel without that signal: openssh answers the open
// anyway but prints "Warning: ssh server tried agent forwarding … break-in
// attempt" for it. Only direct-tcpip logins (no session exists to carry the
// signal) keep the probing behavior.
type agentRequest int

const (
	agentUnknown   agentRequest = iota // no session signal yet (direct-tcpip path)
	agentWanted                        // auth-agent-req seen on the session
	agentNotWanted                     // session started without auth-agent-req
)

// agentNotRequestedHint is returned when a session starts without the
// auth-agent-req signal: the relay never opens the agent channel on
// guesswork, so the client gets the exact recovery commands instead. The
// PubkeyAuthentication=no escape matters because clients offer their default
// keys automatically — a "password" user often hits the pubkey path without
// knowing it (their key was accepted, so no password prompt ever appeared).
const agentNotRequestedHint = "agent forwarding was not requested, so the device login cannot be signed with your key — reconnect with `ssh -A -o AddKeysToAgent=yes -i <key>` (or `ssh-add` the key first), or use password auth: `ssh -o PubkeyAuthentication=no <user>@<host>`"

// completeAgentLogin opens the OpenSSH agent channel back to the end user's
// client and dials the device through it: the agent signs the device's
// challenge, so the device still authenticates the user's real key — the
// private key never leaves the client. The client must have requested agent
// forwarding (`ssh -A` / ForwardAgent yes).
//
// The agent channel must stay open until the device handshake finishes: the
// signature requests arrive mid-handshake, after Signers(). Failures before
// the dial are wrapped in agentLoginError.
func (s *Server) completeAgentLogin(sc *ssh.ServerConn, ca *stashedAuth) (*ssh.Client, <-chan ssh.NewChannel, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	ch, _, err := sc.OpenChannel("auth-agent@openssh.com", nil)
	if err != nil {
		return nil, nil, nil, nil, &agentLoginError{fmt.Errorf("agent forwarding unavailable (%v) — reconnect with `ssh -A -o AddKeysToAgent=yes -i <key>` (or `ssh-add` the key first), or use password auth: `ssh -o PubkeyAuthentication=no <user>@<host>`", err)}
	}
	signers, err := agent.NewClient(ch).Signers()
	if err != nil {
		ch.Close()
		return nil, nil, nil, nil, &agentLoginError{fmt.Errorf("agent channel failed: %w", err)}
	}
	if len(signers) == 0 {
		ch.Close()
		return nil, nil, nil, nil, &agentLoginError{fmt.Errorf("the forwarded agent has no keys — run `ssh-add ~/.ssh/your_key`, or reconnect with `ssh -A -o AddKeysToAgent=yes` (keeps `ssh -i` working), or use password auth: `ssh -o PubkeyAuthentication=no <user>@<host>`")}
	}
	defer ch.Close() // after the handshake: signatures are requested during it

	return s.dialDeviceAuth(sc, ca.binding, ca.deviceUser,
		[]ssh.AuthMethod{signerAuth(ca.pubkey, signers)})
}

// signerAuth builds the device-side publickey auth method: the key the client
// authenticated with goes first (the device most likely authorized it), then
// the rest of the agent's keys — clients often offer a different key to the
// relay than the one the device wants, and the device picks what it accepts.
func signerAuth(want ssh.PublicKey, signers []ssh.Signer) ssh.AuthMethod {
	ordered := make([]ssh.Signer, 0, len(signers))
	if want != nil {
		for _, sgn := range signers {
			if bytes.Equal(sgn.PublicKey().Marshal(), want.Marshal()) {
				ordered = append(ordered, sgn)
				break
			}
		}
	}
	for _, sgn := range signers {
		if want != nil && bytes.Equal(sgn.PublicKey().Marshal(), want.Marshal()) {
			continue
		}
		ordered = append(ordered, sgn)
	}
	return ssh.PublicKeys(ordered...)
}
