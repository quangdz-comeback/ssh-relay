package server

import (
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/quangdz/ssh-relay/internal/policy"
)

func evalReq(t *testing.T, s *Server, eff policy.Effective, reqType string, payload []byte) (bool, bool, string) {
	t.Helper()
	req := &ssh.Request{Type: reqType, WantReply: true, Payload: payload}
	return s.evalRequest(req, &st{ip: "127.0.0.1", eff: eff})
}

func sshStr(s string) []byte { return ssh.Marshal(struct{ S string }{s}) }

func TestEvalRequestGates(t *testing.T) {
	s := &Server{log: discardLogger()}

	allowed := policy.Effective{AllowTCPForwarding: true, AllowSFTP: true, AllowSCP: true, AllowX11Forwarding: true}
	gated := policy.Effective{AllowTCPForwarding: false, AllowSFTP: false, AllowSCP: false, AllowX11Forwarding: false}

	// sftp: gated off → refused with the reason message.
	fwd, ok, msg := evalReq(t, s, gated, "subsystem", sshStr("sftp"))
	if fwd || ok || !strings.Contains(msg, "sftp is disabled") {
		t.Fatalf("sftp gate: fwd=%v ok=%v msg=%q", fwd, ok, msg)
	}
	// sftp: allowed → forwarded.
	if fwd, ok, _ := evalReq(t, s, allowed, "subsystem", sshStr("sftp")); !fwd {
		t.Fatalf("sftp must forward when allowed (fwd=%v ok=%v)", fwd, ok)
	}

	// scp: legacy exec prefix gated; other commands pass.
	fwd, _, _ = evalReq(t, s, gated, "exec", sshStr("scp -t /tmp/x"))
	if fwd {
		t.Fatalf("scp must be gated")
	}
	if fwd, _, _ := evalReq(t, s, allowed, "exec", sshStr("scp -t /tmp/x")); !fwd {
		t.Fatalf("scp must forward when allowed")
	}
	if fwd, _, _ := evalReq(t, s, gated, "exec", sshStr("ls -la")); !fwd {
		t.Fatalf("non-scp exec must never be gated by --allow-scp")
	}

	// env: only TERM/LANG survive.
	fwd, ok, _ = evalReq(t, s, allowed, "env", ssh.Marshal(struct{ Name, Value string }{"TERM", "xterm"}))
	if !fwd {
		t.Fatalf("TERM must be forwarded")
	}
	fwd, ok, _ = evalReq(t, s, allowed, "env", ssh.Marshal(struct{ Name, Value string }{"LD_PRELOAD", "/evil"}))
	if fwd || !ok {
		t.Fatalf("non-allow-listed env must be dropped with a silent ok (fwd=%v ok=%v)", fwd, ok)
	}

	// x11-req gated.
	if fwd, _, msg := evalReq(t, s, gated, "x11-req", nil); fwd || !strings.Contains(msg, "x11 forwarding is disabled") {
		t.Fatalf("x11 gate: fwd=%v msg=%q", fwd, msg)
	}

	// Verbatim pass-through set.
	for _, rt := range []string{"pty-req", "shell", "signal", "window-change"} {
		if fwd, _, _ := evalReq(t, s, gated, rt, []byte{1, 2, 3}); !fwd {
			t.Fatalf("%s must always be forwarded", rt)
		}
	}
}
