package server

import (
	"bytes"
	"testing"

	"github.com/quangdz/ssh-relay/internal/config"
)

func TestToTerminal(t *testing.T) {
	in := []byte("a\nb\nc\n")
	if got := toTerminal(in, false); !bytes.Equal(got, in) {
		t.Fatalf("no-pty output must keep LF: %q", got)
	}
	got := toTerminal(in, true)
	if bytes.Contains(got, []byte("\n")) && bytes.Contains(got, []byte("\r\n")) {
		if !bytes.Equal(got, []byte("a\r\nb\r\nc\r\n")) {
			t.Fatalf("pty output = %q, want CRLF", got)
		}
	} else {
		t.Fatalf("pty output must use CRLF: %q", got)
	}
}

func TestSSHCommandPortFormatting(t *testing.T) {
	s := &Server{deps: Deps{Cfg: &config.Config{ListenPort: 22}, AdvertiseHost: "1.2.3.4"}}
	if got, want := s.sshCommand("d-abc123"), "ssh d-abc123@1.2.3.4"; got != want {
		t.Fatalf("port 22: %q, want %q", got, want)
	}
	if got, want := s.sshUserCommand("myvps"), "ssh <user>+myvps@1.2.3.4"; got != want {
		t.Fatalf("port 22 user: %q, want %q", got, want)
	}

	s.deps.Cfg.ListenPort = 2222
	if got, want := s.sshCommand("d-abc123"), "ssh -p 2222 d-abc123@1.2.3.4"; got != want {
		t.Fatalf("port 2222: %q, want %q", got, want)
	}
	if got, want := s.sshUserCommand("myvps"), "ssh -p 2222 <user>+myvps@1.2.3.4"; got != want {
		t.Fatalf("port 2222 user: %q, want %q", got, want)
	}

	// Nil Cfg (tests/embedding) behaves like port 22.
	s2 := &Server{deps: Deps{AdvertiseHost: "r"}}
	if got, want := s2.sshCommand("a-b-c"), "ssh a-b-c@r"; got != want {
		t.Fatalf("nil cfg: %q, want %q", got, want)
	}
}
