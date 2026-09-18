package config

import "testing"

func TestParseFlags(t *testing.T) {
	c, err := Parse([]string{
		"--listen-port", "2200",
		"--ip", "127.0.0.1",
		"--bw-limit", "10M",
		"--allowed-sessions-per-ip", "5",
		"--fail2ban=false",
		"--allow-sftp=false",
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.ListenPort != 2200 || c.ListenIP != "127.0.0.1" || c.AllowedSessionsPerIP != 5 {
		t.Fatalf("unexpected values: %+v", c)
	}
	if !c.IsSet("allow-sftp") || c.AllowSFTP {
		t.Fatalf("allow-sftp flag not tracked: set=%v val=%v", c.IsSet("allow-sftp"), c.AllowSFTP)
	}
	if c.IsSet("allow-scp") || !c.AllowSCP {
		t.Fatalf("unset flag should keep default: set=%v val=%v", c.IsSet("allow-scp"), c.AllowSCP)
	}
	if c.Fail2ban {
		t.Fatalf("fail2ban=false not honored")
	}
	if got, want := c.ListenAddr(), "127.0.0.1:2200"; got != want {
		t.Fatalf("ListenAddr = %q, want %q", got, want)
	}
}

func TestDefaults(t *testing.T) {
	c, err := Parse(nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.ListenPort != DefaultListenPort || c.AllowedSessionsPerIP != DefaultSessionsPerIP {
		t.Fatalf("defaults wrong: %+v", c)
	}
	if c.Fail2ban != true || c.AllowTCPForwarding != true || c.AllowSFTP != true || c.AllowSCP != true || c.AllowX11Forwarding != false {
		t.Fatalf("flag defaults wrong: %+v", c)
	}
	if got, want := c.ListenAddr(), ":2222"; got != want {
		t.Fatalf("ListenAddr = %q, want %q", got, want)
	}
}

func TestValidationErrors(t *testing.T) {
	cases := [][]string{
		{"--listen-port", "0"},
		{"--listen-port", "70000"},
		{"--ip", "not-an-ip"},
		{"--bw-limit", "10X"},
		{"--allowed-sessions-per-ip", "0"},
		{"--log-level", "verbose"},
	}
	for _, args := range cases {
		if _, err := Parse(args); err == nil {
			t.Errorf("Parse(%v) expected error", args)
		}
	}
}
