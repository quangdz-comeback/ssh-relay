package policy

import (
	"net/netip"
	"testing"
)

func boolPtr(b bool) *bool    { return &b }
func intPtr(i int) *int       { return &i }
func strPtr(s string) *string { return &s }

const samplePolicy = `{
  "listen_ip": "127.0.0.1",
  "default": {
    "allow_tcp_forwarding": false,
    "bw_limit": "10M",
    "max_sessions_per_ip": 7
  },
  "custom_policies": [
    {
      "name": "office",
      "cidrs": ["10.0.0.0/8", "192.0.2.7"],
      "policy": { "allow_tcp_forwarding": true, "max_sessions_per_ip": 10 }
    },
    {
      "name": "banned",
      "cidrs": ["203.0.113.9/32"],
      "policy": { "blocked": true, "reason": "abuse" }
    }
  ]
}`

func base() Effective {
	return Effective{
		AllowTCPForwarding: true,
		AllowSFTP:          true,
		AllowSCP:           true,
		AllowX11Forwarding: false,
		BWLimitPerSec:      0,
		MaxSessionsPerIP:   3,
	}
}

func TestParseAndLayering(t *testing.T) {
	set, err := Parse([]byte(samplePolicy))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if set.ListenIP != "127.0.0.1" {
		t.Fatalf("listen_ip = %q", set.ListenIP)
	}

	// Layer 1+2: file default over builtin.
	eff := set.OverlayDefault(base())
	if eff.AllowTCPForwarding {
		t.Fatalf("default block allow_tcp_forwarding not applied")
	}
	if eff.BWLimitPerSec != 10*1024*1024 || eff.MaxSessionsPerIP != 7 {
		t.Fatalf("default block numbers wrong: %+v", eff)
	}
	if !eff.AllowSFTP {
		t.Fatalf("absent field must inherit builtin")
	}

	// Layer 3 simulates "explicit flag wins": apply after file default.
	flagLayer := eff
	flagLayer.AllowTCPForwarding = true // --allow-tcp-forwarding=true passed
	if !flagLayer.AllowTCPForwarding {
		t.Fatalf("flag layer must win over file default")
	}

	// Layer 4: custom policy, first match wins (10.9.9.9 hits "office").
	eff2 := set.EffectiveFor(flagLayer, netip.MustParseAddr("10.9.9.9"))
	if !eff2.AllowTCPForwarding || eff2.MaxSessionsPerIP != 10 {
		t.Fatalf("office policy not applied: %+v", eff2)
	}
	if eff2.BWLimitPerSec != 10*1024*1024 {
		t.Fatalf("office must inherit bw_limit from default block: %+v", eff2)
	}

	// Bare IP cidr matches.
	eff3 := set.EffectiveFor(flagLayer, netip.MustParseAddr("192.0.2.7"))
	if eff2.MaxSessionsPerIP != 10 || !eff3.AllowTCPForwarding {
		t.Fatalf("bare-IP cidr not matched: %+v", eff3)
	}

	// Blocked IP.
	eff4 := set.EffectiveFor(flagLayer, netip.MustParseAddr("203.0.113.9"))
	if !eff4.Blocked || eff4.BlockReason != "abuse" {
		t.Fatalf("blocked policy not applied: %+v", eff4)
	}

	// Unmatched IP keeps the layered base (flag layer included).
	eff5 := set.EffectiveFor(flagLayer, netip.MustParseAddr("8.8.8.8"))
	if eff5.MaxSessionsPerIP != 7 || !eff5.AllowTCPForwarding {
		t.Fatalf("unmatched ip must keep base: %+v", eff5)
	}
}

func TestStrictSchema(t *testing.T) {
	bad := []string{
		`{"nope": 1}`,
		`{"default": {"nope": true}}`,
		`{"default": {"bw_limit": "10X"}}`,
		`{"default": {"max_sessions_per_ip": 0}}`,
		`{"listen_ip": "nope"}`,
		`{"custom_policies": [{"name": "x", "cidrs": []}]}`,
		`{"custom_policies": [{"name": "x", "cidrs": ["300.1.2.3/4"]}]}`,
		`{"custom_policies": [{"name": "", "cidrs": ["10.0.0.0/8"]}]}`,
		`{"custom_policies": [{"name": "a", "cidrs": ["10.0.0.0/8"]}, {"name": "a", "cidrs": ["11.0.0.0/8"]}]}`,
		`{`,
	}
	for _, s := range bad {
		if _, err := Parse([]byte(s)); err == nil {
			t.Errorf("Parse(%s) expected error", s)
		}
	}
}

func TestEmptySet(t *testing.T) {
	set := EmptySet()
	eff := set.OverlayDefault(base())
	if eff != base() {
		t.Fatalf("empty set must not change base: %+v", eff)
	}
}
