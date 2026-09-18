// Package policy implements the layered policy model: built-in defaults →
// policy.json "default" block → explicitly set CLI flags → first matching
// per-IP custom_policies entry (ARCHITECTURE §6.3).
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"

	"github.com/quangdz/ssh-relay/internal/bwlimit"
)

// Fields is the set of overridable knobs. Pointer fields are "present only"
// layers: nil means "inherit from the previous layer".
type Fields struct {
	AllowTCPForwarding *bool   `json:"allow_tcp_forwarding,omitempty"`
	AllowSFTP          *bool   `json:"allow_sftp,omitempty"`
	AllowSCP           *bool   `json:"allow_scp,omitempty"`
	AllowX11Forwarding *bool   `json:"allow_x11_forwarding,omitempty"`
	BWLimit            *string `json:"bw_limit,omitempty"`
	MaxSessionsPerIP   *int    `json:"max_sessions_per_ip,omitempty"`
	Blocked            *bool   `json:"blocked,omitempty"`
	Reason             string  `json:"reason,omitempty"`
}

type customPolicyJSON struct {
	Name   string   `json:"name"`
	CIDRs  []string `json:"cidrs"`
	Policy Fields   `json:"policy"`
}

// PolicySet is the parsed policy.json. Strict schema: unknown fields are a
// load error (fail-closed on mass deploys).
type PolicySet struct {
	ListenIP string             `json:"listen_ip,omitempty"`
	Hostname string             `json:"hostname,omitempty"`
	Default  Fields             `json:"default"`
	Custom   []customPolicyJSON `json:"custom_policies,omitempty"`

	compiled []compiledCustom
}

type compiledCustom struct {
	name     string
	prefixes []netip.Prefix
	fields   Fields
}

// Effective is the fully resolved per-connection policy (no pointers).
type Effective struct {
	AllowTCPForwarding bool
	AllowSFTP          bool
	AllowSCP           bool
	AllowX11Forwarding bool
	BWLimitPerSec      int64 // 0 = unlimited
	MaxSessionsPerIP   int
	Blocked            bool
	BlockReason        string
}

// Parse decodes and validates a policy.json payload.
func Parse(data []byte) (*PolicySet, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var set PolicySet
	if err := dec.Decode(&set); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if err := set.compile(); err != nil {
		return nil, err
	}
	return &set, nil
}

// LoadFile reads and parses policy.json from disk.
func LoadFile(path string) (*PolicySet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

func (s *PolicySet) compile() error {
	if s.ListenIP != "" {
		if _, err := netip.ParseAddr(s.ListenIP); err != nil {
			return fmt.Errorf("policy: listen_ip %q is not a valid IP", s.ListenIP)
		}
	}
	seen := map[string]bool{}
	for _, c := range s.Custom {
		if c.Name == "" {
			return fmt.Errorf("policy: custom_policies entry missing name")
		}
		if seen[c.Name] {
			return fmt.Errorf("policy: duplicate custom policy name %q", c.Name)
		}
		seen[c.Name] = true
		if len(c.CIDRs) == 0 {
			return fmt.Errorf("policy: custom policy %q has no cidrs", c.Name)
		}
		cc := compiledCustom{name: c.Name, fields: c.Policy}
		for _, cidr := range c.CIDRs {
			p, err := parseCIDR(cidr)
			if err != nil {
				return fmt.Errorf("policy: custom policy %q: %w", c.Name, err)
			}
			cc.prefixes = append(cc.prefixes, p)
		}
		if err := validateFields(c.Name, c.Policy); err != nil {
			return err
		}
		s.compiled = append(s.compiled, cc)
	}
	return validateFields("default", s.Default)
}

func parseCIDR(s string) (netip.Prefix, error) {
	// Accept bare IPs as /32 (v4) or /128 (v6) for operator convenience.
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	return netip.ParsePrefix(s)
}

func validateFields(what string, f Fields) error {
	if f.BWLimit != nil {
		if _, err := bwlimit.Parse(*f.BWLimit); err != nil {
			return fmt.Errorf("policy: %s: bw_limit: %w", what, err)
		}
	}
	if f.MaxSessionsPerIP != nil && *f.MaxSessionsPerIP < 1 {
		return fmt.Errorf("policy: %s: max_sessions_per_ip must be >= 1", what)
	}
	return nil
}

// Apply overlays present-only fields onto dst.
func (f Fields) Apply(dst *Effective) {
	if f.AllowTCPForwarding != nil {
		dst.AllowTCPForwarding = *f.AllowTCPForwarding
	}
	if f.AllowSFTP != nil {
		dst.AllowSFTP = *f.AllowSFTP
	}
	if f.AllowSCP != nil {
		dst.AllowSCP = *f.AllowSCP
	}
	if f.AllowX11Forwarding != nil {
		dst.AllowX11Forwarding = *f.AllowX11Forwarding
	}
	if f.BWLimit != nil {
		if v, err := bwlimit.Parse(*f.BWLimit); err == nil {
			dst.BWLimitPerSec = v
		}
	}
	if f.MaxSessionsPerIP != nil {
		dst.MaxSessionsPerIP = *f.MaxSessionsPerIP
	}
	if f.Blocked != nil {
		dst.Blocked = *f.Blocked
		if *f.Blocked && f.Reason != "" {
			dst.BlockReason = f.Reason
		}
	}
}

// OverlayDefault applies the file's default block onto base and returns the
// result (used at startup; the hot path uses EffectiveFor).
func (s *PolicySet) OverlayDefault(base Effective) Effective {
	eff := base
	s.Default.Apply(&eff)
	return eff
}

// EffectiveFor resolves the per-connection policy: base (already carrying
// builtin + file-default + explicit-flag layers) overlaid with the first
// custom policy whose CIDRs contain ip. First match wins.
func (s *PolicySet) EffectiveFor(base Effective, ip netip.Addr) Effective {
	eff := base
	for _, c := range s.compiled {
		matched := false
		for _, p := range c.prefixes {
			if p.Contains(ip) {
				matched = true
				break
			}
		}
		if matched {
			c.fields.Apply(&eff)
			break
		}
	}
	return eff
}
