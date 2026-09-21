package registry

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// fakeConn is only an identity token for owner comparisons.
func fakeConn(name string) *ssh.ServerConn {
	_ = name
	return &ssh.ServerConn{}
}

func TestBindLookupRelease(t *testing.T) {
	r := New()
	a := fakeConn("deviceA")
	b, err := r.Bind("myvps", a, "1.2.3.4", "myvps", 61001, 10)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if b.Alias != "myvps" {
		t.Fatalf("alias = %q", b.Alias)
	}
	if got, ok := r.Lookup("MyVps"); !ok || got != b {
		t.Fatalf("lookup case-insensitive failed: %v %v", got, ok)
	}
	if _, ok := r.Lookup("other"); ok {
		t.Fatalf("unexpected binding")
	}
	// Conflict.
	if _, err := r.Bind("myvps", fakeConn("deviceB"), "1.2.3.4", "myvps", 61002, 10); err == nil {
		t.Fatalf("duplicate bind must fail")
	}
	// Release by owner.
	if !r.ReleaseOne("MYVPS", a) {
		t.Fatalf("release by owner failed")
	}
	if _, err := r.Bind("myvps", fakeConn("deviceB"), "1.2.3.4", "myvps", 61002, 10); err != nil {
		t.Fatalf("bind after release: %v", err)
	}
}

func TestAliasRules(t *testing.T) {
	r := New()
	owner := fakeConn("d")
	// Reserved name.
	if _, err := r.Bind("json", owner, "ip", "json", 1, 1); err == nil {
		t.Fatalf("json must be reserved")
	}
	// Generated prefix is not registrable as a CUSTOM name (the -R address
	// path validates before Bind; Bind itself accepts d- for generated IDs).
	if _, generated, err := NormalizeRequestedAddr("d-abc123"); err == nil || generated {
		t.Fatalf("d- prefix must not be registrable as custom name")
	}
	// Bad charset / too short.
	for _, bad := range []string{"ab", "-abc", "abc-", "a b", "a.b", "x"} {
		if _, err := r.Bind(bad, owner, "ip", bad, 1, 1); err == nil {
			t.Fatalf("invalid alias %q accepted", bad)
		}
	}
	// Uppercase input is normalized, not rejected.
	if b, err := r.Bind("UPPER", fakeConn("d2"), "ip", "UPPER", 1, 1); err != nil || b.Alias != "upper" {
		t.Fatalf("uppercase normalize: %v %v", b, err)
	}
	// Generated aliases are valid and unique.
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		a, generated, err := NormalizeRequestedAddr("")
		if err != nil || !generated {
			t.Fatalf("NormalizeRequestedAddr(\"\") = %v, %v", a, generated)
		}
		if !strings.HasPrefix(a, "d-") || len(a) != 12 {
			t.Fatalf("generated alias %q malformed", a)
		}
		if seen[a] {
			t.Fatalf("generated alias %q repeated", a)
		}
		seen[a] = true
	}
	// Custom address passes through.
	a, generated, err := NormalizeRequestedAddr("My-VPS")
	if err != nil || generated || a != "my-vps" {
		t.Fatalf("custom alias: %q %v %v", a, generated, err)
	}
	// Inner underscores are valid (Termux/Android names like u0_a96);
	// leading/trailing underscores stay invalid.
	if b, err := r.Bind("u0_a96", fakeConn("d3"), "ip", "u0_a96", 1, 1); err != nil || b.Alias != "u0_a96" {
		t.Fatalf("underscore alias: %v %v", b, err)
	}
	for _, bad := range []string{"_abc", "ab_"} {
		if _, err := r.Bind(bad, owner, "ip", bad, 1, 1); err == nil {
			t.Fatalf("invalid underscore alias %q accepted", bad)
		}
	}
	// localhost means generate.
	if _, generated, _ = NormalizeRequestedAddr("localhost"); !generated {
		t.Fatalf("localhost must generate")
	}
}

func TestOwnerAccountingAndByIP(t *testing.T) {
	r := New()
	owner := fakeConn("device")
	for i := 0; i < MaxBindingsPerConn; i++ {
		alias := fmt.Sprintf("tunnel-%02d", i)
		if _, err := r.Bind(alias, owner, "9.9.9.9", alias, 61000+i, 2); err != nil {
			t.Fatalf("bind %s: %v", alias, err)
		}
	}
	if _, err := r.Bind("overflow", owner, "9.9.9.9", "overflow", 61999, 2); err != ErrTooMany {
		t.Fatalf("per-conn cap: err=%v want ErrTooMany", err)
	}
	if got := len(r.ByOwnerIP("9.9.9.9")); got != MaxBindingsPerConn {
		t.Fatalf("ByOwnerIP = %d", got)
	}
	if got := len(r.ByOwnerIP("1.1.1.1")); got != 0 {
		t.Fatalf("ByOwnerIP other = %d", got)
	}
	if _, err := r.Bind("gamma", owner, "9.9.9.9", "gamma", 61000, 2); err != ErrTooMany {
		t.Fatalf("per-conn cap: err=%v want ErrTooMany", err)
	}
	freed := r.ReleaseByOwner(owner)
	if len(freed) != MaxBindingsPerConn || r.Count() != 0 {
		t.Fatalf("release-by-owner: %v count=%d", freed, r.Count())
	}
}

func TestBridgeCapAndConcurrency(t *testing.T) {
	r := New()
	b, _ := r.Bind("cap", fakeConn("d"), "ip", "cap", 1, 2)
	if !b.AcquireBridge() || !b.AcquireBridge() {
		t.Fatalf("first two acquires must pass")
	}
	if b.AcquireBridge() {
		t.Fatalf("third acquire must fail at cap 2")
	}
	b.ReleaseBridge()
	if !b.AcquireBridge() {
		t.Fatalf("acquire after release must pass")
	}
	// Concurrent release safety.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); b.ReleaseBridge() }()
	}
	wg.Wait()
}
