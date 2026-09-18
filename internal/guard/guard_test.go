package guard

import (
	"testing"
	"time"
)

func TestIPLimiter(t *testing.T) {
	l := NewIPLimiter()
	if !l.Acquire("1.1.1.1", 2) || !l.Acquire("1.1.1.1", 2) {
		t.Fatalf("first two acquires must pass")
	}
	if l.Acquire("1.1.1.1", 2) {
		t.Fatalf("third acquire must fail at limit 2")
	}
	if l.Used("1.1.1.1") != 2 {
		t.Fatalf("used = %d", l.Used("1.1.1.1"))
	}
	l.Release("1.1.1.1")
	if !l.Acquire("1.1.1.1", 2) {
		t.Fatalf("acquire after release must pass")
	}
	l.Release("1.1.1.1")
	l.Release("1.1.1.1")
	if l.Used("1.1.1.1") != 0 {
		t.Fatalf("count must hit zero, got %d", l.Used("1.1.1.1"))
	}
	// Different limits per conn (policy override) are evaluated at acquire
	// time against the current count: the second connection's own limit (5)
	// still admits it because only 1 slot is taken.
	if !l.Acquire("2.2.2.2", 1) {
		t.Fatal("acquire 2.2.2.2")
	}
	if !l.Acquire("2.2.2.2", 5) {
		t.Fatal("count=1 < max=5 must be admitted")
	}
}

func TestFail2banBansAfterThreshold(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := NewFail2ban(true)
	f.now = func() time.Time { return now }

	for i := 0; i < F2BThreshold-1; i++ {
		if f.Failure("9.9.9.9") {
			t.Fatalf("ban before threshold (i=%d)", i)
		}
	}
	if !f.Failure("9.9.9.9") {
		t.Fatalf("threshold failure must trigger a ban")
	}
	if banned, d := f.Banned("9.9.9.9"); !banned || d != F2BBaseBan {
		t.Fatalf("banned=%v d=%v, want true/%v", banned, d, F2BBaseBan)
	}

	// Success clears a short failure streak.
	for i := 0; i < F2BThreshold-1; i++ {
		f.Failure("8.8.8.8")
	}
	f.Success("8.8.8.8")
	for i := 0; i < F2BThreshold-1; i++ {
		if f.Failure("8.8.8.8") {
			t.Fatalf("streak must have been cleared by success")
		}
	}
}

func TestFail2banDoublingAndExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := NewFail2ban(true)
	f.now = func() time.Time { return now }

	repeat := func() {
		for i := 0; i < F2BThreshold; i++ {
			f.Failure("7.7.7.7")
		}
	}
	repeat() // ban #1: 1h
	now = now.Add(F2BBaseBan + time.Minute)
	repeat() // ban #2: 2h
	_, d := f.Banned("7.7.7.7")
	if d != 2*F2BBaseBan {
		t.Fatalf("second ban = %v, want %v", d, 2*F2BBaseBan)
	}
	now = now.Add(2*F2BBaseBan + time.Minute)
	repeat() // ban #3: 4h
	_, d = f.Banned("7.7.7.7")
	if d != 4*F2BBaseBan {
		t.Fatalf("third ban = %v, want %v", d, 4*F2BBaseBan)
	}

	// Window expiry: failures older than the window do not count.
	f2 := NewFail2ban(true)
	f2.now = func() time.Time { return now }
	for i := 0; i < F2BThreshold-1; i++ {
		f2.Failure("6.6.6.6")
	}
	now = now.Add(F2BWindow + time.Minute)
	if f2.Failure("6.6.6.6") {
		t.Fatalf("expired failures must not trigger a ban")
	}

	// Disabled manager is a no-op.
	f3 := NewFail2ban(false)
	if f3.Failure("5.5.5.5") || func() bool { b, _ := f3.Banned("5.5.5.5"); return b }() {
		t.Fatalf("disabled fail2ban must be a no-op")
	}
}
