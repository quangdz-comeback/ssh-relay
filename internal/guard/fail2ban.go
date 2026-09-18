// Package guard implements the relay's protective limits: per-IP concurrent
// session accounting and the built-in fail2ban ban manager.
package guard

import (
	"sync"
	"time"
)

// Default fail2ban tuning (documented in PLAN §5/M4; package-level constants
// for v1 — flags stay at the user-facing surface).
const (
	F2BThreshold = 5
	F2BWindow    = 10 * time.Minute
	F2BBaseBan   = time.Hour
	F2BMaxBan    = 24 * time.Hour
)

type banState struct {
	until     time.Time
	violation int // how many times this IP has been banned (drives doubling)
}

// Fail2ban counts authentication failures per source IP and temporarily bans
// offenders. In-memory only.
type Fail2ban struct {
	enabled bool
	now     func() time.Time

	mu    sync.Mutex
	fails map[string][]time.Time
	bans  map[string]banState
}

// NewFail2ban builds a ban manager; enabled=false turns it into a no-op.
func NewFail2ban(enabled bool) *Fail2ban {
	return &Fail2ban{
		enabled: enabled,
		now:     time.Now,
		fails:   map[string][]time.Time{},
		bans:    map[string]banState{},
	}
}

// Banned reports whether ip is currently banned and for how much longer.
func (f *Fail2ban) Banned(ip string) (bool, time.Duration) {
	if !f.enabled {
		return false, 0
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.bans[ip]
	if !ok {
		return false, 0
	}
	if d := b.until.Sub(f.now()); d > 0 {
		return true, d
	}
	delete(f.bans, ip)
	return false, 0
}

// Failure records an auth failure; when the threshold inside the window is
// reached the IP is banned (first ban 1h, doubling per re-offense, 24h cap).
// It reports whether this failure triggered a ban.
func (f *Fail2ban) Failure(ip string) bool {
	if !f.enabled {
		return false
	}
	now := f.now()
	f.mu.Lock()
	defer f.mu.Unlock()

	keep := f.fails[ip][:0]
	for _, t := range f.fails[ip] {
		if now.Sub(t) <= F2BWindow {
			keep = append(keep, t)
		}
	}
	keep = append(keep, now)
	if len(keep) < F2BThreshold {
		f.fails[ip] = keep
		return false
	}

	violation := 1
	if prev, ok := f.bans[ip]; ok {
		violation = prev.violation + 1
	}
	ban := F2BBaseBan << (violation - 1)
	if ban > F2BMaxBan || ban <= 0 {
		ban = F2BMaxBan
	}
	f.bans[ip] = banState{until: now.Add(ban), violation: violation}
	delete(f.fails, ip)
	return true
}

// Success clears the failure window for ip (a legitimate user mistyping once
// is not an attacker).
func (f *Fail2ban) Success(ip string) {
	if !f.enabled {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.fails, ip)
}
