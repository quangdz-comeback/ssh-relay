package guard

import "sync"

// IPLimiter accounts concurrent authenticated connections per source IP.
// The per-IP maximum is passed at Acquire time because it can differ per
// connection (policy.json custom_policies, ARCHITECTURE §7.1/§6.3).
type IPLimiter struct {
	mu     sync.Mutex
	counts map[string]int
}

func NewIPLimiter() *IPLimiter {
	return &IPLimiter{counts: map[string]int{}}
}

// Acquire reserves one slot for ip; false when the limit is reached.
func (l *IPLimiter) Acquire(ip string, max int) bool {
	if max < 1 {
		max = 1
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counts[ip] >= max {
		return false
	}
	l.counts[ip]++
	return true
}

// Release returns ip's slot.
func (l *IPLimiter) Release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counts[ip] <= 1 {
		delete(l.counts, ip)
		return
	}
	l.counts[ip]--
}

// Used reports live connections for ip.
func (l *IPLimiter) Used(ip string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.counts[ip]
}
