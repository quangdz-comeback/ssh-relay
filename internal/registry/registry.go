// Package registry owns the live alias → device-connection bindings.
package registry

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	// GeneratedPrefix marks machine-generated aliases (deviceIDs). Custom
	// aliases may not use it, keeping the two namespaces disjoint.
	GeneratedPrefix = "d-"

	// MaxBindingsPerConn caps -R registrations on one control connection.
	MaxBindingsPerConn = 8
)

var (
	ErrAliasInUse    = errors.New("alias already bound to a live tunnel")
	ErrAliasInvalid  = errors.New("alias is not valid")
	ErrAliasReserved = errors.New("alias is reserved")
	ErrTooMany       = errors.New("too many bindings on this connection")
)

// Binding is one live alias registration.
type Binding struct {
	Alias       string
	Owner       *ssh.ServerConn // control connection; identity for teardown
	OwnerIP     string
	ListenAddr  string       // bind address as requested by the device ("" = generated)
	VirtualPort uint32       // fake bound port, only used for forwarded-tcpip opens
	CreatedAt   atomic.Value // time.Time

	bridges    atomic.Int32
	MaxBridges int
}

// AcquireBridge reserves one end-user session slot; false when full.
func (b *Binding) AcquireBridge() bool {
	if b.bridges.Add(1) > int32(b.MaxBridges) {
		b.bridges.Add(-1)
		return false
	}
	return true
}

// ReleaseBridge returns a session slot.
func (b *Binding) ReleaseBridge() { b.bridges.Add(-1) }

// Bridges reports the current number of live end-user sessions.
func (b *Binding) Bridges() int32 { return b.bridges.Load() }

// Created returns the registration time.
func (b *Binding) Created() time.Time {
	t, _ := b.CreatedAt.Load().(time.Time)
	return t
}

// Registry is the in-memory binding table. All lookups the relay performs are
// read-mostly; owner-IP scans serve the JSON endpoints (ARCHITECTURE §4.4).
type Registry struct {
	mu      sync.RWMutex
	byAlias map[string]*Binding
}

func New() *Registry {
	return &Registry{byAlias: map[string]*Binding{}}
}

// Bind registers alias → owner with the requested listen address.
func (r *Registry) Bind(alias string, owner *ssh.ServerConn, ownerIP, listenAddr string, virtualPort, maxBridges int) (*Binding, error) {
	alias = NormalizeAlias(alias)
	if !ValidBindingAlias(alias) {
		return nil, fmt.Errorf("%w: %q", ErrAliasInvalid, alias)
	}
	if alias == "json" {
		return nil, fmt.Errorf("%w: %q", ErrAliasReserved, alias)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byAlias[alias]; ok {
		return nil, fmt.Errorf("%w: %q", ErrAliasInUse, alias)
	}
	count := 0
	for _, b := range r.byAlias {
		if b.Owner == owner {
			count++
		}
	}
	if count >= MaxBindingsPerConn {
		return nil, ErrTooMany
	}
	if maxBridges < 1 {
		maxBridges = 10
	}
	b := &Binding{
		Alias:       alias,
		Owner:       owner,
		OwnerIP:     ownerIP,
		ListenAddr:  listenAddr,
		VirtualPort: uint32(virtualPort),
		MaxBridges:  maxBridges,
	}
	b.CreatedAt.Store(time.Now())
	r.byAlias[alias] = b
	return b, nil
}

// Lookup returns the live binding for alias.
func (r *Registry) Lookup(alias string) (*Binding, bool) {
	alias = NormalizeAlias(alias)
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, ok := r.byAlias[alias]
	return b, ok
}

// ReleaseOne unbinds alias when owned by conn; reports whether it was freed.
func (r *Registry) ReleaseOne(alias string, conn *ssh.ServerConn) bool {
	alias = NormalizeAlias(alias)
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.byAlias[alias]
	if !ok || b.Owner != conn {
		return false
	}
	delete(r.byAlias, alias)
	return true
}

// ReleaseByOwner unbinds everything owned by conn; returns the freed aliases.
func (r *Registry) ReleaseByOwner(conn *ssh.ServerConn) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var freed []string
	for alias, b := range r.byAlias {
		if b.Owner == conn {
			delete(r.byAlias, alias)
			freed = append(freed, alias)
		}
	}
	return freed
}

// ByOwnerIP lists bindings registered from ip (JSON endpoints).
func (r *Registry) ByOwnerIP(ip string) []*Binding {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*Binding
	for _, b := range r.byAlias {
		if b.OwnerIP == ip {
			out = append(out, b)
		}
	}
	return out
}

// Count returns the number of live bindings (tests/observability).
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byAlias)
}

const crockfordAlphabet = "0123456789abcdefghjkmnpqrstvwxyz"

// GenerateAlias returns a fresh deviceID: "d-" + 10 Crockford base32 chars
// (~50 bits of entropy, no I/L/O/U confusables).
func GenerateAlias() string {
	buf := make([]byte, 10)
	max := big.NewInt(int64(len(crockfordAlphabet)))
	for i := range buf {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(fmt.Sprintf("crypto/rand failure: %v", err)) // unreachable in practice
		}
		buf[i] = crockfordAlphabet[n.Int64()]
	}
	return GeneratedPrefix + string(buf)
}

// NormalizeAlias lowercases and trims an alias coming from user input.
func NormalizeAlias(alias string) string { return strings.ToLower(strings.TrimSpace(alias)) }

// ValidAlias enforces the CUSTOM alias grammar: 3–63 chars, lowercase
// alphanumerics and inner dashes, no generated "d-" prefix, not "json".
// Used when a device registers a named binding.
func ValidAlias(alias string) bool {
	if alias == "" || alias == "json" || strings.HasPrefix(alias, GeneratedPrefix) {
		return false
	}
	return validAliasCharset(alias)
}

// ValidBindingAlias checks charset-only validity for any binding (generated
// deviceIDs live in the "d-" namespace and must be accepted).
func ValidBindingAlias(alias string) bool {
	if alias == "" || alias == "json" {
		return false
	}
	return validAliasCharset(alias)
}

func validAliasCharset(alias string) bool {
	if len(alias) < 3 || len(alias) > 63 {
		return false
	}
	for i, c := range alias {
		switch {
		case c >= 'a' && c <= 'z' || c >= '0' && c <= '9':
		case c == '-' && i > 0 && i < len(alias)-1:
		// Inner underscores: Android/Termux usernames (u0_a96, …) make
		// natural tunnel names, and `-R <name>:0:…` must accept them.
		case c == '_' && i > 0 && i < len(alias)-1:
		default:
			return false
		}
	}
	return true
}

// NormalizeRequestedAddr maps the -R bind address to an alias choice:
// empty/"localhost"/"0.0.0.0"/"*"/"0" means "generate one", anything else is
// used as a custom alias.
func NormalizeRequestedAddr(addr string) (alias string, generated bool, err error) {
	switch strings.ToLower(strings.TrimSpace(addr)) {
	case "", "localhost", "0.0.0.0", "*", "0":
		return GenerateAlias(), true, nil
	default:
		a := NormalizeAlias(addr)
		if !ValidAlias(a) {
			return "", false, fmt.Errorf("%w: %q", ErrAliasInvalid, addr)
		}
		return a, false, nil
	}
}
