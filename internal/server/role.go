package server

import (
	"fmt"
	"strings"
)

// Role classifies an incoming SSH connection by username (ARCHITECTURE §3).
type Role int

const (
	RoleUnknown    Role = iota
	RoleDevice          // "ssh" — control connection, tunnel registration
	RoleDeviceJSON      // "ssh+json" — device role with JSON control output
	RoleStatus          // "json" — status-only JSON endpoint
	RoleClient          // [user"+"]alias — end-user session bridge
)

// String renders the role for logs.
func (r Role) String() string {
	switch r {
	case RoleDevice:
		return "device"
	case RoleDeviceJSON:
		return "device-json"
	case RoleStatus:
		return "status"
	case RoleClient:
		return "client"
	default:
		return "unknown"
	}
}

const (
	// DefaultDeviceUser is the device-side login for `alias@relay` with no
	// explicit user part.
	DefaultDeviceUser = "root"
)

// Classification is the parsed username.
type Classification struct {
	Role       Role
	DeviceUser string // device-side login (RoleClient only; default "root")
	Alias      string // lowercased, validated (RoleClient only)
}

// Classify routes the SSH username to a role. Reserved names are exact
// matches; anything else follows the [user"+"]alias grammar. Unparseable
// usernames fail auth (fail2ban counts them when credentials were involved).
func Classify(username string) (Classification, error) {
	switch username {
	case "ssh":
		return Classification{Role: RoleDevice}, nil
	case "ssh+json":
		return Classification{Role: RoleDeviceJSON}, nil
	case "json":
		return Classification{Role: RoleStatus}, nil
	case "help", "keys", "version":
		return Classification{}, fmt.Errorf("username %q is reserved", username)
	}

	if i := strings.Index(username, "+"); i >= 0 {
		user, alias := username[:i], username[i+1:]
		if !validDeviceUser(user) {
			return Classification{}, fmt.Errorf("invalid device user %q", user)
		}
		a := normalize(alias)
		if !validRoutingAlias(a) {
			return Classification{}, fmt.Errorf("invalid alias %q", alias)
		}
		return Classification{Role: RoleClient, DeviceUser: user, Alias: a}, nil
	}

	a := normalize(username)
	if !validRoutingAlias(a) {
		return Classification{}, fmt.Errorf("invalid alias %q", username)
	}
	return Classification{Role: RoleClient, DeviceUser: DefaultDeviceUser, Alias: a}, nil
}

func normalize(alias string) string { return strings.ToLower(strings.TrimSpace(alias)) }

// validDeviceUser matches a device-side login name.
func validDeviceUser(u string) bool {
	if u == "" || len(u) > 32 {
		return false
	}
	for i, c := range u {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case (c == '.' || c == '_' || c == '-') && i > 0:
		default:
			return false
		}
	}
	return true
}

// validRoutingAlias checks the alias charset for client routing. Unlike
// registry.ValidAlias (registration), generated "d-…" deviceIDs are valid
// here — that is their whole namespace; only "json" stays reserved.
func validRoutingAlias(alias string) bool {
	if alias == "json" {
		return false
	}
	if len(alias) < 3 || len(alias) > 63 {
		return false
	}
	for i, c := range alias {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' && i > 0 && i < len(alias)-1:
		default:
			return false
		}
	}
	return true
}
