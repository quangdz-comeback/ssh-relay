// Package config parses and validates the relay CLI surface.
package config

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/quangdz/ssh-relay/internal/bwlimit"
)

const (
	DefaultListenPort    = 2222
	DefaultSessionsPerIP = 3
)

// Config is the fully parsed CLI state. Values are the raw flag values; use
// IsSet to know whether a flag was explicitly passed (explicit flags win over
// policy.json's default block — see ARCHITECTURE §6.3).
type Config struct {
	ListenIP             string
	ListenPort           int
	BWLimit              string // raw grammar, parsed by bwlimit
	AllowedSessionsPerIP int
	Fail2ban             bool
	AllowTCPForwarding   bool
	AllowSFTP            bool
	AllowSCP             bool
	AllowX11Forwarding   bool
	DataDir              string
	AdvertiseHost        string
	LogLevel             string
	PolicyFile           string
	ShowVersion          bool

	flagSet map[string]bool
}

// IsSet reports whether the named flag was explicitly passed on the command line.
func (c *Config) IsSet(name string) bool { return c.flagSet[name] }

// ListenAddr returns the host:port to bind. An empty listen IP binds all
// interfaces.
func (c *Config) ListenAddr() string {
	ip := strings.TrimSpace(c.ListenIP)
	if ip == "" || ip == "0.0.0.0" || ip == "::" {
		return fmt.Sprintf(":%d", c.ListenPort)
	}
	return net.JoinHostPort(ip, fmt.Sprint(c.ListenPort))
}

// Validate checks cross-field constraints and returns the parsed per-second
// byte limit (0 = unlimited).
func (c *Config) Validate() (bwPerSec int64, err error) {
	if c.ListenPort < 1 || c.ListenPort > 65535 {
		return 0, fmt.Errorf("--listen-port %d outside 1-65535", c.ListenPort)
	}
	if ip := strings.TrimSpace(c.ListenIP); ip != "" {
		if net.ParseIP(ip) == nil {
			return 0, fmt.Errorf("--ip %q is not a valid IP address", c.ListenIP)
		}
	}
	bwPerSec, err = bwlimit.Parse(c.BWLimit)
	if err != nil {
		return 0, fmt.Errorf("--bw-limit: %w", err)
	}
	if c.AllowedSessionsPerIP < 1 {
		return 0, fmt.Errorf("--allowed-sessions-per-ip must be >= 1")
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return 0, fmt.Errorf("--log-level must be debug|info|warn|error")
	}
	return bwPerSec, nil
}

// Parse builds a Config from args (without the program name).
func Parse(args []string) (*Config, error) {
	c := &Config{flagSet: map[string]bool{}}
	fs := flag.NewFlagSet("relay", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	fs.IntVar(&c.ListenPort, "listen-port", DefaultListenPort,
		"TCP port for the SSH listener (use 22 with CAP_NET_BIND_SERVICE)")
	fs.StringVar(&c.ListenIP, "ip", "", "listen IP (default: all interfaces)")
	fs.StringVar(&c.BWLimit, "bw-limit", "unlimited",
		"per-connection per-direction cap: unlimited, 500, 10K, 10M, 10G")
	fs.IntVar(&c.AllowedSessionsPerIP, "allowed-sessions-per-ip", DefaultSessionsPerIP,
		"max concurrent authenticated connections per source IP")
	fs.BoolVar(&c.Fail2ban, "fail2ban", true, "enable the built-in ban manager")
	fs.BoolVar(&c.AllowTCPForwarding, "allow-tcp-forwarding", true,
		"allow client TCP forwarding via -L/-D")
	fs.BoolVar(&c.AllowSFTP, "allow-sftp", true, "allow the sftp subsystem")
	fs.BoolVar(&c.AllowSCP, "allow-scp", true, "allow legacy scp exec requests")
	fs.BoolVar(&c.AllowX11Forwarding, "allow-x11-forwarding", false, "allow X11 forwarding")
	fs.StringVar(&c.DataDir, "data-dir", defaultDataDir(), "state directory (host key)")
	fs.StringVar(&c.AdvertiseHost, "advertise-host", "", "hostname printed in control output (default: os hostname)")
	fs.StringVar(&c.LogLevel, "log-level", "info", "debug|info|warn|error")
	fs.StringVar(&c.PolicyFile, "policy-file", "policy.json", "policy.json path (auto-loaded when present, hot-reloaded)")
	fs.BoolVar(&c.ShowVersion, "version", false, "print version and exit")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	fs.Visit(func(f *flag.Flag) { c.flagSet[f.Name] = true })

	if c.AdvertiseHost == "" {
		h, err := os.Hostname()
		if err != nil || h == "" {
			h = "relay"
		}
		c.AdvertiseHost = h
	}
	if _, err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func defaultDataDir() string {
	if x := os.Getenv("XDG_DATA_HOME"); x != "" {
		return filepath.Join(x, "relay")
	}
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return filepath.Join(h, ".local", "share", "relay")
	}
	return "relay-data"
}
