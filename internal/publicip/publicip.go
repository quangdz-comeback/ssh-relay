// Package publicip resolves the relay's public IP for display in the SSH
// commands printed to device operators (default display host, PLAN §3).
package publicip

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// endpoints are tried in order; the first valid IPv4/IPv6 answer wins.
var endpoints = []string{
	"https://ifconfig.me/ip",
	"https://api.ipify.org",
}

// Fetch queries the public IP. ctx bounds every attempt; the http client is
// created with a hard per-request timeout.
func Fetch(ctx context.Context) (string, error) {
	hc := &http.Client{Timeout: 4 * time.Second}
	var lastErr error
	for _, endpoint := range endpoints {
		ip, err := fetchOne(ctx, hc, endpoint)
		if err == nil {
			return ip, nil
		}
		lastErr = err
	}
	return "", fmt.Errorf("public IP lookup failed: %w", lastErr)
}

func fetchOne(ctx context.Context, hc *http.Client, endpoint string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	// ifconfig.me serves plain text for non-browser user agents.
	req.Header.Set("User-Agent", "ssh-relay (+https://github.com/quangdz-comeback/ssh-relay)")
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: http %d", endpoint, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(body))
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("%s: %q is not an IP", endpoint, ip)
	}
	return ip, nil
}
