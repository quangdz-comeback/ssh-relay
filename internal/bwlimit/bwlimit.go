// Package bwlimit parses the --bw-limit grammar shared by the CLI flag and
// policy.json's bw_limit field: "unlimited" or byte sizes with optional
// K/M/G (1024-based) suffixes, interpreted as bytes per second.
package bwlimit

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Unlimited is the sentinel returned for "unlimited" (and the zero value).
const Unlimited = 0

var pattern = regexp.MustCompile(`^(?i)(unlimited|[0-9]+[kmg]?)$`)

// Parse converts a limit string into bytes per second.
// "unlimited" (case-insensitive) or "" yields 0.
func Parse(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "unlimited") {
		return Unlimited, nil
	}
	if !pattern.MatchString(s) {
		return 0, fmt.Errorf("invalid value %q: want unlimited, 500, 10K, 10M, 10G", s)
	}
	mult := int64(1)
	body := s
	switch strings.ToLower(s[len(s)-1:]) {
	case "k":
		mult, body = 1024, s[:len(s)-1]
	case "m":
		mult, body = 1024*1024, s[:len(s)-1]
	case "g":
		mult, body = 1024*1024*1024, s[:len(s)-1]
	}
	n, err := strconv.ParseInt(body, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid value %q: %w", s, err)
	}
	v := n * mult
	if v <= 0 {
		return 0, fmt.Errorf("invalid value %q: must be > 0 or \"unlimited\"", s)
	}
	return v, nil
}

// Describe renders a parsed limit back to canonical form (used in logs).
func Describe(perSec int64) string {
	if perSec <= 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%dB/s", perSec)
}
