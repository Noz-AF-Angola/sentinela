// Package validate holds the input checks applied to every value that ends up
// in a LAPI request or on a cscli command line. The rule of thumb: if a value
// is not obviously harmless, reject it instead of trying to clean it.
package validate

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

var (
	durationRe      = regexp.MustCompile(`^([0-9]{1,6})(s|m|h|d)$`)
	hubNameRe       = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,127}$`)
	allowlistNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)
	decisionTypeRe  = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	containerRe     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
)

// HubTypes are the hub item kinds Sentinela lets you manage. They match the
// cscli sub-command names and the keys of `cscli hub list -o json`.
var HubTypes = []string{
	"collections", "scenarios", "parsers", "postoverflows",
	"contexts", "appsec-configs", "appsec-rules",
}

// IsHubType reports whether t is one of HubTypes.
func IsHubType(t string) bool {
	for _, h := range HubTypes {
		if h == t {
			return true
		}
	}
	return false
}

// Scope values understood by CrowdSec for IP based decisions.
const (
	ScopeIP    = "Ip"
	ScopeRange = "Range"
)

// Target parses an IP address or a CIDR range and returns its canonical form
// and the matching CrowdSec scope.
func Target(s string) (value, scope string, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", errors.New("empty IP or range")
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return "", "", fmt.Errorf("invalid CIDR range %q", s)
		}
		return p.Masked().String(), ScopeRange, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return "", "", fmt.Errorf("invalid IP address %q", s)
	}
	return a.Unmap().String(), ScopeIP, nil
}

// IP accepts a single IP address only.
func IP(s string) (string, error) {
	v, scope, err := Target(s)
	if err != nil {
		return "", err
	}
	if scope != ScopeIP {
		return "", fmt.Errorf("%q is a range, a single IP address is expected", s)
	}
	return v, nil
}

// Duration accepts values such as 30m, 4h or 7d. Days are converted to hours
// because the LAPI parses decision durations with Go's time.ParseDuration.
func Duration(s string) (string, error) {
	m := durationRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return "", fmt.Errorf("invalid duration %q (use e.g. 30m, 4h, 7d)", s)
	}
	n, _ := strconv.Atoi(m[1])
	if n == 0 {
		return "", errors.New("duration must be greater than zero")
	}
	if m[2] == "d" {
		if n > 3650 {
			return "", errors.New("duration is longer than ten years")
		}
		return strconv.Itoa(n*24) + "h", nil
	}
	return m[1] + m[2], nil
}

// Expiration is like Duration but keeps the "d" suffix, which cscli
// accepts for allowlist expirations. An empty value means "never".
func Expiration(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if !durationRe.MatchString(s) {
		return "", fmt.Errorf("invalid expiration %q (use e.g. 12h, 30d)", s)
	}
	return s, nil
}

// HubName validates a hub item name such as crowdsecurity/appsec-virtual-patching.
func HubName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !hubNameRe.MatchString(s) || strings.Contains(s, "..") {
		return "", fmt.Errorf("invalid hub item name %q", s)
	}
	return s, nil
}

// AllowlistName validates an allowlist name.
func AllowlistName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !allowlistNameRe.MatchString(s) {
		return "", fmt.Errorf("invalid allowlist name %q (letters, digits, . _ - only)", s)
	}
	return s, nil
}

// DecisionType validates a remediation type (ban, captcha, ...).
func DecisionType(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "ban", nil
	}
	if !decisionTypeRe.MatchString(s) {
		return "", fmt.Errorf("invalid decision type %q", s)
	}
	return s, nil
}

// Container validates a Docker container name.
func Container(s string) (string, error) {
	if !containerRe.MatchString(s) {
		return "", fmt.Errorf("invalid container name %q", s)
	}
	return s, nil
}

// Text checks a short free-text value (a reason, a comment, a description).
// Control characters are rejected and the length is capped.
func Text(s string, max int) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) > max {
		return "", fmt.Errorf("text is longer than %d characters", max)
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", errors.New("text contains control characters")
		}
	}
	return s, nil
}
