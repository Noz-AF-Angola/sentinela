// Package config reads Sentinela's settings from environment variables.
// Secrets can be given through *_FILE variables (Docker secrets) so they never
// have to appear in a compose file or in `docker inspect`.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// Auth modes.
const (
	AuthLocal = "local"
	AuthProxy = "proxy"
)

// cscli modes.
const (
	CSCLINone   = "none"
	CSCLIExec   = "exec"
	CSCLIDocker = "docker"
)

// Config is the complete runtime configuration.
type Config struct {
	Listen       string
	ReadOnly     bool
	CookieSecure bool
	SessionTTL   time.Duration

	AuthMode          string
	UsersFile         string
	TrustedProxies    []netip.Prefix
	ProxyUserHeader   string
	ProxyGroupsHeader string
	ProxyAdminGroup   string
	ProxyLogoutURL    string

	LAPIURL       string
	LAPIMachineID string
	LAPIPassword  string
	LAPICAFile    string

	MetricsURL string

	CSCLIMode       string
	CSCLICommand    []string
	ReloadCommand   []string
	DockerHost      string
	DockerContainer string
}

// Getenv matches os.Getenv; tests pass a map lookup instead.
type Getenv func(string) string

func secret(get Getenv, name string) (string, error) {
	if path := get(name + "_FILE"); path != "" {
		b, err := os.ReadFile(path) //nolint:gosec // path set by the operator.
		if err != nil {
			return "", fmt.Errorf("%s_FILE: %w", name, err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	return get(name), nil
}

func boolean(get Getenv, name string, def bool) (bool, error) {
	v := strings.TrimSpace(get(name))
	if v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s: not a boolean: %q", name, v)
	}
	return b, nil
}

func or(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return strings.TrimSpace(v)
}

// Load reads and checks the configuration.
func Load(get Getenv) (*Config, error) {
	c := &Config{
		Listen:            or(get("SENTINELA_LISTEN"), "127.0.0.1:8080"),
		AuthMode:          or(get("SENTINELA_AUTH_MODE"), AuthLocal),
		UsersFile:         get("SENTINELA_USERS_FILE"),
		ProxyUserHeader:   or(get("SENTINELA_PROXY_USER_HEADER"), "Remote-User"),
		ProxyGroupsHeader: or(get("SENTINELA_PROXY_GROUPS_HEADER"), "Remote-Groups"),
		ProxyAdminGroup:   strings.TrimSpace(get("SENTINELA_PROXY_ADMIN_GROUP")),
		ProxyLogoutURL:    strings.TrimSpace(get("SENTINELA_PROXY_LOGOUT_URL")),
		LAPIURL:           strings.TrimSpace(get("SENTINELA_LAPI_URL")),
		LAPIMachineID:     strings.TrimSpace(get("SENTINELA_LAPI_MACHINE_ID")),
		LAPICAFile:        strings.TrimSpace(get("SENTINELA_LAPI_CA_FILE")),
		MetricsURL:        strings.TrimSpace(get("SENTINELA_METRICS_URL")),
		CSCLIMode:         or(get("SENTINELA_CSCLI_MODE"), CSCLINone),
		CSCLICommand:      strings.Fields(or(get("SENTINELA_CSCLI_COMMAND"), "cscli")),
		ReloadCommand:     strings.Fields(get("SENTINELA_RELOAD_COMMAND")),
		DockerHost:        or(get("SENTINELA_DOCKER_HOST"), "unix:///var/run/docker.sock"),
		DockerContainer:   or(get("SENTINELA_DOCKER_CONTAINER"), "crowdsec"),
	}
	var err error
	if c.LAPIPassword, err = secret(get, "SENTINELA_LAPI_PASSWORD"); err != nil {
		return nil, err
	}
	if c.ReadOnly, err = boolean(get, "SENTINELA_READ_ONLY", false); err != nil {
		return nil, err
	}
	if c.CookieSecure, err = boolean(get, "SENTINELA_COOKIE_SECURE", true); err != nil {
		return nil, err
	}
	c.SessionTTL = 8 * time.Hour
	if v := get("SENTINELA_SESSION_TTL"); v != "" {
		if c.SessionTTL, err = time.ParseDuration(v); err != nil || c.SessionTTL < time.Minute || c.SessionTTL > 7*24*time.Hour {
			return nil, fmt.Errorf("SENTINELA_SESSION_TTL: want a duration between 1m and 168h, got %q", v)
		}
	}
	for _, p := range strings.FieldsFunc(get("SENTINELA_TRUSTED_PROXIES"), func(r rune) bool { return r == ',' || r == ' ' }) {
		pfx, err := netip.ParsePrefix(p)
		if err != nil {
			a, aerr := netip.ParseAddr(p)
			if aerr != nil {
				return nil, fmt.Errorf("SENTINELA_TRUSTED_PROXIES: invalid network %q", p)
			}
			pfx = netip.PrefixFrom(a, a.BitLen())
		}
		c.TrustedProxies = append(c.TrustedProxies, pfx.Masked())
	}
	return c, c.check()
}

func (c *Config) check() error {
	switch c.AuthMode {
	case AuthLocal:
		if c.UsersFile == "" {
			return errors.New("SENTINELA_USERS_FILE is required with SENTINELA_AUTH_MODE=local")
		}
	case AuthProxy:
		if len(c.TrustedProxies) == 0 {
			return errors.New("SENTINELA_TRUSTED_PROXIES is required with SENTINELA_AUTH_MODE=proxy: " +
				"without it anyone could set the user header themselves")
		}
		for _, p := range c.TrustedProxies {
			if p.Bits() == 0 {
				return fmt.Errorf("SENTINELA_TRUSTED_PROXIES: %s would trust every address", p)
			}
		}
	default:
		return fmt.Errorf("SENTINELA_AUTH_MODE must be %q or %q", AuthLocal, AuthProxy)
	}
	if c.LAPIURL != "" && (c.LAPIMachineID == "" || c.LAPIPassword == "") {
		return errors.New("SENTINELA_LAPI_URL is set but SENTINELA_LAPI_MACHINE_ID or SENTINELA_LAPI_PASSWORD(_FILE) is missing")
	}
	switch c.CSCLIMode {
	case CSCLINone, CSCLIExec, CSCLIDocker:
	default:
		return fmt.Errorf("SENTINELA_CSCLI_MODE must be none, exec or docker, got %q", c.CSCLIMode)
	}
	if c.LAPIURL == "" && c.MetricsURL == "" && c.CSCLIMode == CSCLINone {
		return errors.New("nothing to manage: set SENTINELA_LAPI_URL, SENTINELA_METRICS_URL and/or SENTINELA_CSCLI_MODE")
	}
	return nil
}
