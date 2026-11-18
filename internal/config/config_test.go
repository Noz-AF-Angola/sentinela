package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func env(m map[string]string) Getenv {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	dir := t.TempDir()
	pw := filepath.Join(dir, "pw")
	if err := os.WriteFile(pw, []byte("lapi-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(env(map[string]string{
		"SENTINELA_USERS_FILE":         "/run/secrets/users",
		"SENTINELA_LAPI_URL":           "http://crowdsec:8080",
		"SENTINELA_LAPI_MACHINE_ID":    "sentinela",
		"SENTINELA_LAPI_PASSWORD_FILE": pw,
		"SENTINELA_CSCLI_COMMAND":      "sudo -n /usr/bin/cscli",
		"SENTINELA_TRUSTED_PROXIES":    "172.16.0.0/12, 192.0.2.1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:8080" || !c.CookieSecure || c.ReadOnly || c.LAPIPassword != "lapi-secret" {
		t.Errorf("config = %+v", c)
	}
	if strings.Join(c.CSCLICommand, "|") != "sudo|-n|/usr/bin/cscli" {
		t.Errorf("command = %v", c.CSCLICommand)
	}
	if len(c.TrustedProxies) != 2 || c.TrustedProxies[1].String() != "192.0.2.1/32" {
		t.Errorf("proxies = %v", c.TrustedProxies)
	}
}

func TestLoadErrors(t *testing.T) {
	base := map[string]string{"SENTINELA_USERS_FILE": "/u", "SENTINELA_METRICS_URL": "http://x:6060/metrics"}
	with := func(k, v string) map[string]string {
		m := map[string]string{}
		for a, b := range base {
			m[a] = b
		}
		m[k] = v
		return m
	}
	bad := []map[string]string{
		with("SENTINELA_USERS_FILE", ""),
		with("SENTINELA_AUTH_MODE", "proxy"),
		with("SENTINELA_AUTH_MODE", "none"),
		with("SENTINELA_LAPI_URL", "http://crowdsec:8080"),
		with("SENTINELA_CSCLI_MODE", "ssh"),
		with("SENTINELA_READ_ONLY", "maybe"),
		with("SENTINELA_SESSION_TTL", "10s"),
		with("SENTINELA_TRUSTED_PROXIES", "not-a-net"),
		with("SENTINELA_METRICS_URL", ""),
		with("SENTINELA_LAPI_PASSWORD_FILE", "/does/not/exist"),
	}
	for i, m := range bad {
		if _, err := Load(env(m)); err == nil {
			t.Errorf("case %d accepted: %v", i, m)
		}
	}
	m := with("SENTINELA_AUTH_MODE", "proxy")
	m["SENTINELA_TRUSTED_PROXIES"] = "0.0.0.0/0"
	if _, err := Load(env(m)); err == nil {
		t.Error("trusting 0.0.0.0/0 accepted")
	}
	m["SENTINELA_TRUSTED_PROXIES"] = "10.0.0.0/8"
	if _, err := Load(env(m)); err != nil {
		t.Errorf("proxy mode: %v", err)
	}
}
