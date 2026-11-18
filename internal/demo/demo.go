// Package demo provides in-memory stand-ins for the LAPI, the metrics
// endpoint and cscli. `sentinela demo` uses them to show the interface without
// a CrowdSec installation, and the web tests use them as fakes. All addresses
// are from the documentation ranges (RFC 5737 / RFC 3849).
package demo

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Noz-AF-Angola/sentinela/internal/cscli"
	"github.com/Noz-AF-Angola/sentinela/internal/lapi"
	"github.com/Noz-AF-Angola/sentinela/internal/metrics"
	"github.com/Noz-AF-Angola/sentinela/internal/validate"
)

// Backend implements the LAPI, Metrics and CSCLI interfaces of package web.
type Backend struct {
	mu         sync.Mutex
	alerts     []lapi.Alert
	nextAlert  int64
	nextDec    int64
	hub        cscli.Hub
	allowlists map[string]*cscli.Allowlist
	Reloads    int
	now        func() time.Time
}

// New returns a backend filled with plausible sample data.
func New() *Backend {
	b := &Backend{nextAlert: 1, nextDec: 1, allowlists: map[string]*cscli.Allowlist{}, now: time.Now}
	now := b.now()
	type seed struct {
		ip, cn, as, scenario string
		ago                  time.Duration
		events               int64
		ban                  bool
	}
	seeds := []seed{
		{"203.0.113.45", "NL", "EXAMPLE-HOSTING", "crowdsecurity/http-probing", 12 * time.Minute, 11, true},
		{"198.51.100.23", "US", "EXAMPLE-CLOUD", "crowdsecurity/vpatch-CVE-2017-9841", 25 * time.Minute, 1, true},
		{"192.0.2.77", "DE", "EXAMPLE-TRANSIT", "crowdsecurity/ssh-bf", 40 * time.Minute, 6, true},
		{"203.0.113.9", "CN", "EXAMPLE-NET", "crowdsecurity/http-sensitive-files", 2 * time.Hour, 5, true},
		{"198.51.100.140", "BR", "EXAMPLE-ISP", "crowdsecurity/appsec-vpatch", 3 * time.Hour, 3, true},
		{"192.0.2.201", "FR", "EXAMPLE-DC", "crowdsecurity/http-crawl-non_statics", 5 * time.Hour, 40, false},
		{"203.0.113.88", "RU", "EXAMPLE-VPS", "crowdsecurity/vpatch-env-access", 7 * time.Hour, 1, true},
		{"198.51.100.61", "US", "EXAMPLE-CLOUD", "crowdsecurity/http-probing", 9 * time.Hour, 12, true},
		{"192.0.2.33", "IN", "EXAMPLE-MOBILE", "crowdsecurity/ssh-slow-bf", 15 * time.Hour, 10, true},
		{"203.0.113.150", "SG", "EXAMPLE-HOSTING", "crowdsecurity/http-bad-user-agent", 20 * time.Hour, 2, false},
	}
	for _, s := range seeds {
		created := now.Add(-s.ago)
		a := lapi.Alert{
			ID: b.nextAlert, MachineID: "agent-01", Scenario: s.scenario, ScenarioVersion: "0.3",
			Message:     fmt.Sprintf("Ip %s performed '%s' (%d events over 30s)", s.ip, s.scenario, s.events),
			EventsCount: s.events, CreatedAt: created.UTC().Format(time.RFC3339),
			StartAt: created.Add(-30 * time.Second).UTC().Format(time.RFC3339), StopAt: created.UTC().Format(time.RFC3339),
			Source: &lapi.Source{Scope: "Ip", Value: s.ip, IP: s.ip, Cn: s.cn, AsName: s.as, AsNumber: "64500"},
			Meta: []lapi.Meta{
				{Key: "target_fqdn", Value: `["app.example.com"]`},
				{Key: "uri", Value: `["/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php","/.env"]`},
			},
			Events: []lapi.Event{{Timestamp: created.UTC().Format(time.RFC3339), Meta: []lapi.Meta{
				{Key: "source_ip", Value: s.ip}, {Key: "http_verb", Value: "GET"},
				{Key: "http_path", Value: "/.env"}, {Key: "http_status", Value: "403"},
				{Key: "target_fqdn", Value: "app.example.com"},
			}}},
			Remediation: s.ban,
		}
		b.nextAlert++
		if s.ban {
			a.Decisions = []lapi.Decision{{
				ID: b.nextDec, Origin: "crowdsec", Type: "ban", Scope: "Ip", Value: s.ip,
				Duration: "4h0m0s", Until: created.Add(4 * time.Hour).UTC().Format(time.RFC3339), Scenario: s.scenario,
			}}
			b.nextDec++
		}
		b.alerts = append(b.alerts, a)
	}
	b.hub = cscli.Hub{
		"collections": {
			{Type: "collections", Name: "crowdsecurity/linux", Status: "enabled", LocalVersion: "0.2", Installed: true, Description: "core linux support : syslog+geoip+ssh"},
			{Type: "collections", Name: "crowdsecurity/traefik", Status: "enabled", LocalVersion: "0.1", Installed: true, Description: "traefik support: parser and generic http scenarios"},
			{Type: "collections", Name: "crowdsecurity/appsec-virtual-patching", Status: "enabled,update-available", LocalVersion: "6.4", Installed: true, UpdateAvailable: true, Description: "A virtual patching collection, suitable for CrowdSec WAF"},
			{Type: "collections", Name: "crowdsecurity/appsec-generic-rules", Status: "enabled", LocalVersion: "0.3", Installed: true, Description: "AppSec rules for generic attacks"},
			{Type: "collections", Name: "crowdsecurity/nginx", Status: "disabled", Description: "nginx support : parser and generic http scenarios"},
			{Type: "collections", Name: "crowdsecurity/wordpress", Status: "disabled", Description: "wordpress : scenarios and rules for wordpress"},
		},
		"scenarios": {
			{Type: "scenarios", Name: "crowdsecurity/ssh-bf", Status: "enabled", LocalVersion: "0.3", Installed: true, Description: "Detect ssh bruteforce"},
			{Type: "scenarios", Name: "crowdsecurity/http-probing", Status: "enabled", LocalVersion: "0.4", Installed: true, Description: "Detect site scanning/probing from a single ip"},
			{Type: "scenarios", Name: "crowdsecurity/http-sensitive-files", Status: "enabled", LocalVersion: "0.3", Installed: true, Description: "Detect attempt to access to sensitive files (.log, .db ..) or folders (.git)"},
			{Type: "scenarios", Name: "crowdsecurity/appsec-vpatch", Status: "enabled", LocalVersion: "0.1", Installed: true, Description: "Identify attacks flagged by CrowdSec AppSec"},
			{Type: "scenarios", Name: "local/office-hours", Status: "enabled,local", Installed: true, Local: true, Description: "custom scenario"},
		},
		"parsers": {
			{Type: "parsers", Name: "crowdsecurity/whitelists", Status: "enabled", LocalVersion: "0.2", Installed: true, Description: "Whitelist events from private ipv4 addresses"},
			{Type: "parsers", Name: "crowdsecurity/traefik-logs", Status: "enabled", LocalVersion: "0.9", Installed: true, Description: "Parse Traefik access logs"},
		},
		"appsec-configs": {
			{Type: "appsec-configs", Name: "crowdsecurity/appsec-default", Status: "enabled", LocalVersion: "0.2", Installed: true, Description: "The default AppSec config"},
		},
		"appsec-rules": {
			{Type: "appsec-rules", Name: "crowdsecurity/vpatch-CVE-2017-9841", Status: "enabled", LocalVersion: "0.2", Installed: true, Description: "PHPUnit RCE (CVE-2017-9841)"},
			{Type: "appsec-rules", Name: "crowdsecurity/vpatch-env-access", Status: "enabled", LocalVersion: "0.3", Installed: true, Description: "Detect access to .env files"},
			{Type: "appsec-rules", Name: "crowdsecurity/vpatch-git-config", Status: "enabled,update-available", LocalVersion: "0.1", Installed: true, UpdateAvailable: true, Description: "Detect access to .git files"},
			{Type: "appsec-rules", Name: "crowdsecurity/vpatch-CVE-2024-4577", Status: "enabled", LocalVersion: "0.4", Installed: true, Description: "PHP-CGI argument injection (CVE-2024-4577)"},
			{Type: "appsec-rules", Name: "crowdsecurity/vpatch-CVE-2023-22515", Status: "disabled", Description: "Confluence broken access control (CVE-2023-22515)"},
		},
	}
	b.allowlists["office"] = &cscli.Allowlist{
		Name: "office", Description: "Office network and VPN exit", CreatedAt: now.Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339),
		UpdatedAt: now.Add(-48 * time.Hour).UTC().Format(time.RFC3339),
		Items: []cscli.AllowlistItem{
			{Value: "192.0.2.0/28", Comment: "office", CreatedAt: now.Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339)},
			{Value: "198.51.100.200", Comment: "contractor, temporary", Expiration: now.Add(5 * 24 * time.Hour).UTC().Format(time.RFC3339), CreatedAt: now.Add(-48 * time.Hour).UTC().Format(time.RFC3339)},
		},
	}
	b.allowlists["office"].Size = len(b.allowlists["office"].Items)
	return b
}

// Alerts implements web.LAPI.
func (b *Backend) Alerts(_ context.Context, f lapi.AlertFilter) ([]lapi.Alert, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var since time.Time
	if f.Since != "" {
		d, err := time.ParseDuration(f.Since)
		if err != nil {
			return nil, err
		}
		since = b.now().Add(-d)
	}
	var out []lapi.Alert
	for i := len(b.alerts) - 1; i >= 0; i-- {
		a := b.alerts[i]
		if f.IP != "" && a.Source.Value != f.IP || f.Scenario != "" && a.Scenario != f.Scenario {
			continue
		}
		if f.ActiveDecisionsOnly && len(a.Decisions) == 0 {
			continue
		}
		if f.Origin != "" {
			match := false
			for _, d := range a.Decisions {
				match = match || d.Origin == f.Origin
			}
			if !match {
				continue
			}
		}
		if t, err := time.Parse(time.RFC3339, a.CreatedAt); err == nil && t.Before(since) {
			continue
		}
		a.Decisions = append([]lapi.Decision(nil), a.Decisions...)
		for j := range a.Decisions {
			if until, err := time.Parse(time.RFC3339, a.Decisions[j].Until); err == nil {
				a.Decisions[j].Duration = until.Sub(b.now()).Truncate(time.Second).String()
			}
		}
		out = append(out, a)
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out, nil
}

// Alert implements web.LAPI.
func (b *Backend) Alert(_ context.Context, id int64) (*lapi.Alert, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, a := range b.alerts {
		if a.ID == id {
			cp := a
			return &cp, nil
		}
	}
	return nil, &lapi.APIError{Status: 404, Message: "object not found"}
}

// AddDecision implements web.LAPI.
func (b *Backend) AddDecision(_ context.Context, d lapi.NewDecision) error {
	dur, err := time.ParseDuration(d.Duration)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	src := &lapi.Source{Scope: d.Scope, Value: d.Value}
	if d.Scope == validate.ScopeIP {
		src.IP = d.Value
	}
	b.alerts = append(b.alerts, lapi.Alert{
		ID: b.nextAlert, Scenario: d.Reason, Message: "manual decision", CreatedAt: now.UTC().Format(time.RFC3339),
		Source: src, Remediation: true,
		Decisions: []lapi.Decision{{ID: b.nextDec, Origin: "cscli", Type: d.Type, Scope: d.Scope, Value: d.Value,
			Duration: d.Duration, Until: now.Add(dur).UTC().Format(time.RFC3339), Scenario: d.Reason}},
	})
	b.nextAlert++
	b.nextDec++
	return nil
}

// DeleteDecision implements web.LAPI.
func (b *Backend) DeleteDecision(_ context.Context, id int64) (int, error) {
	return b.deleteWhere(func(d lapi.Decision) bool { return d.ID == id }), nil
}

// DeleteDecisionsByIP implements web.LAPI.
func (b *Backend) DeleteDecisionsByIP(_ context.Context, ip string) (int, error) {
	return b.deleteWhere(func(d lapi.Decision) bool { return d.Value == ip }), nil
}

func (b *Backend) deleteWhere(match func(lapi.Decision) bool) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for i := range b.alerts {
		kept := b.alerts[i].Decisions[:0]
		for _, d := range b.alerts[i].Decisions {
			if match(d) {
				n++
				continue
			}
			kept = append(kept, d)
		}
		b.alerts[i].Decisions = kept
	}
	return n
}

// Fetch implements web.Metrics.
func (b *Backend) Fetch(_ context.Context) (*metrics.Summary, error) {
	e := "127.0.0.1:7422"
	samples := []metrics.Sample{
		{Name: "cs_appsec_reqs_total", Labels: map[string]string{"appsec_engine": e}, Value: 184230},
		{Name: "cs_appsec_block_total", Labels: map[string]string{"appsec_engine": e}, Value: 1312},
		{Name: "cs_active_decisions", Labels: map[string]string{"origin": "CAPI", "reason": "http:scan"}, Value: 14987},
		{Name: "cs_active_decisions", Labels: map[string]string{"origin": "lists", "reason": "firehol_cybercrime"}, Value: 2210},
		{Name: "cs_active_decisions", Labels: map[string]string{"origin": "crowdsec", "reason": "crowdsecurity/http-probing"}, Value: 8},
	}
	for rule, hits := range map[string]float64{
		"crowdsecurity/vpatch-env-access": 611, "crowdsecurity/vpatch-git-config": 402,
		"crowdsecurity/vpatch-CVE-2017-9841": 188, "crowdsecurity/vpatch-CVE-2024-4577": 74,
		"crowdsecurity/generic-wordpress-uploads-php": 37,
	} {
		samples = append(samples, metrics.Sample{Name: "cs_appsec_rule_hits",
			Labels: map[string]string{"appsec_engine": e, "rule_name": rule, "type": "inband"}, Value: hits})
	}
	s := metrics.Summarise(samples)
	s.FetchedAt = b.now()
	return s, nil
}

// Bouncers implements web.CSCLI.
func (b *Backend) Bouncers(context.Context) ([]cscli.Bouncer, error) {
	now := b.now().UTC()
	return []cscli.Bouncer{
		{Name: "firewall", IP: "127.0.0.1", Type: "crowdsec-firewall-bouncer", Version: "v0.0.31", LastPull: now.Add(-8 * time.Second).Format(time.RFC3339), AuthType: "api-key", Valid: true},
		{Name: "traefik", IP: "172.18.0.4", Type: "crowdsec-bouncer-traefik-plugin", Version: "1.4.2", LastPull: now.Add(-50 * time.Second).Format(time.RFC3339), AuthType: "api-key", Valid: true},
	}, nil
}

// Machines implements web.CSCLI.
func (b *Backend) Machines(context.Context) ([]cscli.Machine, error) {
	return []cscli.Machine{{ID: "agent-01", IP: "127.0.0.1", Version: "v1.6.8", LastHeartbeat: b.now().Add(-20 * time.Second).UTC().Format(time.RFC3339), AuthType: "password", OS: "Ubuntu 24.04", Validated: true},
		{ID: "sentinela", IP: "172.18.0.9", Version: "", AuthType: "password", Validated: true}}, nil
}

// HubList implements web.CSCLI.
func (b *Backend) HubList(context.Context) (cscli.Hub, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := cscli.Hub{}
	for k, v := range b.hub {
		out[k] = append([]cscli.HubItem(nil), v...)
	}
	return out, nil
}

// HubAction implements web.CSCLI.
func (b *Backend) HubAction(_ context.Context, typ, action, name string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, it := range b.hub[typ] {
		if it.Name != name {
			continue
		}
		p := &b.hub[typ][i]
		switch action {
		case "install":
			p.Installed, p.Status, p.LocalVersion = true, "enabled", "0.1"
		case "remove":
			p.Installed, p.Status, p.UpdateAvailable = false, "disabled", false
		case "upgrade":
			p.UpdateAvailable, p.Status = false, "enabled"
		default:
			return "", fmt.Errorf("unknown action %q", action)
		}
		return "ok", nil
	}
	return "", fmt.Errorf("can't find '%s' in %s", name, typ)
}

// HubUpdate implements web.CSCLI.
func (b *Backend) HubUpdate(context.Context) error { return nil }

// Allowlists implements web.CSCLI.
func (b *Backend) Allowlists(context.Context) ([]cscli.Allowlist, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []cscli.Allowlist
	for _, a := range b.allowlists {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Allowlist implements web.CSCLI.
func (b *Backend) Allowlist(_ context.Context, name string) (*cscli.Allowlist, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	a, ok := b.allowlists[name]
	if !ok {
		return nil, fmt.Errorf("allowlist %s not found", name)
	}
	cp := *a
	cp.Items = append([]cscli.AllowlistItem(nil), a.Items...)
	return &cp, nil
}

// CreateAllowlist implements web.CSCLI.
func (b *Backend) CreateAllowlist(_ context.Context, name, description string) error {
	if _, err := validate.AllowlistName(name); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.allowlists[name]; ok {
		return fmt.Errorf("allowlist %s already exists", name)
	}
	now := b.now().UTC().Format(time.RFC3339)
	b.allowlists[name] = &cscli.Allowlist{Name: name, Description: description, CreatedAt: now, UpdatedAt: now}
	return nil
}

// DeleteAllowlist implements web.CSCLI.
func (b *Backend) DeleteAllowlist(_ context.Context, name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.allowlists[name]; !ok {
		return fmt.Errorf("allowlist %s not found", name)
	}
	delete(b.allowlists, name)
	return nil
}

// AllowlistAdd implements web.CSCLI.
func (b *Backend) AllowlistAdd(_ context.Context, name string, values []string, expiration, comment string) error {
	if len(values) == 0 {
		return errors.New("give between 1 and 100 values")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	a, ok := b.allowlists[name]
	if !ok {
		return fmt.Errorf("allowlist %s not found", name)
	}
	exp := ""
	if expiration != "" {
		e, err := validate.Expiration(expiration)
		if err != nil {
			return err
		}
		n, _ := strconv.Atoi(e[:len(e)-1])
		unit := map[byte]time.Duration{'s': time.Second, 'm': time.Minute, 'h': time.Hour, 'd': 24 * time.Hour}[e[len(e)-1]]
		exp = b.now().Add(time.Duration(n) * unit).UTC().Format(time.RFC3339)
	}
	for _, v := range values {
		canon, _, err := validate.Target(v)
		if err != nil {
			return err
		}
		a.Items = append(a.Items, cscli.AllowlistItem{Value: canon, Comment: comment, Expiration: exp, CreatedAt: b.now().UTC().Format(time.RFC3339)})
	}
	a.Size = len(a.Items)
	return nil
}

// AllowlistRemove implements web.CSCLI.
func (b *Backend) AllowlistRemove(_ context.Context, name, value string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	a, ok := b.allowlists[name]
	if !ok {
		return fmt.Errorf("allowlist %s not found", name)
	}
	kept := a.Items[:0]
	for _, it := range a.Items {
		if !strings.EqualFold(it.Value, value) {
			kept = append(kept, it)
		}
	}
	a.Items = kept
	a.Size = len(kept)
	return nil
}

// CanReload implements web.CSCLI.
func (b *Backend) CanReload() bool { return true }

// Reload implements web.CSCLI.
func (b *Backend) Reload(context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.Reloads++
	return nil
}
