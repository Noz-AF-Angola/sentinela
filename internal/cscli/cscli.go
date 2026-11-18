package cscli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Noz-AF-Angola/sentinela/internal/validate"
)

// CSCLI wraps the cscli commands Sentinela needs. Output formats changed a
// little between CrowdSec releases, so JSON is decoded into maps and the
// fields are looked up under every name they have been known by.
type CSCLI struct {
	run    Runner
	reload Reloader
}

// New returns a CSCLI. reload may be nil when reloading is not configured.
func New(run Runner, reload Reloader) *CSCLI {
	return &CSCLI{run: run, reload: reload}
}

// CanReload reports whether a reload command is configured.
func (c *CSCLI) CanReload() bool { return c.reload != nil }

// Reload asks CrowdSec to reload.
func (c *CSCLI) Reload(ctx context.Context) error {
	if c.reload == nil {
		return errors.New("reload is not configured")
	}
	return c.reload.Reload(ctx)
}

type obj = map[string]any

func str(m obj, keys ...string) string {
	for _, k := range keys {
		switch v := m[k].(type) {
		case string:
			if v != "" {
				return v
			}
		case float64:
			return fmt.Sprintf("%g", v)
		case bool:
			return fmt.Sprintf("%t", v)
		}
	}
	return ""
}

func boolean(m obj, keys ...string) (value, found bool) {
	for _, k := range keys {
		if v, ok := m[k].(bool); ok {
			return v, true
		}
	}
	return false, false
}

func (c *CSCLI) json(ctx context.Context, out any, args ...string) error {
	raw, err := c.run.Run(ctx, append(args, "-o", "json")...)
	if err != nil {
		return err
	}
	if s := strings.TrimSpace(string(raw)); s == "" || s == "null" {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("cscli %s: unexpected output: %w", strings.Join(args, " "), err)
	}
	return nil
}

// list decodes either a JSON array or an object wrapping one.
func (c *CSCLI) list(ctx context.Context, args ...string) ([]obj, error) {
	var raw any
	if err := c.json(ctx, &raw, args...); err != nil {
		return nil, err
	}
	return asList(raw), nil
}

func asList(raw any) []obj {
	switch v := raw.(type) {
	case []any:
		out := make([]obj, 0, len(v))
		for _, e := range v {
			if m, ok := e.(obj); ok {
				out = append(out, m)
			}
		}
		return out
	case obj:
		for _, v := range v {
			if l, ok := v.([]any); ok {
				return asList(l)
			}
		}
	}
	return nil
}

// Bouncer is a remediation component registered with the LAPI.
type Bouncer struct {
	Name, IP, Type, Version, LastPull, AuthType string
	Valid                                       bool
}

// Bouncers runs `cscli bouncers list`.
func (c *CSCLI) Bouncers(ctx context.Context) ([]Bouncer, error) {
	rows, err := c.list(ctx, "bouncers", "list")
	if err != nil {
		return nil, err
	}
	out := make([]Bouncer, 0, len(rows))
	for _, r := range rows {
		b := Bouncer{
			Name: str(r, "name"), IP: str(r, "ip_address", "ipAddress"),
			Type: str(r, "type"), Version: str(r, "version"),
			LastPull: str(r, "last_pull", "lastPull"), AuthType: str(r, "auth_type", "authType"),
			Valid: true,
		}
		if revoked, ok := boolean(r, "revoked"); ok {
			b.Valid = !revoked
		} else if valid, ok := boolean(r, "valid", "isValidated"); ok {
			b.Valid = valid
		}
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Machine is a CrowdSec agent (log processor) registered with the LAPI.
type Machine struct {
	ID, IP, Version, LastHeartbeat, AuthType, OS string
	Validated                                    bool
}

// Machines runs `cscli machines list`.
func (c *CSCLI) Machines(ctx context.Context) ([]Machine, error) {
	rows, err := c.list(ctx, "machines", "list")
	if err != nil {
		return nil, err
	}
	out := make([]Machine, 0, len(rows))
	for _, r := range rows {
		m := Machine{
			ID: str(r, "machineId", "machine_id", "name"), IP: str(r, "ipAddress", "ip_address"),
			Version: str(r, "version"), LastHeartbeat: str(r, "last_heartbeat", "lastHeartbeat"),
			AuthType: str(r, "auth_type", "authType"), OS: str(r, "os"),
		}
		m.Validated, _ = boolean(r, "isValidated", "is_validated", "validated")
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// HubItem is a collection, scenario, parser, AppSec rule...
type HubItem struct {
	Type, Name, Status, LocalVersion, Description string
	Installed, UpdateAvailable, Tainted, Local    bool
}

// Hub is `cscli hub list -a` grouped by item type.
type Hub map[string][]HubItem

// HubList runs `cscli hub list -a` (installed and available items).
func (c *CSCLI) HubList(ctx context.Context) (Hub, error) {
	var raw map[string]any
	if err := c.json(ctx, &raw, "hub", "list", "-a"); err != nil {
		return nil, err
	}
	hub := Hub{}
	for _, typ := range validate.HubTypes {
		for _, r := range asList(raw[typ]) {
			it := HubItem{
				Type: typ, Name: str(r, "name"), Status: str(r, "status"),
				LocalVersion: str(r, "local_version", "localVersion"),
				Description:  str(r, "description"),
			}
			st := strings.ToLower(it.Status)
			if inst, ok := boolean(r, "installed"); ok {
				it.Installed = inst
			} else {
				it.Installed = strings.Contains(st, "enabled") || strings.Contains(st, "installed")
			}
			it.UpdateAvailable = strings.Contains(st, "update")
			it.Tainted = strings.Contains(st, "tainted")
			it.Local = strings.Contains(st, "local")
			if it.Name != "" {
				hub[typ] = append(hub[typ], it)
			}
		}
		sort.Slice(hub[typ], func(i, j int) bool { return hub[typ][i].Name < hub[typ][j].Name })
	}
	return hub, nil
}

// HubActions are the item operations exposed in the UI.
var HubActions = []string{"install", "remove", "upgrade"}

// HubAction runs `cscli <type> <action> <name>`.
func (c *CSCLI) HubAction(ctx context.Context, typ, action, name string) (string, error) {
	if !validate.IsHubType(typ) {
		return "", fmt.Errorf("unknown hub type %q", typ)
	}
	ok := false
	for _, a := range HubActions {
		ok = ok || a == action
	}
	if !ok {
		return "", fmt.Errorf("unknown hub action %q", action)
	}
	name, err := validate.HubName(name)
	if err != nil {
		return "", err
	}
	out, err := c.run.Run(ctx, typ, action, name)
	return strings.TrimSpace(string(out)), err
}

// HubUpdate runs `cscli hub update` (refreshes the index, installs nothing).
func (c *CSCLI) HubUpdate(ctx context.Context) error {
	_, err := c.run.Run(ctx, "hub", "update")
	return err
}

// AllowlistItem is one value of an allowlist.
type AllowlistItem struct {
	Value, Comment, Expiration, CreatedAt string
}

// Allowlist is a named set of IPs and ranges that never get a decision.
type Allowlist struct {
	Name, Description, CreatedAt, UpdatedAt string
	ConsoleManaged                          bool
	Size                                    int
	Items                                   []AllowlistItem
}

func toAllowlist(r obj) Allowlist {
	a := Allowlist{
		Name: str(r, "name"), Description: str(r, "description"),
		CreatedAt: str(r, "created_at", "createdAt"), UpdatedAt: str(r, "updated_at", "updatedAt"),
	}
	a.ConsoleManaged, _ = boolean(r, "console_managed", "consoleManaged", "from_console")
	for _, it := range asList(r["items"]) {
		a.Items = append(a.Items, AllowlistItem{
			Value: str(it, "value"), Comment: str(it, "comment", "description"),
			Expiration: str(it, "expiration", "expires_at", "expiresAt"),
			CreatedAt:  str(it, "created_at", "createdAt"),
		})
	}
	a.Size = len(a.Items)
	if s, ok := r["size"].(float64); ok && a.Size == 0 {
		a.Size = int(s)
	}
	return a
}

// Allowlists runs `cscli allowlists list`.
func (c *CSCLI) Allowlists(ctx context.Context) ([]Allowlist, error) {
	rows, err := c.list(ctx, "allowlists", "list")
	if err != nil {
		return nil, err
	}
	out := make([]Allowlist, 0, len(rows))
	for _, r := range rows {
		out = append(out, toAllowlist(r))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Allowlist runs `cscli allowlists inspect <name>`.
func (c *CSCLI) Allowlist(ctx context.Context, name string) (*Allowlist, error) {
	name, err := validate.AllowlistName(name)
	if err != nil {
		return nil, err
	}
	var raw any
	if err := c.json(ctx, &raw, "allowlists", "inspect", name); err != nil {
		return nil, err
	}
	m, ok := raw.(obj)
	if !ok {
		if l := asList(raw); len(l) > 0 {
			m = l[0]
		} else {
			return nil, fmt.Errorf("allowlist %q not found", name)
		}
	}
	a := toAllowlist(m)
	if a.Name == "" {
		a.Name = name
	}
	return &a, nil
}

// CreateAllowlist runs `cscli allowlists create`.
func (c *CSCLI) CreateAllowlist(ctx context.Context, name, description string) error {
	name, err := validate.AllowlistName(name)
	if err != nil {
		return err
	}
	description, err = validate.Text(description, 200)
	if err != nil {
		return err
	}
	if description == "" {
		description = "created with Sentinela"
	}
	_, err = c.run.Run(ctx, "allowlists", "create", name, "--description="+description)
	return err
}

// DeleteAllowlist runs `cscli allowlists delete`.
func (c *CSCLI) DeleteAllowlist(ctx context.Context, name string) error {
	name, err := validate.AllowlistName(name)
	if err != nil {
		return err
	}
	_, err = c.run.Run(ctx, "allowlists", "delete", name)
	return err
}

// AllowlistAdd runs `cscli allowlists add`. values must already be validated
// IPs or ranges; they are validated again here.
func (c *CSCLI) AllowlistAdd(ctx context.Context, name string, values []string, expiration, comment string) error {
	name, err := validate.AllowlistName(name)
	if err != nil {
		return err
	}
	if len(values) == 0 || len(values) > 100 {
		return errors.New("give between 1 and 100 values")
	}
	args := []string{"allowlists", "add", name}
	for _, v := range values {
		canon, _, err := validate.Target(v)
		if err != nil {
			return err
		}
		args = append(args, canon)
	}
	if expiration, err = validate.Expiration(expiration); err != nil {
		return err
	}
	if expiration != "" {
		args = append(args, "--expiration="+expiration)
	}
	if comment, err = validate.Text(comment, 200); err != nil {
		return err
	}
	if comment != "" {
		args = append(args, "--comment="+comment)
	}
	_, err = c.run.Run(ctx, args...)
	return err
}

// AllowlistRemove runs `cscli allowlists remove`.
func (c *CSCLI) AllowlistRemove(ctx context.Context, name, value string) error {
	name, err := validate.AllowlistName(name)
	if err != nil {
		return err
	}
	canon, _, err := validate.Target(value)
	if err != nil {
		return err
	}
	_, err = c.run.Run(ctx, "allowlists", "remove", name, canon)
	return err
}
