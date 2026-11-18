package cscli

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type fakeRunner struct {
	calls   [][]string
	outputs map[string]string
	err     error
}

func (f *fakeRunner) Run(_ context.Context, args ...string) ([]byte, error) {
	f.calls = append(f.calls, args)
	if f.err != nil {
		return nil, f.err
	}
	return []byte(f.outputs[strings.Join(args, " ")]), nil
}

func (f *fakeRunner) last() []string { return f.calls[len(f.calls)-1] }

func TestListsDecode(t *testing.T) {
	r := &fakeRunner{outputs: map[string]string{
		"bouncers list -o json": `[{"name":"traefik","ip_address":"172.18.0.5","type":"crowdsec-bouncer-traefik","version":"v1.4","last_pull":"2026-01-01T00:00:00Z","auth_type":"api-key","revoked":false},
			{"name":"old","revoked":true}]`,
		"machines list -o json": `[{"machineId":"host-agent","ipAddress":"127.0.0.1","isValidated":true,"version":"v1.6.8","last_heartbeat":"2026-01-01T00:00:00Z"}]`,
		"hub list -a -o json": `{"collections":[{"name":"crowdsecurity/linux","status":"enabled","local_version":"0.2","description":"core linux support"}],
			"appsec-rules":[{"name":"crowdsecurity/vpatch-CVE-2017-9841","status":"enabled,update-available"},{"name":"crowdsecurity/vpatch-env-access","status":"disabled"}],
			"scenarios":[{"name":"me/custom","status":"enabled,local"}]}`,
		"allowlists list -o json":           `[{"name":"office","description":"office IPs","items":[{"value":"192.0.2.0/24","expiration":"0001-01-01T00:00:00Z"}]}]`,
		"allowlists inspect office -o json": `{"name":"office","description":"office IPs","items":[{"value":"192.0.2.0/24","comment":"hq"}]}`,
		"allowlists inspect empty -o json":  `null`,
	}}
	c := New(r, nil)
	ctx := context.Background()

	b, err := c.Bouncers(ctx)
	if err != nil || len(b) != 2 || b[0].Name != "old" || b[0].Valid || !b[1].Valid || b[1].IP != "172.18.0.5" {
		t.Errorf("bouncers = %+v %v", b, err)
	}
	m, err := c.Machines(ctx)
	if err != nil || len(m) != 1 || !m[0].Validated || m[0].ID != "host-agent" {
		t.Errorf("machines = %+v %v", m, err)
	}
	hub, err := c.HubList(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rules := hub["appsec-rules"]
	if len(rules) != 2 || !rules[0].Installed || !rules[0].UpdateAvailable || rules[1].Installed {
		t.Errorf("appsec rules = %+v", rules)
	}
	if !hub["scenarios"][0].Local || hub["collections"][0].LocalVersion != "0.2" {
		t.Errorf("hub = %+v", hub)
	}
	al, err := c.Allowlists(ctx)
	if err != nil || len(al) != 1 || al[0].Size != 1 {
		t.Errorf("allowlists = %+v %v", al, err)
	}
	one, err := c.Allowlist(ctx, "office")
	if err != nil || one.Items[0].Comment != "hq" {
		t.Errorf("allowlist = %+v %v", one, err)
	}
	if _, err := c.Allowlist(ctx, "empty"); err == nil {
		t.Error("empty allowlist output accepted")
	}
	if _, err := c.Allowlist(ctx, "-x"); err == nil {
		t.Error("bad name accepted")
	}
}

func TestMutations(t *testing.T) {
	r := &fakeRunner{outputs: map[string]string{}}
	c := New(r, nil)
	ctx := context.Background()

	if _, err := c.HubAction(ctx, "appsec-rules", "install", "crowdsecurity/vpatch-env-access"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.last(), []string{"appsec-rules", "install", "crowdsecurity/vpatch-env-access"}) {
		t.Errorf("args = %v", r.last())
	}
	for _, bad := range [][3]string{
		{"bouncers", "install", "x"}, {"collections", "delete", "x"}, {"collections", "install", "--force"},
	} {
		if _, err := c.HubAction(ctx, bad[0], bad[1], bad[2]); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	if err := c.CreateAllowlist(ctx, "office", "-rf"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.last(), []string{"allowlists", "create", "office", "--description=-rf"}) {
		t.Errorf("args = %v", r.last())
	}
	if err := c.AllowlistAdd(ctx, "office", []string{"192.0.2.7", "198.51.100.9/24"}, "30d", "vpn exit"); err != nil {
		t.Fatal(err)
	}
	want := []string{"allowlists", "add", "office", "192.0.2.7", "198.51.100.0/24", "--expiration=30d", "--comment=vpn exit"}
	if !reflect.DeepEqual(r.last(), want) {
		t.Errorf("args = %v", r.last())
	}
	if err := c.AllowlistAdd(ctx, "office", []string{"--all"}, "", ""); err == nil {
		t.Error("flag accepted as value")
	}
	if err := c.AllowlistRemove(ctx, "office", "192.0.2.7"); err != nil || r.last()[3] != "192.0.2.7" {
		t.Errorf("remove: %v %v", r.last(), err)
	}
	if err := c.DeleteAllowlist(ctx, "office"); err != nil {
		t.Fatal(err)
	}
	if err := c.HubUpdate(ctx); err != nil || r.last()[0] != "hub" {
		t.Errorf("hub update: %v", err)
	}
	if c.CanReload() || c.Reload(ctx) == nil {
		t.Error("reload should be unavailable")
	}
	r.err = errors.New("boom")
	if _, err := c.Bouncers(ctx); err == nil {
		t.Error("runner error swallowed")
	}
}

func TestExecRunner(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-cscli")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nif [ \"$2\" = fail ]; then echo 'level=fatal msg=nope' >&2; exit 3; fi\necho \"$@\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	r := ExecRunner{Command: []string{script, "--config=/x"}}
	out, err := r.Run(context.Background(), "bouncers", "list", "a b;c")
	if err != nil || strings.TrimSpace(string(out)) != "--config=/x bouncers list a b;c" {
		t.Errorf("out = %q %v", out, err)
	}
	_, err = r.Run(context.Background(), "fail")
	if err == nil || !strings.Contains(err.Error(), "nope") {
		t.Errorf("err = %v", err)
	}
	if err := (ExecReloader{Command: []string{script}}).Reload(context.Background()); err != nil {
		t.Error(err)
	}
	if _, err := (ExecRunner{}).Run(context.Background()); err == nil {
		t.Error("empty command accepted")
	}
}

func frame(stream byte, s string) []byte {
	h := make([]byte, 8)
	h[0] = stream
	binary.BigEndian.PutUint32(h[4:], uint32(len(s)))
	return append(h, s...)
}

func TestDockerRunner(t *testing.T) {
	var gotCmd []string
	var signal string
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1.41/containers/crowdsec/exec", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Cmd []string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotCmd = body.Cmd
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"Id":"abc"}`))
	})
	mux.HandleFunc("POST /v1.41/exec/abc/start", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Join([][]byte{frame(1, `[{"name":`), frame(2, "warn"), frame(1, `"traefik"}]`)}, nil))
	})
	mux.HandleFunc("GET /v1.41/exec/abc/json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ExitCode":0}`))
	})
	mux.HandleFunc("POST /v1.41/containers/crowdsec/kill", func(w http.ResponseWriter, r *http.Request) {
		signal = r.URL.Query().Get("signal")
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d, err := NewDocker(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c := New(DockerRunner{Docker: d, Container: "crowdsec"}, DockerReloader{Docker: d, Container: "crowdsec"})
	b, err := c.Bouncers(context.Background())
	if err != nil || len(b) != 1 || b[0].Name != "traefik" {
		t.Fatalf("bouncers = %+v %v", b, err)
	}
	if !reflect.DeepEqual(gotCmd, []string{"cscli", "bouncers", "list", "-o", "json"}) {
		t.Errorf("cmd = %v", gotCmd)
	}
	if err := c.Reload(context.Background()); err != nil || signal != "SIGHUP" {
		t.Errorf("reload: %v signal=%q", err, signal)
	}
	if _, _, _, err := d.Exec(context.Background(), "bad/name", nil); err == nil {
		t.Error("bad container name accepted")
	}
	if _, err := NewDocker("ftp://x"); err == nil {
		t.Error("bad scheme accepted")
	}
	var o, e bytes.Buffer
	if err := demux(bytes.NewReader(frame(1, "abc")[:6]), &o, &e); err == nil {
		t.Error("truncated header accepted")
	}
}
