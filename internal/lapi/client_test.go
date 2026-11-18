package lapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fakeLAPI struct {
	logins  atomic.Int32
	expired atomic.Bool
	posted  []alertPost
}

func (f *fakeLAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/watchers/login" {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["machine_id"] != "sentinela" || body["password"] != "s3cret" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"incorrect Username or Password"}`))
			return
		}
		f.logins.Add(1)
		_, _ = w.Write([]byte(`{"code":200,"expire":"` + time.Now().Add(time.Hour).Format(time.RFC3339) + `","token":"tok"}`))
		return
	}
	if r.Header.Get("Authorization") != "Bearer tok" || f.expired.Swap(false) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/v1/alerts":
		if r.URL.Query().Get("has_active_decision") != "true" || r.URL.Query().Get("include_capi") != "false" {
			_, _ = w.Write([]byte(`null`))
			return
		}
		_, _ = w.Write([]byte(`[{"id":7,"scenario":"crowdsecurity/ssh-bf","source":{"scope":"Ip","value":"192.0.2.10","cn":"FR"},
			"decisions":[{"id":42,"type":"ban","scope":"Ip","value":"192.0.2.10","origin":"crowdsec","duration":"3h59m"}]}]`))
	case r.Method == "GET" && r.URL.Path == "/v1/alerts/7":
		_, _ = w.Write([]byte(`{"id":7,"scenario":"crowdsecurity/ssh-bf","events":[{"timestamp":"t","meta":[{"key":"log_type","value":"ssh_failed-auth"}]}]}`))
	case r.Method == "POST" && r.URL.Path == "/v1/alerts":
		_ = json.NewDecoder(r.Body).Decode(&f.posted)
		_, _ = w.Write([]byte(`["8"]`))
	case r.Method == "DELETE" && r.URL.Path == "/v1/decisions/42":
		_, _ = w.Write([]byte(`{"nbDeleted":"1"}`))
	case r.Method == "DELETE" && r.URL.Path == "/v1/decisions" && r.URL.Query().Get("ip") == "192.0.2.10":
		_, _ = w.Write([]byte(`{"nbDeleted":"2"}`))
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"not found"}`))
	}
}

func TestClient(t *testing.T) {
	f := &fakeLAPI{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c, err := New(srv.URL+"/", "sentinela", "s3cret", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	alerts, err := c.Alerts(ctx, AlertFilter{ActiveDecisionsOnly: true})
	if err != nil || len(alerts) != 1 || alerts[0].Decisions[0].ID != 42 || alerts[0].Source.Cn != "FR" {
		t.Fatalf("alerts = %+v, %v", alerts, err)
	}
	empty, err := c.Alerts(ctx, AlertFilter{IncludeCAPI: true})
	if err != nil || len(empty) != 0 {
		t.Fatalf("null answer: %v %v", empty, err)
	}
	a, err := c.Alert(ctx, 7)
	if err != nil || len(a.Events) != 1 || a.Events[0].Meta[0].Value != "ssh_failed-auth" {
		t.Fatalf("alert = %+v, %v", a, err)
	}
	if f.logins.Load() != 1 {
		t.Errorf("token not reused: %d logins", f.logins.Load())
	}

	f.expired.Store(true)
	if _, err := c.Alerts(ctx, AlertFilter{}); err != nil {
		t.Fatalf("re-login after 401: %v", err)
	}
	if f.logins.Load() != 2 {
		t.Errorf("expected a second login, got %d", f.logins.Load())
	}

	err = c.AddDecision(ctx, NewDecision{Value: "198.51.100.0/24", Scope: "Range", Type: "ban", Duration: "4h", Reason: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.posted) != 1 {
		t.Fatalf("posted %d alerts", len(f.posted))
	}
	p := f.posted[0]
	if p.Decisions[0].Origin != "cscli" || p.Source.Range != "198.51.100.0/24" || p.Source.Scope != "Range" || p.Leakspeed != "0" {
		t.Errorf("posted alert = %+v", p)
	}

	if n, err := c.DeleteDecision(ctx, 42); err != nil || n != 1 {
		t.Errorf("delete = %d %v", n, err)
	}
	if n, err := c.DeleteDecisionsByIP(ctx, "192.0.2.10"); err != nil || n != 2 {
		t.Errorf("unban = %d %v", n, err)
	}
	_, err = c.DeleteDecision(ctx, 99)
	var apiErr *APIError
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("missing decision: %v", err)
	} else if ok := asAPIError(err, &apiErr); !ok || apiErr.Message != "not found" {
		t.Errorf("api error = %v", err)
	}
}

func asAPIError(err error, target **APIError) bool {
	e, ok := err.(*APIError)
	if ok {
		*target = e
	}
	return ok
}

func TestBadCredentials(t *testing.T) {
	srv := httptest.NewServer(&fakeLAPI{})
	defer srv.Close()
	c, _ := New(srv.URL, "sentinela", "wrong", nil)
	_, err := c.Alerts(context.Background(), AlertFilter{})
	if err == nil || !strings.Contains(err.Error(), "incorrect Username") {
		t.Errorf("err = %v", err)
	}
	if _, err := New("ftp://x", "a", "b", nil); err == nil {
		t.Error("bad scheme accepted")
	}
	if _, err := New("http://x", "", "b", nil); err == nil {
		t.Error("missing machine id accepted")
	}
}
