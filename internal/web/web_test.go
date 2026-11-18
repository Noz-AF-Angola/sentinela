package web

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/Noz-AF-Angola/sentinela/internal/auth"
	"github.com/Noz-AF-Angola/sentinela/internal/demo"
)

const pw = "correct horse battery"

func newDirectory(t *testing.T) *auth.Directory {
	t.Helper()
	h, err := auth.HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	users, err := auth.ParseUsers(strings.NewReader("admin:admin:" + h + "\nviewer:viewer:" + h + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	return auth.NewDirectory(users)
}

type client struct {
	t    *testing.T
	srv  *httptest.Server
	hc   *http.Client
	csrf string
}

func newClient(t *testing.T, opt Options) (*client, *demo.Backend) {
	t.Helper()
	b := demo.New()
	if opt.LAPI == nil && opt.Metrics == nil && opt.CSCLI == nil {
		opt.LAPI, opt.Metrics, opt.CSCLI = b, b, b
	}
	if opt.Directory == nil && opt.Proxy == nil {
		opt.Directory = newDirectory(t)
	}
	opt.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	opt.Version = "test"
	s, err := New(opt)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &client{t: t, srv: srv, hc: hc}, b
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (c *client) get(path string) (int, string, http.Header) {
	c.t.Helper()
	resp, err := c.hc.Get(c.srv.URL + path)
	if err != nil {
		c.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if m := csrfRe.FindSubmatch(b); m != nil {
		c.csrf = string(m[1])
	}
	return resp.StatusCode, string(b), resp.Header
}

func (c *client) post(path string, form url.Values, headers ...string) (int, string, http.Header) {
	c.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, c.srv.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func (c *client) login(user string) {
	c.t.Helper()
	code, _, h := c.post("/login", url.Values{"username": {user}, "password": {pw}, "next": {"/decisions"}})
	if code != http.StatusSeeOther || h.Get("Location") != "/decisions" {
		c.t.Fatalf("login %s: %d %s", user, code, h.Get("Location"))
	}
	c.get("/")
}

func TestLoginFlow(t *testing.T) {
	c, _ := newClient(t, Options{})
	code, _, h := c.get("/decisions?ip=192.0.2.1")
	if code != http.StatusSeeOther || !strings.HasPrefix(h.Get("Location"), "/login?next=") {
		t.Fatalf("anonymous: %d %s", code, h.Get("Location"))
	}
	if code, body, h := c.get("/login"); code != 200 || !strings.Contains(body, "Log in") || h.Get("Content-Security-Policy") == "" {
		t.Fatalf("login page: %d", code)
	}
	code, body, _ := c.post("/login", url.Values{"username": {"admin"}, "password": {"nope nope nope"}})
	if code != http.StatusUnauthorized || !strings.Contains(body, "Wrong user name") {
		t.Fatalf("bad password: %d", code)
	}
	code, _, h = c.post("/login", url.Values{"username": {"admin"}, "password": {pw}, "next": {"//evil.example.com"}})
	if code != http.StatusSeeOther || h.Get("Location") != "/" {
		t.Fatalf("open redirect: %d %s", code, h.Get("Location"))
	}
	if !strings.Contains(h.Get("Set-Cookie"), "HttpOnly") || !strings.Contains(h.Get("Set-Cookie"), "SameSite=Strict") {
		t.Errorf("cookie flags: %s", h.Get("Set-Cookie"))
	}
	if code, _, _ := c.get("/"); code != 200 {
		t.Fatalf("after login: %d", code)
	}
	c.post("/logout", url.Values{"csrf": {c.csrf}})
	if code, _, _ := c.get("/"); code != http.StatusSeeOther {
		t.Errorf("after logout: %d", code)
	}
}

func TestLoginThrottle(t *testing.T) {
	c, _ := newClient(t, Options{})
	for i := 0; i < 5; i++ {
		c.post("/login", url.Values{"username": {"admin"}, "password": {"wrong password"}})
	}
	code, body, _ := c.post("/login", url.Values{"username": {"admin"}, "password": {pw}})
	if code != http.StatusUnauthorized || !strings.Contains(body, "Too many") {
		t.Errorf("not throttled: %d", code)
	}
}

func TestPagesRender(t *testing.T) {
	c, _ := newClient(t, Options{})
	c.login("admin")
	pages := map[string]string{
		"/":                                  "Top scenarios",
		"/decisions":                         "203.0.113.45",
		"/decisions?capi=1&ip=198.51.100.23": "198.51.100.23",
		"/alerts":                            "crowdsecurity/ssh-bf",
		"/alerts?since=7d&limit=5":           "Alerts",
		"/alerts/1":                          "app.example.com",
		"/appsec":                            "crowdsecurity/vpatch-env-access",
		"/bouncers":                          "crowdsec-firewall-bouncer",
		"/machines":                          "agent-01",
		"/hub":                               "crowdsecurity/linux",
		"/hub?type=appsec-rules&show=all":    "CVE-2023-22515",
		"/allowlists":                        "crowdsecurity/whitelists",
		"/allowlists/office":                 "198.51.100.200",
	}
	for path, want := range pages {
		code, body, _ := c.get(path)
		if code != 200 || !strings.Contains(body, want) {
			t.Errorf("%s: %d, missing %q", path, code, want)
		}
	}
	for _, path := range []string{"/alerts/999", "/nope", "/allowlists/bad%20name"} {
		if code, _, _ := c.get(path); code < 400 {
			t.Errorf("%s: %d", path, code)
		}
	}
	if code, body, _ := c.get("/alerts?ip=not-an-ip"); code != 200 || !strings.Contains(body, "invalid IP") {
		t.Errorf("bad filter: %d", code)
	}
}

func TestDecisionLifecycle(t *testing.T) {
	c, b := newClient(t, Options{})
	c.login("admin")

	// No token: refused.
	if code, _, _ := c.post("/decisions", url.Values{"value": {"192.0.2.99"}, "duration": {"4h"}}); code != http.StatusForbidden {
		t.Fatalf("missing csrf: %d", code)
	}
	// Cross-site request: refused even with a token.
	code, _, _ := c.post("/decisions", url.Values{"csrf": {c.csrf}, "value": {"192.0.2.99"}, "duration": {"4h"}},
		"Sec-Fetch-Site", "cross-site")
	if code != http.StatusForbidden {
		t.Fatalf("cross-site: %d", code)
	}
	code, _, h := c.post("/decisions", url.Values{"csrf": {c.csrf}, "value": {"192.0.2.99"}, "duration": {"2d"},
		"type": {"ban"}, "reason": {"<script>alert(1)</script>"}})
	if code != http.StatusSeeOther || h.Get("Location") != "/decisions" {
		t.Fatalf("add: %d %s", code, h.Get("Location"))
	}
	_, body, _ := c.get("/decisions")
	if !strings.Contains(body, "Added a ban on 192.0.2.99 for 48h") || !strings.Contains(body, "192.0.2.99") {
		t.Fatal("decision or flash missing")
	}
	if strings.Contains(body, "<script>alert(1)</script>") || !strings.Contains(body, "&lt;script&gt;") {
		t.Fatal("reason not escaped")
	}
	c.post("/decisions", url.Values{"csrf": {c.csrf}, "value": {"192.0.2.999"}, "duration": {"4h"}})
	if _, body, _ := c.get("/decisions"); !strings.Contains(body, "invalid IP") {
		t.Error("invalid IP not reported")
	}

	c.post("/decisions/unban", url.Values{"csrf": {c.csrf}, "ip": {"192.0.2.99"}})
	if _, body, _ := c.get("/decisions?ip=192.0.2.99"); !strings.Contains(body, "Unblocked 192.0.2.99 (1 decision(s) removed)") {
		t.Error("unban flash missing")
	}
	c.post("/decisions/1/delete", url.Values{"csrf": {c.csrf}, "value": {"203.0.113.45"}})
	if n, _ := b.DeleteDecision(t.Context(), 1); n != 0 {
		t.Error("decision 1 still present")
	}
}

func TestHubAndAllowlists(t *testing.T) {
	c, b := newClient(t, Options{})
	c.login("admin")
	c.post("/hub/action", url.Values{"csrf": {c.csrf}, "type": {"appsec-rules"}, "action": {"install"}, "name": {"crowdsecurity/vpatch-CVE-2023-22515"}})
	if _, body, _ := c.get("/hub?type=appsec-rules"); !strings.Contains(body, "CVE-2023-22515") || !strings.Contains(body, "Done: install") {
		t.Error("install not visible")
	}
	c.post("/reload", url.Values{"csrf": {c.csrf}})
	if b.Reloads != 1 {
		t.Errorf("reloads = %d", b.Reloads)
	}
	c.post("/allowlists", url.Values{"csrf": {c.csrf}, "name": {"vpn"}, "description": {"VPN exits"}})
	c.post("/allowlists/vpn/items", url.Values{"csrf": {c.csrf}, "values": {"192.0.2.50\n198.51.100.0/24"}, "expiration": {"30d"}, "comment": {"vpn"}})
	_, body, _ := c.get("/allowlists/vpn")
	if !strings.Contains(body, "198.51.100.0/24") || !strings.Contains(body, "Added 2 value(s)") {
		t.Fatal("allowlist items missing")
	}
	c.post("/allowlists/vpn/items/remove", url.Values{"csrf": {c.csrf}, "value": {"192.0.2.50"}})
	c.post("/allowlists/vpn/delete", url.Values{"csrf": {c.csrf}})
	if _, body, _ := c.get("/allowlists"); strings.Contains(body, ">vpn<") {
		t.Error("allowlist not deleted")
	}
}

func TestViewerAndReadOnly(t *testing.T) {
	c, _ := newClient(t, Options{})
	c.login("viewer")
	_, body, _ := c.get("/decisions")
	if strings.Contains(body, "Add decision") {
		t.Error("viewer sees the add form")
	}
	if code, _, _ := c.post("/decisions", url.Values{"csrf": {c.csrf}, "value": {"192.0.2.1"}, "duration": {"4h"}}); code != http.StatusForbidden {
		t.Errorf("viewer could add: %d", code)
	}

	ro, _ := newClient(t, Options{ReadOnly: true})
	ro.login("admin")
	if code, _, _ := ro.post("/allowlists", url.Values{"csrf": {ro.csrf}, "name": {"x"}}); code != http.StatusForbidden {
		t.Errorf("read-only admin could edit: %d", code)
	}
}

func TestProxyMode(t *testing.T) {
	trusted := auth.Trusted{netip.MustParsePrefix("127.0.0.0/8")}
	c, _ := newClient(t, Options{Trusted: trusted, Proxy: &auth.ProxyIdentity{
		Trusted: trusted, UserHeader: "Remote-User", GroupHeader: "Remote-Groups", AdminGroup: "admins",
	}})
	if code, _, _ := c.get("/"); code != http.StatusUnauthorized {
		t.Fatalf("no header: %d", code)
	}
	c.hc.Transport = headerTransport{"Remote-User": "carol", "Remote-Groups": "admins"}
	code, body, _ := c.get("/decisions")
	if code != 200 || !strings.Contains(body, "carol") || !strings.Contains(body, "Add decision") {
		t.Fatalf("proxy admin: %d", code)
	}
	if code, _, _ := c.post("/decisions/unban", url.Values{"csrf": {c.csrf}, "ip": {"192.0.2.1"}}); code != http.StatusSeeOther {
		t.Errorf("proxy admin post: %d", code)
	}
	c.hc.Transport = headerTransport{"Remote-User": "dave", "Remote-Groups": "staff"}
	if _, body, _ := c.get("/decisions"); !strings.Contains(body, "dave") || strings.Contains(body, "Add decision") {
		t.Error("session not switched to the new proxy user / viewer role")
	}
	if code, _, h := c.get("/login"); code != http.StatusSeeOther || h.Get("Location") != "/" {
		t.Errorf("login page in proxy mode: %d", code)
	}
}

type headerTransport map[string]string

func (h headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, v := range h {
		r.Header.Set(k, v)
	}
	return http.DefaultTransport.RoundTrip(r)
}

func TestNotConfigured(t *testing.T) {
	c, _ := newClient(t, Options{Metrics: demo.New()})
	c.login("admin")
	for path, want := range map[string]string{
		"/decisions": "Local API is not configured", "/bouncers": "cscli access is not configured",
		"/appsec": "Requests analysed", "/hub": "cscli access is not configured",
	} {
		if _, body, _ := c.get(path); !strings.Contains(body, want) {
			t.Errorf("%s: missing %q", path, want)
		}
	}
	if code, _, _ := c.post("/decisions/unban", url.Values{"csrf": {c.csrf}, "ip": {"192.0.2.1"}}); code != http.StatusServiceUnavailable {
		t.Errorf("unban without LAPI: %d", code)
	}
}

func TestHeadersAndStatic(t *testing.T) {
	c, _ := newClient(t, Options{CookieSecure: true})
	code, _, h := c.get("/static/style.css")
	if code != 200 || h.Get("X-Frame-Options") != "DENY" || h.Get("Strict-Transport-Security") == "" {
		t.Errorf("static: %d %v", code, h)
	}
	if code, body, _ := c.get("/healthz"); code != 200 || body != "ok\n" {
		t.Errorf("healthz: %d %q", code, body)
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{
		"": "/", "/alerts?x=1": "/alerts?x=1", "//evil": "/", "https://evil": "/", "/\\evil": "/", "/a\r\nb": "/",
	} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q", in, got)
		}
	}
}

// A browser on plain HTTP sends no Sec-Fetch-Site, only Origin. The login
// must still work, and the policy must let the browser send a real Origin.
func TestLoginOverPlainHTTP(t *testing.T) {
	c, _ := newClient(t, Options{})
	_, _, h := c.get("/login")
	if p := h.Get("Referrer-Policy"); p == "no-referrer" || p == "" {
		t.Fatalf("Referrer-Policy %q makes browsers send Origin: null", p)
	}
	form := url.Values{"username": {"admin"}, "password": {pw}, "next": {"/"}}
	if code, _, _ := c.post("/login", form, "Origin", c.srv.URL); code != http.StatusSeeOther {
		t.Errorf("same-origin login without Sec-Fetch-Site: %d", code)
	}
	if code, _, _ := c.post("/login", form, "Origin", "http://192.0.2.10:8095"); code != http.StatusForbidden {
		t.Errorf("cross-origin login: %d, want 403", code)
	}
}
