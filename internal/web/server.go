// Package web serves Sentinela's pages. Everything is rendered on the server
// with html/template; the only JavaScript is a small confirm() helper.
package web

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Noz-AF-Angola/sentinela/internal/auth"
	"github.com/Noz-AF-Angola/sentinela/internal/cscli"
	"github.com/Noz-AF-Angola/sentinela/internal/lapi"
	"github.com/Noz-AF-Angola/sentinela/internal/metrics"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// LAPI is the part of the LAPI client the UI uses.
type LAPI interface {
	Alerts(ctx context.Context, f lapi.AlertFilter) ([]lapi.Alert, error)
	Alert(ctx context.Context, id int64) (*lapi.Alert, error)
	AddDecision(ctx context.Context, d lapi.NewDecision) error
	DeleteDecision(ctx context.Context, id int64) (int, error)
	DeleteDecisionsByIP(ctx context.Context, ip string) (int, error)
}

// Metrics fetches the Prometheus summary.
type Metrics interface {
	Fetch(ctx context.Context) (*metrics.Summary, error)
}

// CSCLI is the part of the cscli wrapper the UI uses.
type CSCLI interface {
	Bouncers(ctx context.Context) ([]cscli.Bouncer, error)
	Machines(ctx context.Context) ([]cscli.Machine, error)
	HubList(ctx context.Context) (cscli.Hub, error)
	HubAction(ctx context.Context, typ, action, name string) (string, error)
	HubUpdate(ctx context.Context) error
	Allowlists(ctx context.Context) ([]cscli.Allowlist, error)
	Allowlist(ctx context.Context, name string) (*cscli.Allowlist, error)
	CreateAllowlist(ctx context.Context, name, description string) error
	DeleteAllowlist(ctx context.Context, name string) error
	AllowlistAdd(ctx context.Context, name string, values []string, expiration, comment string) error
	AllowlistRemove(ctx context.Context, name, value string) error
	CanReload() bool
	Reload(ctx context.Context) error
}

// Options wires the server together. LAPI, Metrics and CSCLI may each be nil;
// the matching pages then explain what to configure.
type Options struct {
	LAPI    LAPI
	Metrics Metrics
	CSCLI   CSCLI

	Directory *auth.Directory     // local login; nil in proxy mode
	Proxy     *auth.ProxyIdentity // proxy mode; nil in local mode
	Trusted   auth.Trusted        // for client IPs in logs and rate limits
	LogoutURL string

	ReadOnly     bool
	CookieSecure bool
	SessionTTL   time.Duration
	Version      string
	Logger       *slog.Logger
	Banner       string // shown on every page (used by demo mode)
}

// Server is the HTTP handler.
type Server struct {
	opt      Options
	sessions *auth.Store
	ipLimit  *auth.Limiter
	usrLimit *auth.Limiter
	pages    map[string]*template.Template
	log      *slog.Logger
	mux      *http.ServeMux
	cookie   string
}

// New builds the server.
func New(opt Options) (*Server, error) {
	if opt.Directory == nil && opt.Proxy == nil {
		return nil, fmt.Errorf("an authentication method is required")
	}
	if opt.SessionTTL == 0 {
		opt.SessionTTL = 8 * time.Hour
	}
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	s := &Server{
		opt:      opt,
		sessions: auth.NewStore(opt.SessionTTL),
		ipLimit:  auth.NewLimiter(10, 15*time.Minute),
		usrLimit: auth.NewLimiter(5, 15*time.Minute),
		log:      opt.Logger,
		cookie:   "sentinela_session",
	}
	if opt.CookieSecure {
		// The __Host- prefix makes browsers refuse the cookie unless it is
		// Secure, has Path=/ and no Domain: it cannot be set by a sibling host.
		s.cookie = "__Host-sentinela_session"
	}
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	s.routes()
	return s, nil
}

func (s *Server) parseTemplates() error {
	s.pages = map[string]*template.Template{}
	entries, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := strings.TrimSuffix(strings.TrimPrefix(e, "templates/"), ".html")
		if name == "layout" {
			continue
		}
		t, err := template.New(name).Funcs(funcs).ParseFS(templateFS, "templates/layout.html", e)
		if err != nil {
			return fmt.Errorf("template %s: %w", name, err)
		}
		s.pages[name] = t
	}
	return nil
}

func (s *Server) routes() {
	m := http.NewServeMux()
	static, _ := fs.Sub(staticFS, "static")
	m.Handle("GET /static/", http.StripPrefix("/static/", cacheStatic(http.FileServerFS(static))))
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	m.HandleFunc("GET /login", s.loginPage)
	m.HandleFunc("POST /login", s.loginSubmit)
	m.Handle("POST /logout", s.authed(s.logout))

	view := func(p string, h handler) { m.Handle(p, s.authed(h)) }
	edit := func(p string, h handler) { m.Handle(p, s.authed(s.admin(h))) }

	view("GET /{$}", s.dashboard)
	view("GET /decisions", s.decisions)
	edit("POST /decisions", s.addDecision)
	edit("POST /decisions/unban", s.unban)
	edit("POST /decisions/{id}/delete", s.deleteDecision)
	view("GET /alerts", s.alerts)
	view("GET /alerts/{id}", s.alert)
	view("GET /appsec", s.appsec)
	view("GET /bouncers", s.bouncers)
	view("GET /machines", s.machines)
	view("GET /hub", s.hub)
	edit("POST /hub/action", s.hubAction)
	edit("POST /hub/update", s.hubUpdate)
	edit("POST /reload", s.reload)
	view("GET /allowlists", s.allowlists)
	edit("POST /allowlists", s.createAllowlist)
	view("GET /allowlists/{name}", s.allowlist)
	edit("POST /allowlists/{name}/delete", s.deleteAllowlist)
	edit("POST /allowlists/{name}/items", s.allowlistAdd)
	edit("POST /allowlists/{name}/items/remove", s.allowlistRemove)

	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.errorPage(w, r, nil, http.StatusNotFound, "Page not found.")
	})
	s.mux = m
}

func cacheStatic(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		h.ServeHTTP(w, r)
	})
}

// ServeHTTP adds the security headers and cross-origin protection to every
// response, then dispatches.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self' data:; "+
		"form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	if s.opt.CookieSecure {
		h.Set("Strict-Transport-Security", "max-age=31536000")
	}
	defer func() {
		if v := recover(); v != nil {
			s.log.Error("panic", "path", r.URL.Path, "error", v)
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	}()
	csrf.Handler(s.mux).ServeHTTP(w, r)
}

// csrf rejects cross-site unsafe requests using Sec-Fetch-Site / Origin.
// Forms additionally carry a per-session token (see checkToken).
var csrf = http.NewCrossOriginProtection()

// audit records every change made through the UI.
func (s *Server) audit(r *http.Request, sess *auth.Session, action string, attrs ...any) {
	base := []any{"user", sess.User, "client_ip", s.opt.Trusted.ClientIP(r), "action", action}
	s.log.Info("audit", append(base, attrs...)...)
}
