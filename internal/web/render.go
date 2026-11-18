package web

import (
	"bytes"
	"fmt"
	"html/template"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/Noz-AF-Angola/sentinela/internal/auth"
)

type features struct {
	LAPI, Metrics, CSCLI, Reload bool
}

type pageData struct {
	Title    string
	Active   string
	User     string
	Role     string
	CanEdit  bool
	Proxy    bool
	CSRF     string
	Flashes  []auth.Flash
	Features features
	Version  string
	Banner   string
	Data     any
}

func (s *Server) page(sess *auth.Session, title, active string, data any) *pageData {
	p := &pageData{
		Title: title, Active: active, Data: data, Version: s.opt.Version, Banner: s.opt.Banner,
		Features: features{
			LAPI: s.opt.LAPI != nil, Metrics: s.opt.Metrics != nil, CSCLI: s.opt.CSCLI != nil,
			Reload: s.opt.CSCLI != nil && s.opt.CSCLI.CanReload(),
		},
	}
	if sess != nil {
		p.User, p.Role, p.CSRF, p.Proxy = sess.User, string(sess.Role), sess.CSRF, sess.Proxy
		p.CanEdit = s.canEdit(sess)
		p.Flashes = s.sessions.PopFlashes(sess.ID)
	}
	return p
}

func (s *Server) render(w http.ResponseWriter, status int, name string, p *pageData) {
	t, ok := s.pages[name]
	if !ok {
		http.Error(w, "unknown page", http.StatusInternalServerError)
		return
	}
	if p.Version == "" {
		p.Version = s.opt.Version
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", p); err != nil {
		s.log.Error("render", "page", name, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) errorPage(w http.ResponseWriter, _ *http.Request, sess *auth.Session, status int, msg string) {
	s.render(w, status, "error", s.page(sess, http.StatusText(status), "", map[string]any{
		"Status": status, "Message": msg,
	}))
}

func (s *Server) flash(sess *auth.Session, kind, format string, args ...any) {
	s.sessions.AddFlash(sess.ID, kind, fmt.Sprintf(format, args...))
}

// back redirects to a local page after a POST (post/redirect/get).
func back(w http.ResponseWriter, r *http.Request, fallback string) {
	to := r.PostFormValue("back")
	if to == "" || !strings.HasPrefix(to, "/") || strings.HasPrefix(to, "//") || strings.ContainsAny(to, "\\\r\n") {
		to = fallback
	}
	http.Redirect(w, r, to, http.StatusSeeOther) //nolint:gosec // local paths only, checked above.
}

func parseTime(v string) (time.Time, bool) {
	if v == "" || strings.HasPrefix(v, "0001-01-01") {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999 -0700 MST", "2006-01-02 15:04:05 -0700 MST"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func humanDuration(d time.Duration) string {
	neg := d < 0
	if neg {
		d = -d
	}
	var out string
	switch {
	case d < time.Minute:
		out = fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		out = fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		out = fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		out = fmt.Sprintf("%dd", int(d.Hours()/24))
	}
	if neg {
		return "-" + out
	}
	return out
}

var funcs = template.FuncMap{
	// ago renders a timestamp as "5m ago"; the full date goes in a title.
	"ago": func(v string) string {
		t, ok := parseTime(v)
		if !ok {
			return "—"
		}
		return humanDuration(time.Since(t)) + " ago"
	},
	"when": func(v string) string {
		t, ok := parseTime(v)
		if !ok {
			return ""
		}
		return t.UTC().Format("2006-01-02 15:04:05 UTC")
	},
	"left": func(v string) string {
		t, ok := parseTime(v)
		if !ok {
			return "—"
		}
		return humanDuration(time.Until(t))
	},
	"num": func(f float64) string {
		switch {
		case f >= 1e6:
			return fmt.Sprintf("%.1fM", f/1e6)
		case f >= 1e4:
			return fmt.Sprintf("%.1fk", f/1e3)
		}
		return fmt.Sprintf("%.0f", f)
	},
	"pct": func(f float64) string {
		if math.IsNaN(f) {
			return "0%"
		}
		return fmt.Sprintf("%.1f%%", f)
	},
	"bar": func(v, max float64) int {
		if max <= 0 {
			return 0
		}
		return int(math.Round(100 * v / max))
	},
	"eq":    func(a, b any) bool { return fmt.Sprint(a) == fmt.Sprint(b) },
	"join":  strings.Join,
	"lower": strings.ToLower,
	"short": func(s string, n int) string {
		r := []rune(s)
		if len(r) <= n {
			return s
		}
		return string(r[:n-1]) + "…"
	},
}
