package web

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Noz-AF-Angola/sentinela/internal/auth"
	"github.com/Noz-AF-Angola/sentinela/internal/cscli"
	"github.com/Noz-AF-Angola/sentinela/internal/lapi"
	"github.com/Noz-AF-Angola/sentinela/internal/metrics"
	"github.com/Noz-AF-Angola/sentinela/internal/validate"
)

const (
	readTimeout  = 30 * time.Second
	writeTimeout = 3 * time.Minute // hub installs can be slow
	maxRows      = 1000
)

func ctxRead(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), readTimeout)
}

func ctxWrite(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), writeTimeout)
}

// ---------------------------------------------------------------- dashboard

type decisionRow struct {
	lapi.Decision
	AlertID int64
	Country string
	ASName  string
}

func activeDecisions(alerts []lapi.Alert) []decisionRow {
	var rows []decisionRow
	for _, a := range alerts {
		for _, d := range a.Decisions {
			if strings.HasPrefix(d.Duration, "-") {
				continue // expired but not yet flushed
			}
			row := decisionRow{Decision: d, AlertID: a.ID}
			if a.Source != nil {
				row.Country, row.ASName = a.Source.Cn, a.Source.AsName
			}
			rows = append(rows, row)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].ID > rows[j].ID })
	return rows
}

func countBy(alerts []lapi.Alert, key func(lapi.Alert) string, top int) []metrics.Count {
	m := map[string]float64{}
	for _, a := range alerts {
		if k := key(a); k != "" {
			m[k]++
		}
	}
	out := make([]metrics.Count, 0, len(m))
	for k, v := range m {
		out = append(out, metrics.Count{Label: k, Value: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Value != out[j].Value {
			return out[i].Value > out[j].Value
		}
		return out[i].Label < out[j].Label
	})
	if len(out) > top {
		out = out[:top]
	}
	return out
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	ctx, cancel := ctxRead(r)
	defer cancel()
	data := map[string]any{}
	var mu sync.Mutex
	set := func(k string, v any) { mu.Lock(); data[k] = v; mu.Unlock() }
	var wg sync.WaitGroup
	if s.opt.LAPI != nil {
		wg.Add(2)
		go func() {
			defer wg.Done()
			alerts, err := s.opt.LAPI.Alerts(ctx, lapi.AlertFilter{ActiveDecisionsOnly: true, Limit: 5000})
			if err != nil {
				set("DecisionsErr", err.Error())
				return
			}
			set("ActiveDecisions", len(activeDecisions(alerts)))
		}()
		go func() {
			defer wg.Done()
			alerts, err := s.opt.LAPI.Alerts(ctx, lapi.AlertFilter{Since: "24h", Limit: 1000})
			if err != nil {
				set("AlertsErr", err.Error())
				return
			}
			set("Alerts24h", len(alerts))
			set("TopScenarios", countBy(alerts, func(a lapi.Alert) string { return a.Scenario }, 8))
			set("TopCountries", countBy(alerts, func(a lapi.Alert) string {
				if a.Source == nil {
					return ""
				}
				return a.Source.Cn
			}, 8))
			if len(alerts) > 10 {
				alerts = alerts[:10]
			}
			set("Recent", alerts)
		}()
	}
	if s.opt.Metrics != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m, err := s.opt.Metrics.Fetch(ctx)
			if err != nil {
				set("MetricsErr", err.Error())
				return
			}
			set("Metrics", m)
		}()
	}
	wg.Wait()
	s.render(w, http.StatusOK, "dashboard", s.page(sess, "Overview", "dashboard", data))
}

// ---------------------------------------------------------------- decisions

func (s *Server) decisions(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	q := r.URL.Query()
	data := map[string]any{
		"IP": q.Get("ip"), "Scenario": q.Get("scenario"), "Type": q.Get("type"),
		"Origin": q.Get("origin"), "CAPI": q.Get("capi") == "1",
	}
	if s.opt.LAPI == nil {
		s.render(w, http.StatusOK, "decisions", s.page(sess, "Decisions", "decisions", data))
		return
	}
	f := lapi.AlertFilter{ActiveDecisionsOnly: true, IncludeCAPI: q.Get("capi") == "1", Limit: 5000}
	if ip := strings.TrimSpace(q.Get("ip")); ip != "" {
		v, scope, err := validate.Target(ip)
		if err != nil {
			data["Err"] = err.Error()
		} else if scope == validate.ScopeRange {
			f.Range = v
		} else {
			f.IP = v
		}
	}
	if v, err := validate.Text(q.Get("scenario"), 200); err == nil {
		f.Scenario = v
	}
	if v := strings.TrimSpace(q.Get("type")); v != "" {
		if t, err := validate.DecisionType(v); err == nil {
			f.DecisionType = t
		}
	}
	if v, err := validate.Text(q.Get("origin"), 40); err == nil {
		f.Origin = v
	}
	if data["Err"] == nil {
		ctx, cancel := ctxRead(r)
		defer cancel()
		alerts, err := s.opt.LAPI.Alerts(ctx, f)
		if err != nil {
			data["Err"] = err.Error()
		} else {
			rows := activeDecisions(alerts)
			data["Total"] = len(rows)
			if len(rows) > maxRows {
				rows = rows[:maxRows]
			}
			data["Rows"] = rows
		}
	}
	s.render(w, http.StatusOK, "decisions", s.page(sess, "Decisions", "decisions", data))
}

func (s *Server) requireLAPI(w http.ResponseWriter, r *http.Request, sess *auth.Session) bool {
	if s.opt.LAPI == nil {
		s.errorPage(w, r, sess, http.StatusServiceUnavailable, "The Local API is not configured.")
		return false
	}
	return true
}

func (s *Server) addDecision(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	if !s.requireLAPI(w, r, sess) {
		return
	}
	value, scope, err := validate.Target(r.PostFormValue("value"))
	if err == nil {
		var d lapi.NewDecision
		d.Value, d.Scope = value, scope
		if d.Type, err = validate.DecisionType(r.PostFormValue("type")); err == nil {
			if d.Duration, err = validate.Duration(r.PostFormValue("duration")); err == nil {
				if d.Reason, err = validate.Text(r.PostFormValue("reason"), 200); err == nil {
					if d.Reason == "" {
						d.Reason = "manual " + d.Type + " from Sentinela"
					}
					ctx, cancel := ctxWrite(r)
					defer cancel()
					err = s.opt.LAPI.AddDecision(ctx, d)
					if err == nil {
						s.audit(r, sess, "decision.add", "value", d.Value, "type", d.Type, "duration", d.Duration, "reason", d.Reason)
						s.flash(sess, "ok", "Added a %s on %s for %s.", d.Type, d.Value, d.Duration)
					}
				}
			}
		}
	}
	if err != nil {
		s.flash(sess, "error", "Could not add the decision: %v", err)
	}
	back(w, r, "/decisions")
}

func (s *Server) deleteDecision(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	if !s.requireLAPI(w, r, sess) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		s.flash(sess, "error", "Invalid decision id.")
		back(w, r, "/decisions")
		return
	}
	ctx, cancel := ctxWrite(r)
	defer cancel()
	n, err := s.opt.LAPI.DeleteDecision(ctx, id)
	switch {
	case err != nil:
		s.flash(sess, "error", "Could not delete decision %d: %v", id, err)
	case n == 0:
		s.flash(sess, "info", "Decision %d was already gone.", id)
	default:
		s.audit(r, sess, "decision.delete", "id", id, "value", r.PostFormValue("value"))
		s.flash(sess, "ok", "Deleted decision %d.", id)
	}
	back(w, r, "/decisions")
}

func (s *Server) unban(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	if !s.requireLAPI(w, r, sess) {
		return
	}
	ip, err := validate.IP(r.PostFormValue("ip"))
	if err != nil {
		s.flash(sess, "error", "%v", err)
		back(w, r, "/decisions")
		return
	}
	ctx, cancel := ctxWrite(r)
	defer cancel()
	n, err := s.opt.LAPI.DeleteDecisionsByIP(ctx, ip)
	if err != nil {
		s.flash(sess, "error", "Could not unblock %s: %v", ip, err)
	} else {
		s.audit(r, sess, "decision.unban", "ip", ip, "deleted", n)
		s.flash(sess, "ok", "Unblocked %s (%d decision(s) removed).", ip, n)
	}
	back(w, r, "/decisions")
}

// ---------------------------------------------------------------- alerts

func (s *Server) alerts(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	q := r.URL.Query()
	since := q.Get("since")
	if since == "" && !q.Has("since") {
		since = "24h"
	}
	data := map[string]any{
		"IP": q.Get("ip"), "Scenario": q.Get("scenario"), "Since": since,
		"Origin": q.Get("origin"), "Limit": q.Get("limit"), "Active": q.Get("active") == "1",
	}
	if s.opt.LAPI == nil {
		s.render(w, http.StatusOK, "alerts", s.page(sess, "Alerts", "alerts", data))
		return
	}
	f := lapi.AlertFilter{Limit: 100, ActiveDecisionsOnly: q.Get("active") == "1"}
	var problems []string
	if ip := strings.TrimSpace(q.Get("ip")); ip != "" {
		if v, scope, err := validate.Target(ip); err != nil {
			problems = append(problems, err.Error())
		} else if scope == validate.ScopeRange {
			f.Range = v
		} else {
			f.IP = v
		}
	}
	if since != "" {
		if v, err := validate.Duration(since); err != nil {
			problems = append(problems, err.Error())
		} else {
			f.Since = v
		}
	}
	if v, err := validate.Text(q.Get("scenario"), 200); err == nil {
		f.Scenario = v
	}
	if v, err := validate.Text(q.Get("origin"), 40); err == nil {
		f.Origin = v
	}
	if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 && l <= maxRows {
		f.Limit = l
	}
	if len(problems) > 0 {
		data["Err"] = strings.Join(problems, "; ")
	} else {
		ctx, cancel := ctxRead(r)
		defer cancel()
		alerts, err := s.opt.LAPI.Alerts(ctx, f)
		if err != nil {
			data["Err"] = err.Error()
		}
		data["Rows"] = alerts
	}
	s.render(w, http.StatusOK, "alerts", s.page(sess, "Alerts", "alerts", data))
}

func (s *Server) alert(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	if !s.requireLAPI(w, r, sess) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		s.errorPage(w, r, sess, http.StatusNotFound, "No such alert.")
		return
	}
	ctx, cancel := ctxRead(r)
	defer cancel()
	a, err := s.opt.LAPI.Alert(ctx, id)
	if err != nil {
		s.errorPage(w, r, sess, http.StatusBadGateway, err.Error())
		return
	}
	s.render(w, http.StatusOK, "alert", s.page(sess, "Alert "+strconv.FormatInt(id, 10), "alerts", a))
}

// ---------------------------------------------------------------- appsec

func isAppSecScenario(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "appsec") || strings.Contains(n, "vpatch")
}

func (s *Server) appsec(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	ctx, cancel := ctxRead(r)
	defer cancel()
	data := map[string]any{}
	if s.opt.Metrics != nil {
		m, err := s.opt.Metrics.Fetch(ctx)
		if err != nil {
			data["MetricsErr"] = err.Error()
		} else {
			data["Metrics"] = m
			maxHits := 0.0
			for _, rs := range m.Rules {
				if rs.Hits > maxHits {
					maxHits = rs.Hits
				}
			}
			data["MaxHits"] = maxHits
		}
	}
	if s.opt.LAPI != nil {
		alerts, err := s.opt.LAPI.Alerts(ctx, lapi.AlertFilter{Since: "168h", Limit: 1000})
		if err != nil {
			data["AlertsErr"] = err.Error()
		} else {
			var mine []lapi.Alert
			for _, a := range alerts {
				if isAppSecScenario(a.Scenario) {
					mine = append(mine, a)
				}
			}
			if len(mine) > 50 {
				mine = mine[:50]
			}
			data["Alerts"] = mine
		}
	}
	s.render(w, http.StatusOK, "appsec", s.page(sess, "AppSec (WAF)", "appsec", data))
}

// ---------------------------------------------------------------- bouncers & machines

func (s *Server) bouncers(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	data := map[string]any{}
	if s.opt.CSCLI != nil {
		ctx, cancel := ctxRead(r)
		defer cancel()
		rows, err := s.opt.CSCLI.Bouncers(ctx)
		data["Rows"], data["Err"] = rows, errString(err)
	}
	s.render(w, http.StatusOK, "bouncers", s.page(sess, "Bouncers", "bouncers", data))
}

func (s *Server) machines(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	data := map[string]any{}
	if s.opt.CSCLI != nil {
		ctx, cancel := ctxRead(r)
		defer cancel()
		rows, err := s.opt.CSCLI.Machines(ctx)
		data["Rows"], data["Err"] = rows, errString(err)
	}
	s.render(w, http.StatusOK, "machines", s.page(sess, "Machines", "machines", data))
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// ---------------------------------------------------------------- hub

var hubLabels = map[string]string{
	"collections": "Collections", "scenarios": "Scenarios", "parsers": "Parsers",
	"postoverflows": "Postoverflows", "contexts": "Contexts",
	"appsec-configs": "AppSec configs", "appsec-rules": "AppSec rules (virtual patching)",
}

type hubTab struct {
	Type, Label        string
	Installed, Updates int
}

func (s *Server) hub(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	q := r.URL.Query()
	typ := q.Get("type")
	if !validate.IsHubType(typ) {
		typ = "collections"
	}
	show := q.Get("show")
	if show != "all" && show != "updates" {
		show = "installed"
	}
	search := strings.ToLower(strings.TrimSpace(q.Get("q")))
	data := map[string]any{"Type": typ, "Show": show, "Q": q.Get("q"), "Label": hubLabels[typ]}
	if s.opt.CSCLI != nil {
		ctx, cancel := ctxRead(r)
		defer cancel()
		hub, err := s.opt.CSCLI.HubList(ctx)
		if err != nil {
			data["Err"] = err.Error()
		} else {
			var tabs []hubTab
			for _, t := range validate.HubTypes {
				tab := hubTab{Type: t, Label: hubLabels[t]}
				for _, it := range hub[t] {
					if it.Installed {
						tab.Installed++
					}
					if it.UpdateAvailable {
						tab.Updates++
					}
				}
				tabs = append(tabs, tab)
			}
			var items []cscli.HubItem
			for _, it := range hub[typ] {
				if show == "installed" && !it.Installed || show == "updates" && !it.UpdateAvailable {
					continue
				}
				if search != "" && !strings.Contains(strings.ToLower(it.Name+" "+it.Description), search) {
					continue
				}
				items = append(items, it)
			}
			data["Tabs"], data["Items"], data["Total"] = tabs, items, len(hub[typ])
		}
	}
	s.render(w, http.StatusOK, "hub", s.page(sess, "Hub", "hub", data))
}

func (s *Server) requireCSCLI(w http.ResponseWriter, r *http.Request, sess *auth.Session) bool {
	if s.opt.CSCLI == nil {
		s.errorPage(w, r, sess, http.StatusServiceUnavailable, "cscli access is not configured.")
		return false
	}
	return true
}

func (s *Server) hubAction(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	if !s.requireCSCLI(w, r, sess) {
		return
	}
	typ, action, name := r.PostFormValue("type"), r.PostFormValue("action"), r.PostFormValue("name")
	ctx, cancel := ctxWrite(r)
	defer cancel()
	if _, err := s.opt.CSCLI.HubAction(ctx, typ, action, name); err != nil {
		s.flash(sess, "error", "%s %s failed: %v", action, name, err)
	} else {
		s.audit(r, sess, "hub."+action, "type", typ, "name", name)
		msg := "Done: %s %s."
		if s.opt.CSCLI.CanReload() {
			msg += " Reload CrowdSec to apply it."
		} else {
			msg += " Reload CrowdSec on the host to apply it."
		}
		s.flash(sess, "ok", msg, action, name)
	}
	back(w, r, "/hub?type="+url.QueryEscape(typ))
}

func (s *Server) hubUpdate(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	if !s.requireCSCLI(w, r, sess) {
		return
	}
	ctx, cancel := ctxWrite(r)
	defer cancel()
	if err := s.opt.CSCLI.HubUpdate(ctx); err != nil {
		s.flash(sess, "error", "Hub update failed: %v", err)
	} else {
		s.audit(r, sess, "hub.update")
		s.flash(sess, "ok", "Hub index updated.")
	}
	back(w, r, "/hub")
}

func (s *Server) reload(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	if !s.requireCSCLI(w, r, sess) {
		return
	}
	ctx, cancel := ctxWrite(r)
	defer cancel()
	if err := s.opt.CSCLI.Reload(ctx); err != nil {
		s.flash(sess, "error", "Reload failed: %v", err)
	} else {
		s.audit(r, sess, "crowdsec.reload")
		s.flash(sess, "ok", "CrowdSec is reloading its configuration.")
	}
	back(w, r, "/hub")
}

// ---------------------------------------------------------------- allowlists

func (s *Server) allowlists(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	data := map[string]any{}
	if s.opt.CSCLI != nil {
		ctx, cancel := ctxRead(r)
		defer cancel()
		lists, err := s.opt.CSCLI.Allowlists(ctx)
		data["Rows"], data["Err"] = lists, errString(err)
		hub, err := s.opt.CSCLI.HubList(ctx)
		if err == nil {
			var wl []cscli.HubItem
			for _, it := range hub["parsers"] {
				if it.Installed && strings.Contains(strings.ToLower(it.Name), "whitelist") {
					wl = append(wl, it)
				}
			}
			data["Whitelists"] = wl
		}
	}
	s.render(w, http.StatusOK, "allowlists", s.page(sess, "Allowlists", "allowlists", data))
}

func (s *Server) createAllowlist(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	if !s.requireCSCLI(w, r, sess) {
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	ctx, cancel := ctxWrite(r)
	defer cancel()
	if err := s.opt.CSCLI.CreateAllowlist(ctx, name, r.PostFormValue("description")); err != nil {
		s.flash(sess, "error", "Could not create the allowlist: %v", err)
		back(w, r, "/allowlists")
		return
	}
	s.audit(r, sess, "allowlist.create", "name", name)
	s.flash(sess, "ok", "Created allowlist %s.", name)
	http.Redirect(w, r, "/allowlists/"+url.PathEscape(name), http.StatusSeeOther)
}

func (s *Server) allowlist(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	if !s.requireCSCLI(w, r, sess) {
		return
	}
	name, err := validate.AllowlistName(r.PathValue("name"))
	if err != nil {
		s.errorPage(w, r, sess, http.StatusNotFound, "No such allowlist.")
		return
	}
	ctx, cancel := ctxRead(r)
	defer cancel()
	a, err := s.opt.CSCLI.Allowlist(ctx, name)
	data := map[string]any{"Name": name, "List": a, "Err": errString(err)}
	s.render(w, http.StatusOK, "allowlist", s.page(sess, "Allowlist "+name, "allowlists", data))
}

func (s *Server) deleteAllowlist(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	if !s.requireCSCLI(w, r, sess) {
		return
	}
	name := r.PathValue("name")
	ctx, cancel := ctxWrite(r)
	defer cancel()
	if err := s.opt.CSCLI.DeleteAllowlist(ctx, name); err != nil {
		s.flash(sess, "error", "Could not delete the allowlist: %v", err)
		back(w, r, "/allowlists")
		return
	}
	s.audit(r, sess, "allowlist.delete", "name", name)
	s.flash(sess, "ok", "Deleted allowlist %s.", name)
	http.Redirect(w, r, "/allowlists", http.StatusSeeOther)
}

func (s *Server) allowlistAdd(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	if !s.requireCSCLI(w, r, sess) {
		return
	}
	name := r.PathValue("name")
	values := strings.FieldsFunc(r.PostFormValue("values"), func(c rune) bool {
		return c == '\n' || c == '\r' || c == ',' || c == ' ' || c == '\t'
	})
	ctx, cancel := ctxWrite(r)
	defer cancel()
	err := s.opt.CSCLI.AllowlistAdd(ctx, name, values, r.PostFormValue("expiration"), r.PostFormValue("comment"))
	if err != nil {
		s.flash(sess, "error", "Could not add to the allowlist: %v", err)
	} else {
		s.audit(r, sess, "allowlist.add", "name", name, "values", strings.Join(values, ","))
		s.flash(sess, "ok", "Added %d value(s) to %s.", len(values), name)
	}
	http.Redirect(w, r, "/allowlists/"+url.PathEscape(name), http.StatusSeeOther)
}

func (s *Server) allowlistRemove(w http.ResponseWriter, r *http.Request, sess *auth.Session) {
	if !s.requireCSCLI(w, r, sess) {
		return
	}
	name, value := r.PathValue("name"), r.PostFormValue("value")
	ctx, cancel := ctxWrite(r)
	defer cancel()
	if err := s.opt.CSCLI.AllowlistRemove(ctx, name, value); err != nil {
		s.flash(sess, "error", "Could not remove %s: %v", value, err)
	} else {
		s.audit(r, sess, "allowlist.remove", "name", name, "value", value)
		s.flash(sess, "ok", "Removed %s from %s.", value, name)
	}
	http.Redirect(w, r, "/allowlists/"+url.PathEscape(name), http.StatusSeeOther)
}
