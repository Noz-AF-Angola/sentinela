// Package lapi is a small client for the CrowdSec Local API, authenticated as
// a machine (watcher). That is the same identity cscli uses, and it is what
// the LAPI requires for reading alerts and for adding or deleting decisions.
package lapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Meta is a key/value pair attached to alerts and events.
type Meta struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Event is one of the log events that made a scenario overflow.
type Event struct {
	Timestamp string `json:"timestamp"`
	Meta      []Meta `json:"meta"`
}

// Source describes who triggered an alert.
type Source struct {
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	IP       string `json:"ip,omitempty"`
	Range    string `json:"range,omitempty"`
	AsNumber string `json:"as_number,omitempty"`
	AsName   string `json:"as_name,omitempty"`
	Cn       string `json:"cn,omitempty"`
}

// Decision is a remediation (ban, captcha, ...) applied to a source.
type Decision struct {
	ID        int64  `json:"id"`
	Origin    string `json:"origin"`
	Type      string `json:"type"`
	Scope     string `json:"scope"`
	Value     string `json:"value"`
	Duration  string `json:"duration"`
	Until     string `json:"until,omitempty"`
	Scenario  string `json:"scenario"`
	Simulated bool   `json:"simulated"`
}

// Alert is what the LAPI stores when a scenario fires or a decision is added.
type Alert struct {
	ID              int64      `json:"id"`
	MachineID       string     `json:"machine_id"`
	Scenario        string     `json:"scenario"`
	ScenarioVersion string     `json:"scenario_version"`
	Message         string     `json:"message"`
	EventsCount     int64      `json:"events_count"`
	StartAt         string     `json:"start_at"`
	StopAt          string     `json:"stop_at"`
	CreatedAt       string     `json:"created_at"`
	Source          *Source    `json:"source"`
	Decisions       []Decision `json:"decisions"`
	Events          []Event    `json:"events"`
	Meta            []Meta     `json:"meta"`
	Remediation     bool       `json:"remediation"`
	Simulated       bool       `json:"simulated"`
}

// AlertFilter maps to the query parameters of GET /v1/alerts.
type AlertFilter struct {
	IP                  string
	Range               string
	Scenario            string
	Origin              string
	DecisionType        string
	Since               string // e.g. 24h
	ActiveDecisionsOnly bool
	IncludeCAPI         bool
	Limit               int
}

func (f AlertFilter) query() url.Values {
	q := url.Values{}
	set := func(k, v string) {
		if v != "" {
			q.Set(k, v)
		}
	}
	set("ip", f.IP)
	set("range", f.Range)
	set("scenario", f.Scenario)
	set("origin", f.Origin)
	set("decision_type", f.DecisionType)
	set("since", f.Since)
	if f.ActiveDecisionsOnly {
		q.Set("has_active_decision", "true")
	}
	q.Set("include_capi", strconv.FormatBool(f.IncludeCAPI))
	if f.Limit > 0 {
		q.Set("limit", strconv.Itoa(f.Limit))
	}
	return q
}

// NewDecision is a manual decision, the equivalent of `cscli decisions add`.
type NewDecision struct {
	Value    string // IP or CIDR, already validated
	Scope    string // Ip or Range
	Type     string // ban, captcha, ...
	Duration string // Go duration, e.g. 4h
	Reason   string
}

// Client talks to the LAPI.
type Client struct {
	base      *url.URL
	machineID string
	password  string
	hc        *http.Client
	userAgent string

	mu      sync.Mutex
	token   string
	expires time.Time
	now     func() time.Time
}

// New returns a client for the LAPI at baseURL (e.g. http://crowdsec:8080).
func New(baseURL, machineID, password string, hc *http.Client) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid LAPI URL %q", baseURL)
	}
	if machineID == "" || password == "" {
		return nil, errors.New("LAPI machine id and password are required")
	}
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	return &Client{base: u, machineID: machineID, password: password, hc: hc, userAgent: "sentinela/dev", now: time.Now}, nil
}

// SetVersion sets the User-Agent to "sentinela/VERSION". CrowdSec rejects a
// watcher login whose User-Agent is not in the "name/version" form, answering
// "incorrect Username or Password" even when the credentials are right.
func (c *Client) SetVersion(v string) {
	v = strings.TrimSpace(v)
	if v == "" || strings.ContainsAny(v, " /\t\r\n") {
		v = "dev"
	}
	c.userAgent = "sentinela/" + v
}

// APIError is a non-2xx answer from the LAPI.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("LAPI returned HTTP %d", e.Status)
	}
	return fmt.Sprintf("LAPI returned HTTP %d: %s", e.Status, e.Message)
}

func readAPIError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var m struct {
		Message string `json:"message"`
	}
	msg := ""
	if json.Unmarshal(body, &m) == nil {
		msg = m.Message
	}
	return &APIError{Status: resp.StatusCode, Message: msg}
}

func (c *Client) login(ctx context.Context) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"machine_id": c.machineID,
		"password":   c.password,
		"scenarios":  []string{},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base.String()+"/v1/watchers/login", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("LAPI login: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("LAPI login: %w", readAPIError(resp))
	}
	var out struct {
		Token  string `json:"token"`
		Expire string `json:"expire"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out); err != nil || out.Token == "" {
		return "", errors.New("LAPI login: no token in response")
	}
	exp, err := time.Parse(time.RFC3339, out.Expire)
	if err != nil {
		exp = c.now().Add(30 * time.Minute)
	}
	c.token, c.expires = out.Token, exp
	return out.Token, nil
}

func (c *Client) bearer(ctx context.Context, force bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !force && c.token != "" && c.now().Add(time.Minute).Before(c.expires) {
		return c.token, nil
	}
	return c.login(ctx)
}

// do performs an authenticated request and decodes the JSON answer into out.
// A 401 triggers one fresh login and a retry.
func (c *Client) do(ctx context.Context, method, path string, q url.Values, in, out any) error {
	var payload []byte
	if in != nil {
		var err error
		if payload, err = json.Marshal(in); err != nil {
			return err
		}
	}
	u := c.base.String() + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	for attempt := 0; attempt < 2; attempt++ {
		tok, err := c.bearer(ctx, attempt > 0)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("User-Agent", c.userAgent)
		if in != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.hc.Do(req)
		if err != nil {
			return fmt.Errorf("LAPI %s %s: %w", method, path, err)
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			_ = resp.Body.Close()
			continue
		}
		err = func() error {
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode < 200 || resp.StatusCode > 299 {
				return readAPIError(resp)
			}
			if out == nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
				return nil
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
			if err != nil {
				return err
			}
			// The LAPI answers "null" instead of [] when nothing matches.
			if bytes.Equal(bytes.TrimSpace(body), []byte("null")) {
				return nil
			}
			return json.Unmarshal(body, out)
		}()
		return err
	}
	return &APIError{Status: http.StatusUnauthorized, Message: "authentication failed"}
}

// Alerts lists alerts.
func (c *Client) Alerts(ctx context.Context, f AlertFilter) ([]Alert, error) {
	var out []Alert
	err := c.do(ctx, http.MethodGet, "/v1/alerts", f.query(), nil, &out)
	return out, err
}

// Alert fetches one alert with its events.
func (c *Client) Alert(ctx context.Context, id int64) (*Alert, error) {
	var out Alert
	if err := c.do(ctx, http.MethodGet, "/v1/alerts/"+strconv.FormatInt(id, 10), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// alertPost mirrors models.Alert with every field the LAPI marks as required.
type alertPost struct {
	Capacity        int32          `json:"capacity"`
	Decisions       []decisionPost `json:"decisions"`
	Events          []Event        `json:"events"`
	EventsCount     int32          `json:"events_count"`
	Leakspeed       string         `json:"leakspeed"`
	Message         string         `json:"message"`
	Remediation     bool           `json:"remediation"`
	Scenario        string         `json:"scenario"`
	ScenarioHash    string         `json:"scenario_hash"`
	ScenarioVersion string         `json:"scenario_version"`
	Simulated       bool           `json:"simulated"`
	Source          Source         `json:"source"`
	StartAt         string         `json:"start_at"`
	StopAt          string         `json:"stop_at"`
}

type decisionPost struct {
	Duration  string `json:"duration"`
	Origin    string `json:"origin"`
	Scenario  string `json:"scenario"`
	Scope     string `json:"scope"`
	Simulated bool   `json:"simulated"`
	Type      string `json:"type"`
	Value     string `json:"value"`
}

// AddDecision creates a manual decision the same way `cscli decisions add`
// does: by posting an alert that carries the decision. The origin is "cscli"
// because that is the origin the LAPI and the bouncers expect for manual
// decisions.
func (c *Client) AddDecision(ctx context.Context, d NewDecision) error {
	now := c.now().UTC().Format(time.RFC3339)
	src := Source{Scope: d.Scope, Value: d.Value}
	if d.Scope == "Ip" {
		src.IP = d.Value
	} else {
		src.Range = d.Value
	}
	alert := alertPost{
		Decisions: []decisionPost{{
			Duration: d.Duration, Origin: "cscli", Scenario: d.Reason,
			Scope: d.Scope, Type: d.Type, Value: d.Value,
		}},
		Events:    []Event{},
		Leakspeed: "0",
		Message: fmt.Sprintf("%s %s for %s: %s (added with Sentinela)",
			d.Type, d.Value, d.Duration, d.Reason),
		Remediation: true,
		Scenario:    d.Reason,
		Source:      src,
		StartAt:     now,
		StopAt:      now,
	}
	return c.do(ctx, http.MethodPost, "/v1/alerts", nil, []alertPost{alert}, nil)
}

type deleteResult struct {
	NbDeleted string `json:"nbDeleted"`
}

func (r deleteResult) count() int {
	n, _ := strconv.Atoi(r.NbDeleted)
	return n
}

// DeleteDecision removes one decision by id and returns how many were deleted.
func (c *Client) DeleteDecision(ctx context.Context, id int64) (int, error) {
	var out deleteResult
	err := c.do(ctx, http.MethodDelete, "/v1/decisions/"+strconv.FormatInt(id, 10), nil, nil, &out)
	return out.count(), err
}

// DeleteDecisionsByIP removes every decision that applies to ip (unban).
func (c *Client) DeleteDecisionsByIP(ctx context.Context, ip string) (int, error) {
	var out deleteResult
	err := c.do(ctx, http.MethodDelete, "/v1/decisions", url.Values{"ip": {ip}}, nil, &out)
	return out.count(), err
}
