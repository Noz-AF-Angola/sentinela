// Package metrics reads CrowdSec's Prometheus endpoint (usually :6060) and
// summarises the AppSec and decision counters. Reading metrics needs no
// credentials, so this works even when cscli is not available.
package metrics

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Sample is one line of the Prometheus text format.
type Sample struct {
	Name   string
	Labels map[string]string
	Value  float64
}

// Parse reads the Prometheus text exposition format. It only needs counters
// and gauges, so histogram details are read like any other sample.
func Parse(r io.Reader) ([]Sample, error) {
	var out []Sample
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		s, err := parseLine(line)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, sc.Err()
}

func parseLine(line string) (Sample, error) {
	s := Sample{Labels: map[string]string{}}
	i := strings.IndexAny(line, "{ ")
	if i <= 0 {
		return s, fmt.Errorf("bad metrics line %q", line)
	}
	s.Name = line[:i]
	rest := line[i:]
	if rest[0] == '{' {
		end, err := parseLabels(rest, s.Labels)
		if err != nil {
			return s, err
		}
		rest = rest[end:]
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return s, fmt.Errorf("no value in %q", line)
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return s, fmt.Errorf("bad value in %q", line)
	}
	s.Value = v
	return s, nil
}

// parseLabels parses {a="b",c="d"} at the start of s and returns the index
// just after the closing brace.
func parseLabels(s string, into map[string]string) (int, error) {
	i := 1
	for {
		for i < len(s) && (s[i] == ' ' || s[i] == ',') {
			i++
		}
		if i >= len(s) {
			return 0, errors.New("unterminated label set")
		}
		if s[i] == '}' {
			return i + 1, nil
		}
		eq := strings.IndexByte(s[i:], '=')
		if eq < 0 || i+eq+1 >= len(s) || s[i+eq+1] != '"' {
			return 0, errors.New("bad label")
		}
		key := strings.TrimSpace(s[i : i+eq])
		i += eq + 2
		var val strings.Builder
		for {
			if i >= len(s) {
				return 0, errors.New("unterminated label value")
			}
			c := s[i]
			if c == '\\' && i+1 < len(s) {
				switch s[i+1] {
				case 'n':
					val.WriteByte('\n')
				default:
					val.WriteByte(s[i+1])
				}
				i += 2
				continue
			}
			if c == '"' {
				i++
				break
			}
			val.WriteByte(c)
			i++
		}
		into[key] = val.String()
	}
}

// EngineStat is the request count of one AppSec engine.
type EngineStat struct {
	Engine    string
	Processed float64
	Blocked   float64
}

// BlockRate returns the share of blocked requests, in percent.
func (e EngineStat) BlockRate() float64 {
	if e.Processed == 0 {
		return 0
	}
	return 100 * e.Blocked / e.Processed
}

// RuleStat counts how often one AppSec rule matched.
type RuleStat struct {
	Engine string
	Rule   string
	Type   string
	Hits   float64
}

// Count is a labelled total.
type Count struct {
	Label string
	Value float64
}

// Summary is what the dashboard and the AppSec page show.
type Summary struct {
	Engines         []EngineStat
	Rules           []RuleStat
	TotalProcessed  float64
	TotalBlocked    float64
	DecisionsOrigin []Count // cs_active_decisions by origin
	DecisionsReason []Count // cs_active_decisions by reason
	HasAppSec       bool
	FetchedAt       time.Time
}

// Summarise turns raw samples into a Summary.
func Summarise(samples []Sample) *Summary {
	engines := map[string]*EngineStat{}
	rules := map[[3]string]float64{}
	origins := map[string]float64{}
	reasons := map[string]float64{}
	sum := &Summary{}
	engine := func(name string) *EngineStat {
		if name == "" {
			name = "default"
		}
		e, ok := engines[name]
		if !ok {
			e = &EngineStat{Engine: name}
			engines[name] = e
		}
		return e
	}
	for _, s := range samples {
		switch s.Name {
		case "cs_appsec_reqs_total":
			engine(s.Labels["appsec_engine"]).Processed += s.Value
			sum.HasAppSec = true
		case "cs_appsec_block_total":
			engine(s.Labels["appsec_engine"]).Blocked += s.Value
			sum.HasAppSec = true
		case "cs_appsec_rule_hits":
			rules[[3]string{s.Labels["appsec_engine"], s.Labels["rule_name"], s.Labels["type"]}] += s.Value
			sum.HasAppSec = true
		case "cs_active_decisions":
			origins[s.Labels["origin"]] += s.Value
			reasons[s.Labels["reason"]] += s.Value
		}
	}
	for _, e := range engines {
		sum.Engines = append(sum.Engines, *e)
		sum.TotalProcessed += e.Processed
		sum.TotalBlocked += e.Blocked
	}
	sort.Slice(sum.Engines, func(i, j int) bool { return sum.Engines[i].Engine < sum.Engines[j].Engine })
	for k, v := range rules {
		sum.Rules = append(sum.Rules, RuleStat{Engine: k[0], Rule: k[1], Type: k[2], Hits: v})
	}
	sort.Slice(sum.Rules, func(i, j int) bool {
		if sum.Rules[i].Hits != sum.Rules[j].Hits {
			return sum.Rules[i].Hits > sum.Rules[j].Hits
		}
		return sum.Rules[i].Rule < sum.Rules[j].Rule
	})
	sum.DecisionsOrigin = sortedCounts(origins)
	sum.DecisionsReason = sortedCounts(reasons)
	return sum
}

func sortedCounts(m map[string]float64) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		if v > 0 {
			out = append(out, Count{Label: k, Value: v})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Value != out[j].Value {
			return out[i].Value > out[j].Value
		}
		return out[i].Label < out[j].Label
	})
	return out
}

// Fetcher downloads and summarises the metrics endpoint.
type Fetcher struct {
	URL string
	HC  *http.Client
}

// Fetch reads the endpoint once.
func (f *Fetcher) Fetch(ctx context.Context) (*Summary, error) {
	hc := f.HC
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/plain")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("metrics endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metrics endpoint returned HTTP %d", resp.StatusCode)
	}
	samples, err := Parse(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	s := Summarise(samples)
	s.FetchedAt = time.Now()
	return s, nil
}
