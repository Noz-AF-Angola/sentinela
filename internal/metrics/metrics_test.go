package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const sample = `# HELP cs_appsec_reqs_total Total events processed by the Application Security Engine.
# TYPE cs_appsec_reqs_total counter
cs_appsec_reqs_total{appsec_engine="127.0.0.1:7422",source="198.51.100.4"} 120
cs_appsec_reqs_total{appsec_engine="127.0.0.1:7422",source="192.0.2.1"} 80
cs_appsec_block_total{appsec_engine="127.0.0.1:7422",source="198.51.100.4"} 10
cs_appsec_rule_hits{appsec_engine="127.0.0.1:7422",rule_name="crowdsecurity/vpatch-CVE-2017-9841",source="198.51.100.4",type="inband"} 7
cs_appsec_rule_hits{appsec_engine="127.0.0.1:7422",rule_name="crowdsecurity/vpatch-env-access",source="192.0.2.1",type="inband"} 3
cs_appsec_rule_hits{appsec_engine="127.0.0.1:7422",rule_name="crowdsecurity/vpatch-CVE-2017-9841",source="192.0.2.1",type="inband"} 2
cs_active_decisions{action="ban",origin="CAPI",reason="http:scan"} 1500
cs_active_decisions{action="ban",origin="crowdsec",reason="crowdsecurity/http-probing"} 4
cs_active_decisions{action="ban",origin="cscli",reason="manual \"ban\"\\x"} 1
go_goroutines 42
process_start_time_seconds 1.7e+09 1700000000000
`

func TestParseAndSummarise(t *testing.T) {
	samples, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 11 {
		t.Fatalf("got %d samples", len(samples))
	}
	if got := samples[8].Labels["reason"]; got != `manual "ban"\x` {
		t.Errorf("escaped label = %q", got)
	}
	s := Summarise(samples)
	if !s.HasAppSec || s.TotalProcessed != 200 || s.TotalBlocked != 10 || len(s.Engines) != 1 {
		t.Fatalf("summary = %+v", s)
	}
	if r := s.Engines[0].BlockRate(); r != 5 {
		t.Errorf("block rate = %v", r)
	}
	if len(s.Rules) != 2 || s.Rules[0].Rule != "crowdsecurity/vpatch-CVE-2017-9841" || s.Rules[0].Hits != 9 {
		t.Errorf("rules = %+v", s.Rules)
	}
	if s.DecisionsOrigin[0].Label != "CAPI" || len(s.DecisionsReason) != 3 {
		t.Errorf("decisions = %+v %+v", s.DecisionsOrigin, s.DecisionsReason)
	}
	if (EngineStat{}).BlockRate() != 0 {
		t.Error("zero division")
	}
}

func TestParseErrors(t *testing.T) {
	for _, bad := range []string{"novalue", `x{a="b} 1`, `x{a=b} 1`, "x abc"} {
		if _, err := Parse(strings.NewReader(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(sample))
	}))
	defer srv.Close()
	s, err := (&Fetcher{URL: srv.URL}).Fetch(context.Background())
	if err != nil || s.TotalProcessed != 200 || s.FetchedAt.IsZero() {
		t.Fatalf("fetch = %+v %v", s, err)
	}
	if _, err := (&Fetcher{URL: srv.URL + "/missing\x00"}).Fetch(context.Background()); err == nil {
		t.Error("bad URL accepted")
	}
}
