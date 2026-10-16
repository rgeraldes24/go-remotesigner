// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/rgeraldes24/go-remotesigner/internal/consensus/types"
	"github.com/rgeraldes24/go-remotesigner/internal/server"
	"github.com/rgeraldes24/go-remotesigner/internal/server/auth"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

func newMetrics(t *testing.T) *Metrics {
	t.Helper()
	loaded := 3
	m, err := New(Config{Version: "v1.2.3", SignersLoaded: func() int { return loaded }})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func quiet() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l
}

// families gathers the registry by name.
func families(t *testing.T, g prometheus.Gatherer) map[string]*dto.MetricFamily {
	t.Helper()
	mfs, err := g.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*dto.MetricFamily{}
	for _, mf := range mfs {
		out[mf.GetName()] = mf
	}
	return out
}

// labelValues returns the values of one label across a family's series.
func labelValues(mf *dto.MetricFamily, label string) []string {
	var out []string
	for _, m := range mf.GetMetric() {
		for _, l := range m.GetLabel() {
			if l.GetName() == label && !slices.Contains(out, l.GetValue()) {
				out = append(out, l.GetValue())
			}
		}
	}
	slices.Sort(out)
	return out
}

func sorted(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	return s
}

// Every documented metric is registered, and every documented label value
// exists before it first occurs (docs/contract.md section 18).
func TestCatalogue(t *testing.T) {
	m := newMetrics(t)
	fams := families(t, m.Registry)

	var typeNames []string
	for _, ty := range types.ArtifactTypes() {
		typeNames = append(typeNames, string(ty))
	}
	var reasons []string
	for _, r := range PreventedReasons {
		reasons = append(reasons, strings.ToLower(string(r)))
	}
	tests := []struct {
		name   string
		labels map[string][]string
	}{
		{"signing_requests_total", map[string][]string{"type": typeNames, "result": RequestResults}},
		{"signing_mldsa87_signing_duration_seconds", map[string][]string{"type": typeNames}},
		{"http_mldsa87_malformed_request_count_total", nil},
		{"signing_mldsa87_missing_identifier_count_total", nil},
		{"signing_signers_loaded_count", nil},
		{"signing_keys_quarantined", nil},
		{"signing_verify_failures_total", nil},
		{"consensus_slashingprotection_permitted_signings_total", nil},
		{"consensus_slashingprotection_prevented_signings_total", map[string][]string{"reason": reasons}},
		{"consensus_slashingprotection_database_duration_seconds", map[string][]string{"operation": {"attestation", "block"}}},
		{"consensus_randao_reveals_total", map[string][]string{"result": RandaoResults}},
		{"consensus_randao_new_layer_rate_limited_total", nil},
		{"consensus_randao_reveal_duration_seconds", map[string][]string{"path": {RandaoPathHot, RandaoPathScan}}},
		{"consensus_randao_slow_path_scans_total", nil},
		{"consensus_randao_min_layers_remaining", nil},
		{"process_release", map[string][]string{"version": {"v1.2.3"}}},
		{"go_goroutines", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mf, ok := fams[tt.name]
			if !ok {
				t.Fatal("not registered")
			}
			for label, want := range tt.labels {
				if got := labelValues(mf, label); !slices.Equal(got, sorted(want)) {
					t.Errorf("%s values %v, want %v", label, got, sorted(want))
				}
			}
		})
	}
	if v := fams["consensus_randao_min_layers_remaining"].GetMetric()[0].GetGauge().GetValue(); !math.IsNaN(v) {
		t.Errorf("consensus_randao_min_layers_remaining = %v before any frontier, want NaN", v)
	}
	if v := fams["signing_signers_loaded_count"].GetMetric()[0].GetGauge().GetValue(); v != 3 {
		t.Errorf("signing_signers_loaded_count = %v, want 3", v)
	}
	if got := len(fams["signing_requests_total"].GetMetric()); got != 9*4 {
		t.Errorf("signing_requests_total has %d series, want 36", got)
	}
	// The contract's examples, spelled out.
	if !slices.Contains(labelValues(fams["consensus_slashingprotection_prevented_signings_total"], "reason"), "slashing_double_vote") {
		t.Error("no slashing_double_vote reason")
	}
	m.Prevented(slashing.ReasonSurroundedVote).Inc()
	if len(families(t, m.Registry)["consensus_slashingprotection_prevented_signings_total"].GetMetric()) != len(PreventedReasons) {
		t.Error("Prevented created a label value outside the catalogue")
	}
}

func TestResultOf(t *testing.T) {
	tests := []struct {
		status int
		want   string
	}{
		{200, ResultOK},
		{400, ResultBadRequest},
		{403, ResultRefused},
		{404, ResultBadRequest},
		{412, ResultRefused},
		{413, ResultBadRequest},
		{500, ResultError},
		{503, ResultError},
	}
	for _, tt := range tests {
		if got := ResultOf(tt.status); got != tt.want {
			t.Errorf("ResultOf(%d) = %s, want %s", tt.status, got, tt.want)
		}
	}
}

// The metrics listener serves GET /metrics to allowlisted hosts only, and
// nothing else.
func TestListenerHandler(t *testing.T) {
	m := newMetrics(t)
	l := NewListener(ListenerConfig{Addr: "127.0.0.1:0", HostAllowlist: []string{"localhost", "127.0.0.1"},
		Gatherer: m.Registry, Log: quiet()})
	tests := []struct {
		name, method, path, host string
		status                   int
		body                     string
	}{
		{"scrape", http.MethodGet, "/metrics", "localhost:9001", 200, "signing_requests_total{result=\"ok\",type=\"ATTESTATION\"} 0"},
		{"scrape by IP", http.MethodGet, "/metrics", "127.0.0.1:9001", 200, "process_release{version=\"v1.2.3\"} 1"},
		{"foreign Host", http.MethodGet, "/metrics", "evil.example:9001", 403, "HOST_NOT_ALLOWED"},
		{"other path", http.MethodGet, "/", "localhost:9001", 404, ""},
		{"POST", http.MethodPost, "/metrics", "localhost:9001", 405, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(tt.method, tt.path, nil)
			r.Host = tt.host
			rec := httptest.NewRecorder()
			l.Handler().ServeHTTP(rec, r)
			if rec.Code != tt.status || !strings.Contains(rec.Body.String(), tt.body) {
				t.Fatalf("%d %.200q, want %d containing %q", rec.Code, rec.Body.String(), tt.status, tt.body)
			}
		})
	}
}

// With a metrics token, a scrape needs it (401 otherwise); the host
// allowlist still runs first.
func TestListenerToken(t *testing.T) {
	dir := t.TempDir()
	tok := "0x" + strings.Repeat("ab", 32)
	tokenFile := dir + "/metrics-token"
	if err := os.WriteFile(tokenFile, []byte(tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := auth.New(auth.Config{Mode: auth.ModeNone, MetricsTokenFile: tokenFile})
	if err != nil {
		t.Fatal(err)
	}
	l := NewListener(ListenerConfig{Addr: "127.0.0.1:0", HostAllowlist: []string{"localhost"}, Gatherer: newMetrics(t).Registry,
		Auth: a, Log: quiet()})
	tests := []struct {
		name, host, auth string
		status           int
		body             string
	}{
		{"no token", "localhost", "", 401, "UNAUTHENTICATED"},
		{"wrong token", "localhost", "Bearer 0x" + strings.Repeat("cd", 32), 401, "UNAUTHENTICATED"},
		{"token", "localhost", "Bearer " + tok, 200, "signing_verify_failures_total 0"},
		{"foreign Host with the token", "evil.example", "Bearer " + tok, 403, "HOST_NOT_ALLOWED"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, Path, nil)
			r.Host = tt.host
			if tt.auth != "" {
				r.Header.Set("Authorization", tt.auth)
			}
			rec := httptest.NewRecorder()
			l.Handler().ServeHTTP(rec, r)
			if rec.Code != tt.status || !strings.Contains(rec.Body.String(), tt.body) {
				t.Fatalf("%d %.200q, want %d containing %q", rec.Code, rec.Body.String(), tt.status, tt.body)
			}
			if tt.status == 401 && rec.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatal("no WWW-Authenticate: Bearer")
			}
		})
	}
}

// No metric carries a key, identifier or URL label: every label name is
// one of the documented ones, whatever has been recorded.
func TestNoKeyLabels(t *testing.T) {
	m := newMetrics(t)
	for _, ty := range types.ArtifactTypes() {
		m.SigningRequests.WithLabelValues(string(ty), ResultOK).Inc()
		m.SigningDuration.WithLabelValues(string(ty)).Observe(0.001)
	}
	m.Prevented(slashing.ReasonDoubleVote).Inc()
	m.RandaoReveals.WithLabelValues(RandaoFirstUse).Inc()
	allowed := []string{"type", "result", "reason", "operation", "path", "version"}
	for name, mf := range families(t, m.Registry) {
		for _, metric := range mf.GetMetric() {
			for _, l := range metric.GetLabel() {
				if !slices.Contains(allowed, l.GetName()) {
					t.Errorf("%s has label %s=%q", name, l.GetName(), l.GetValue())
				}
			}
		}
	}
}

func TestListenerServes(t *testing.T) {
	m := newMetrics(t)
	l := NewListener(ListenerConfig{Addr: "127.0.0.1:0", HostAllowlist: []string{"127.0.0.1"}, Gatherer: m.Registry, Log: quiet()})
	if err := l.Listen(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- l.Serve() }()
	resp, err := http.Get("http://" + l.Addr().String() + Path)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "signing_verify_failures_total 0") {
		t.Fatalf("%d %.200q", resp.StatusCode, body)
	}
	if err := l.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Serve = %v after Shutdown", err)
	}
}

// Every metric that deploy/prometheus/alerts.yml uses exists, and the four
// documented alerts are there.
func TestAlertRules(t *testing.T) {
	m := newMetrics(t)
	authn, err := auth.New(auth.Config{Mode: auth.ModeNone})
	if err != nil {
		t.Fatal(err)
	}
	// The API listener registers the HTTP metrics.
	if _, err := server.New(server.Config{Addr: "127.0.0.1:0", Auth: authn, Registerer: m.Registry, Log: quiet()}); err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	mfs, err := m.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		known[mf.GetName()] = true
	}

	data, err := os.ReadFile("../../deploy/prometheus/alerts.yml")
	if err != nil {
		t.Fatal(err)
	}
	var rules struct {
		Groups []struct {
			Rules []struct {
				Alert string `yaml:"alert"`
				Expr  string `yaml:"expr"`
			} `yaml:"rules"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(data, &rules); err != nil {
		t.Fatal(err)
	}
	// Label matchers, ranges and quoted strings are not metric names.
	strip := regexp.MustCompile(`\{[^}]*\}|\[[^\]]*\]|"[^"]*"`)
	ident := regexp.MustCompile(`[a-z_][a-z0-9_]*`)
	used := map[string]bool{}
	var alerts []string
	for _, g := range rules.Groups {
		for _, r := range g.Rules {
			alerts = append(alerts, r.Alert)
			for _, id := range ident.FindAllString(strip.ReplaceAllString(r.Expr, ""), -1) {
				if !strings.Contains(id, "_") { // functions and operators: increase, or
					continue
				}
				used[id] = true
				if !known[id] {
					t.Errorf("alert %s uses %s, which is not registered", r.Alert, id)
				}
			}
		}
	}
	for _, name := range []string{"consensus_randao_new_layer_rate_limited_total", "consensus_randao_reveals_total",
		"signing_verify_failures_total", "signing_keys_quarantined", "http_connections_limit_reached_total"} {
		if !used[name] {
			t.Errorf("no alert uses %s", name)
		}
	}
	if len(alerts) != 4 {
		t.Errorf("alerts %v, want 4", alerts)
	}
}
