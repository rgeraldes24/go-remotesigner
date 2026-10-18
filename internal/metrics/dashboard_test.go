// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"

	"github.com/rgeraldes24/go-remotesigner/internal/server"
	"github.com/rgeraldes24/go-remotesigner/internal/server/auth"
)

const dashboardPath = "../../deploy/grafana/remotesigner.json"

// dashboardPanel is the part of a Grafana panel the tests read.
type dashboardPanel struct {
	Type    string `json:"type"`
	Title   string `json:"title"`
	Targets []struct {
		Expr string `json:"expr"`
	} `json:"targets"`
}

// dashboard is the part of the Grafana dashboard the tests read.
type dashboard struct {
	Description string           `json:"description"`
	Panels      []dashboardPanel `json:"panels"`
	Templating  struct {
		List []dashboardVariable `json:"list"`
	} `json:"templating"`
}

// dashboardVariable is a template variable. Its query is a string (the data
// source type of a datasource variable) or an object holding the PromQL.
type dashboardVariable struct {
	Name  string          `json:"name"`
	Type  string          `json:"type"`
	Query json.RawMessage `json:"query"`
}

// promQL returns the PromQL of a query variable.
func (v dashboardVariable) promQL(t *testing.T) string {
	t.Helper()
	var q struct {
		Query string `json:"query"`
	}
	if err := json.Unmarshal(v.Query, &q); err != nil {
		t.Fatalf("variable %q: query: %v", v.Name, err)
	}
	return q.Query
}

// readDashboard returns the shipped dashboard.
func readDashboard(t *testing.T) dashboard {
	t.Helper()
	data, err := os.ReadFile(dashboardPath)
	if err != nil {
		t.Fatal(err)
	}
	var d dashboard
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatalf("%s: %v", dashboardPath, err)
	}
	return d
}

// templateFunctions are the Grafana template functions a variable query may
// use around a metric name.
var templateFunctions = []string{"label_values"}

// promQLFunctions are the PromQL functions with an underscore in their name
// that the dashboard uses; every other such identifier is a metric name.
var promQLFunctions = []string{"histogram_quantile"}

// metricNames returns the metric names a PromQL expression reads.
func metricNames(expr string) []string {
	strip := regexp.MustCompile(`\{[^}]*\}|\[[^\]]*\]|"[^"]*"|\$\w+`)
	ident := regexp.MustCompile(`[a-zA-Z_:][a-zA-Z0-9_:]*`)
	var names []string
	for _, id := range ident.FindAllString(strip.ReplaceAllString(expr, ""), -1) {
		if strings.Contains(id, "_") && !slices.Contains(promQLFunctions, id) && !slices.Contains(names, id) {
			names = append(names, id)
		}
	}
	return names
}

func TestMetricNames(t *testing.T) {
	got := metricNames(`histogram_quantile(0.99, sum by (le, path) (rate(consensus_randao_reveal_duration_seconds_bucket{instance=~"$instance"}[$__rate_interval])))`)
	if want := []string{"consensus_randao_reveal_duration_seconds_bucket"}; !slices.Equal(got, want) {
		t.Errorf("metricNames = %q, want %q", got, want)
	}
}

// Every metric the shipped Grafana dashboard queries is registered, and the
// dashboard has slashing-protection and RANDAO panels that read those
// metrics. It carries the licence notice of a file derived from Web3Signer.
func TestGrafanaDashboard(t *testing.T) {
	m := newMetrics(t)
	authn, err := auth.New(auth.Config{Mode: auth.ModeNone})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(server.Config{Addr: "127.0.0.1:0", Auth: authn, Registerer: m.Registry, Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	// http_request_duration_seconds has a series only once a request was
	// served.
	r := httptest.NewRequest(http.MethodGet, "/upcheck", nil)
	r.Host = "127.0.0.1"
	srv.Handler().ServeHTTP(httptest.NewRecorder(), r)
	fams := families(t, m.Registry)
	// known reports whether name is a series of a registered family: the
	// family itself or, for a histogram or summary, its _bucket, _sum or
	// _count series.
	known := func(name string) bool {
		if _, ok := fams[name]; ok {
			return true
		}
		for _, suffix := range []string{"_bucket", "_sum", "_count"} {
			base, ok := strings.CutSuffix(name, suffix)
			if !ok {
				continue
			}
			if mf, ok := fams[base]; ok && (mf.GetType() == dto.MetricType_HISTOGRAM || mf.GetType() == dto.MetricType_SUMMARY) {
				return suffix != "_bucket" || mf.GetType() == dto.MetricType_HISTOGRAM
			}
		}
		return false
	}

	d := readDashboard(t)
	for _, v := range d.Templating.List {
		if v.Type != "query" {
			continue
		}
		for _, name := range metricNames(v.promQL(t)) {
			if !known(name) && !slices.Contains(templateFunctions, name) {
				t.Errorf("variable %q queries %s, which is not registered", v.Name, name)
			}
		}
	}
	for _, line := range []string{
		"Copyright 2020 ConsenSys AG.",
		"Copyright 2026 The go-remotesigner Authors.",
		"SPDX-License-Identifier: Apache-2.0",
		"Derived from Web3Signer dashboard/web3signer-eth2-dashboard-grafana.json at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.",
	} {
		if !slices.Contains(strings.Split(d.Description, "\n"), line) {
			t.Errorf("description lacks the line %q", line)
		}
	}

	rows := map[string]bool{}
	var row string
	used := map[string][]string{} // row title -> metric names its panels read
	for _, p := range d.Panels {
		if p.Type == "row" {
			row = p.Title
			rows[row] = true
			continue
		}
		if len(p.Targets) == 0 {
			t.Errorf("panel %q has no query", p.Title)
		}
		for _, tg := range p.Targets {
			for _, name := range metricNames(tg.Expr) {
				used[row] = append(used[row], name)
				// The process collector reports fewer metrics outside Linux.
				if !known(name) && (runtime.GOOS == "linux" || !strings.HasPrefix(name, "process_")) {
					t.Errorf("panel %q queries %s, which is not registered", p.Title, name)
				}
			}
		}
	}
	for _, want := range []struct{ row, metric string }{
		{"Slashing protection", "consensus_slashingprotection_prevented_signings_total"},
		{"Slashing protection", "consensus_slashingprotection_permitted_signings_total"},
		{"Slashing protection", "consensus_slashingprotection_database_duration_seconds_bucket"},
		{"RANDAO", "consensus_randao_reveals_total"},
		{"RANDAO", "consensus_randao_new_layer_rate_limited_total"},
		{"RANDAO", "consensus_randao_slow_path_scans_total"},
		{"RANDAO", "consensus_randao_reveal_duration_seconds_bucket"},
		{"RANDAO", "consensus_randao_min_layers_remaining"},
		{"Signing", "signing_requests_total"},
	} {
		if !rows[want.row] {
			t.Errorf("no %q row", want.row)
			continue
		}
		if !slices.Contains(used[want.row], want.metric) {
			t.Errorf("the %q row does not chart %s", want.row, want.metric)
		}
	}
}
