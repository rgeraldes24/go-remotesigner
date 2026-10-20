// Copyright 2020 ConsenSys AG.
// Copyright 2026 The go-remotesigner Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//
// Modified by The go-remotesigner Authors, 2026: translated from Java to Go and adapted for QRL.
// Derived from Web3Signer
// core/src/main/java/tech/pegasys/web3signer/core/service/http/metrics/HttpApiMetrics.java and
// core/src/main/java/tech/pegasys/web3signer/core/metrics/SlashingProtectionMetrics.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

// Package metrics holds the signer's Prometheus registry and the metrics
// listener that serves it (docs/operations/metrics.md).
//
// Names keep Web3Signer's <category>_<name> structure with bls renamed to
// mldsa87 and eth2 to consensus, and histograms in place of summaries. The
// names and label values that the qrysm e2e evaluator reads are part of the
// contract (docs/contract.md section 18): every documented label value is
// created at startup, so a scrape shows it at zero before it first occurs.
// No metric carries a public key or a URL.
package metrics

import (
	"math"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/rgeraldes24/go-remotesigner/internal/consensus/types"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// Values of the result label of signing_requests_total.
const (
	ResultOK         = "ok"          // signed and released
	ResultRefused    = "refused"     // a policy, clock or slashing refusal (403, 412)
	ResultBadRequest = "bad_request" // any other client error (400, 404)
	ResultError      = "error"       // a server fault or an unavailable key (5xx)
)

// Values of the result label of consensus_randao_reveals_total.
const (
	RandaoFirstUse    = "first_use"
	RandaoNewLayer    = "new_layer"
	RandaoGapAdvanced = "gap_advanced"
	RandaoReReveal    = "re_reveal"
	RandaoRefused     = "refused" // any 412, 422 or 429
	RandaoError       = "error"   // 500
)

// Values of the path label of consensus_randao_reveal_duration_seconds.
const (
	RandaoPathHot  = "hot"  // served from the frontier or the precomputed layer
	RandaoPathScan = "scan" // needed a computation from x_0
)

// Values of the operation label of
// consensus_slashingprotection_database_duration_seconds.
const (
	OperationBlock       = "block"
	OperationAttestation = "attestation"
)

// RequestResults are the values of the result label of
// signing_requests_total.
var RequestResults = []string{ResultOK, ResultRefused, ResultBadRequest, ResultError}

// RandaoResults are the values of the result label of
// consensus_randao_reveals_total.
var RandaoResults = []string{RandaoFirstUse, RandaoNewLayer, RandaoGapAdvanced, RandaoReReveal, RandaoRefused, RandaoError}

// PreventedReasons are the slashing refusals, each the value of the reason
// label of consensus_slashingprotection_prevented_signings_total in lower
// case.
var PreventedReasons = []slashing.Reason{
	slashing.ReasonDoubleProposal,
	slashing.ReasonDoubleVote,
	slashing.ReasonSurroundingVote,
	slashing.ReasonSurroundedVote,
	slashing.ReasonBelowWatermark,
	slashing.ReasonAboveHighWatermark,
	slashing.ReasonValidatorDisabled,
}

// Config configures New.
type Config struct {
	// Version is the release, the version label of process_release.
	Version string
	// SignersLoaded returns the number of loaded keys.
	SignersLoaded func() int
}

// Metrics is the registry and the signer's own metrics. The HTTP metrics
// of the API listener register themselves in Registry (package server).
type Metrics struct {
	Registry *prometheus.Registry

	// SigningRequests is signing_requests_total{type,result}.
	SigningRequests *prometheus.CounterVec
	// SigningDuration is signing_mldsa87_signing_duration_seconds{type}:
	// signing and verifying one signature.
	SigningDuration *prometheus.HistogramVec
	// MalformedRequests is http_mldsa87_malformed_request_count_total: sign
	// requests refused before their type was known (a bad identifier or
	// body).
	MalformedRequests prometheus.Counter
	// MissingIdentifier is signing_mldsa87_missing_identifier_count_total:
	// sign requests for a key that is not loaded.
	MissingIdentifier prometheus.Counter
	// KeysQuarantined is signing_keys_quarantined.
	KeysQuarantined prometheus.Gauge
	// VerifyFailures is signing_verify_failures_total.
	VerifyFailures prometheus.Counter

	// SlashingPermitted is consensus_slashingprotection_permitted_signings_total.
	SlashingPermitted prometheus.Counter
	// SlashingPrevented is
	// consensus_slashingprotection_prevented_signings_total{reason}; use
	// Prevented.
	SlashingPrevented *prometheus.CounterVec
	// SlashingDatabaseDuration is
	// consensus_slashingprotection_database_duration_seconds{operation}.
	SlashingDatabaseDuration *prometheus.HistogramVec

	// RandaoReveals is consensus_randao_reveals_total{result}.
	RandaoReveals *prometheus.CounterVec
	// RandaoNewLayerRateLimited is
	// consensus_randao_new_layer_rate_limited_total.
	RandaoNewLayerRateLimited prometheus.Counter
	// RandaoRevealDuration is consensus_randao_reveal_duration_seconds{path}
	// of released reveals.
	RandaoRevealDuration *prometheus.HistogramVec
	// RandaoSlowPathScans is consensus_randao_slow_path_scans_total.
	RandaoSlowPathScans prometheus.Counter
	// RandaoMinLayersRemaining is consensus_randao_min_layers_remaining.
	RandaoMinLayersRemaining prometheus.Gauge
}

// NewRegistry builds the registry every mode shares: the Go and process
// collectors, process_release{version} and, when cfg.SignersLoaded is set,
// signing_signers_loaded_count. Execution mode serves only these and the
// HTTP metrics.
func NewRegistry(cfg Config) (*prometheus.Registry, error) {
	r := prometheus.NewRegistry()
	for _, c := range baseCollectors(cfg) {
		if err := r.Register(c); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func baseCollectors(cfg Config) []prometheus.Collector {
	release := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "process_release",
		Help: "The running release; always 1.",
	}, []string{"version"})
	release.WithLabelValues(cfg.Version).Set(1)
	cs := []prometheus.Collector{
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		release,
	}
	if cfg.SignersLoaded != nil {
		loaded := cfg.SignersLoaded
		cs = append(cs, prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "signing_signers_loaded_count",
			Help: "Keys loaded.",
		}, func() float64 { return float64(loaded()) }))
	}
	return cs
}

// New builds the registry with the Go and process collectors,
// process_release{version} and the signer's metrics, every documented label
// value created.
func New(cfg Config) (*Metrics, error) {
	m := &Metrics{
		Registry: prometheus.NewRegistry(),
		SigningRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "signing_requests_total",
			Help: "Sign requests by artifact type and result (ok, refused, bad_request, error).",
		}, []string{"type", "result"}),
		SigningDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "signing_mldsa87_signing_duration_seconds",
			Help:    "Time to sign and verify one ML-DSA-87 signature, by artifact type.",
			Buckets: []float64{.0005, .001, .0025, .005, .01, .025, .05, .1, .25, .5, 1},
		}, []string{"type"}),
		MalformedRequests: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "http_mldsa87_malformed_request_count_total",
			Help: "Sign requests refused for a malformed identifier or body.",
		}),
		MissingIdentifier: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "signing_mldsa87_missing_identifier_count_total",
			Help: "Sign requests for a key that is not loaded.",
		}),
		KeysQuarantined: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "signing_keys_quarantined",
			Help: "Keys quarantined after a signature failed verification; they refuse to sign until a reload.",
		}),
		VerifyFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "signing_verify_failures_total",
			Help: "Signatures that failed verification before release; the bytes were discarded.",
		}),
		SlashingPermitted: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "consensus_slashingprotection_permitted_signings_total",
			Help: "Slashing checks of blocks and attestations that allowed signing.",
		}),
		SlashingPrevented: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "consensus_slashingprotection_prevented_signings_total",
			Help: "Slashing checks of blocks and attestations that refused signing, by reason.",
		}, []string{"reason"}),
		SlashingDatabaseDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "consensus_slashingprotection_database_duration_seconds",
			Help:    "Time spent in the slashing-protection store while signing, by operation.",
			Buckets: prometheus.DefBuckets,
		}, []string{"operation"}),
		RandaoReveals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "consensus_randao_reveals_total",
			Help: "RANDAO reveal requests by result.",
		}, []string{"result"}),
		RandaoNewLayerRateLimited: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "consensus_randao_new_layer_rate_limited_total",
			Help: "RANDAO reveals refused because the key's new-layer bucket was empty.",
		}),
		RandaoRevealDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "consensus_randao_reveal_duration_seconds",
			Help:    "Time to release a RANDAO reveal, by path (hot: no onion computation; scan: computed from x_0).",
			Buckets: []float64{.0001, .0005, .001, .005, .01, .05, .1, .25, .5, 1, 2.5},
		}, []string{"path"}),
		RandaoSlowPathScans: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "consensus_randao_slow_path_scans_total",
			Help: "RANDAO onion scans from x_0 (first use, gap advance, deep reorg, unknown commitment).",
		}),
		RandaoMinLayersRemaining: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "consensus_randao_min_layers_remaining",
			Help: "Fewest RANDAO layers any loaded key has left (its frontier index); NaN while no loaded key has a frontier.",
		}),
	}
	cs := append(baseCollectors(cfg),
		m.SigningRequests, m.SigningDuration, m.MalformedRequests, m.MissingIdentifier, m.KeysQuarantined,
		m.VerifyFailures, m.SlashingPermitted, m.SlashingPrevented, m.SlashingDatabaseDuration, m.RandaoReveals,
		m.RandaoNewLayerRateLimited, m.RandaoRevealDuration, m.RandaoSlowPathScans, m.RandaoMinLayersRemaining,
	)
	for _, c := range cs {
		if err := m.Registry.Register(c); err != nil {
			return nil, err
		}
	}

	for _, t := range types.ArtifactTypes() {
		m.SigningDuration.WithLabelValues(string(t))
		for _, r := range RequestResults {
			m.SigningRequests.WithLabelValues(string(t), r)
		}
	}
	for _, r := range PreventedReasons {
		m.Prevented(r)
	}
	for _, op := range []string{OperationBlock, OperationAttestation} {
		m.SlashingDatabaseDuration.WithLabelValues(op)
	}
	for _, r := range RandaoResults {
		m.RandaoReveals.WithLabelValues(r)
	}
	for _, p := range []string{RandaoPathHot, RandaoPathScan} {
		m.RandaoRevealDuration.WithLabelValues(p)
	}
	m.RandaoMinLayersRemaining.Set(math.NaN())
	return m, nil
}

// Prevented returns the prevented-signings counter of a refusal reason.
func (m *Metrics) Prevented(r slashing.Reason) prometheus.Counter {
	return m.SlashingPrevented.WithLabelValues(strings.ToLower(string(r)))
}

// ResultOf maps the status of a sign response to its result label.
func ResultOf(status int) string {
	switch {
	case status < 300:
		return ResultOK
	case status == 403, status == 412:
		return ResultRefused
	case status < 500:
		return ResultBadRequest
	default:
		return ResultError
	}
}
