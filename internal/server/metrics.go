// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// httpMetrics are the API listener's metrics (docs/operations/metrics.md).
// Their names and labels are part of the contract with the qrysm e2e
// evaluator (docs/contract.md section 18).
type httpMetrics struct {
	open         prometheus.Gauge
	limitReached prometheus.Counter
	inFlight     prometheus.Gauge
	// duration is http_request_duration_seconds{route,code}: route is the
	// matched route pattern ("-" when the request was refused before
	// routing), code the numeric status.
	duration *prometheus.HistogramVec
}

func newHTTPMetrics(reg prometheus.Registerer) (*httpMetrics, error) {
	m := &httpMetrics{
		open: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "http_connections_open",
			Help: "Open connections to the API listener.",
		}),
		limitReached: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "http_connections_limit_reached_total",
			Help: "Times an accepted connection brought the API listener to --http-max-connections; further connections wait until one closes.",
		}),
		inFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "http_requests_in_flight",
			Help: "API requests being served.",
		}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "API request durations by route pattern and status code.",
			Buckets: prometheus.DefBuckets,
		}, []string{"route", "code"}),
	}
	if reg != nil {
		for _, c := range []prometheus.Collector{m.open, m.limitReached, m.inFlight, m.duration} {
			if err := reg.Register(c); err != nil {
				return nil, err
			}
		}
	}
	return m, nil
}

// observe wraps the whole middleware chain: it counts the requests in
// flight and records each one's duration by route and status once it has
// been served. The route is known only then, because the router sets it on
// the request.
func (m *httpMetrics) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.inFlight.Inc()
		defer m.inFlight.Dec()
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		m.duration.WithLabelValues(routeOf(r), strconv.Itoa(rec.status())).Observe(time.Since(start).Seconds())
	})
}
