// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net"
	"sync"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/netutil"
)

// DefaultMaxConnections is the default of --http-max-connections.
const DefaultMaxConnections = 1024

// connMetrics are the listener's metrics.
type connMetrics struct {
	open         prometheus.Gauge
	limitReached prometheus.Counter
}

func newConnMetrics(reg prometheus.Registerer) (*connMetrics, error) {
	m := &connMetrics{
		open: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "http_connections_open",
			Help: "Open connections to the API listener.",
		}),
		limitReached: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "http_connections_limit_reached_total",
			Help: "Times an accepted connection brought the API listener to --http-max-connections; further connections wait until one closes.",
		}),
	}
	if reg != nil {
		for _, c := range []prometheus.Collector{m.open, m.limitReached} {
			if err := reg.Register(c); err != nil {
				return nil, err
			}
		}
	}
	return m, nil
}

// limitListener caps the open connections with netutil.LimitListener: once
// max connections are open, Accept waits until one closes. It also counts
// open connections and the times the cap was reached.
type limitListener struct {
	net.Listener // netutil.LimitListener over the bound socket
	max          int64
	open         atomic.Int64
	m            *connMetrics
}

func newLimitListener(l net.Listener, max int, m *connMetrics) *limitListener {
	return &limitListener{Listener: netutil.LimitListener(l, max), max: int64(max), m: m}
}

func (l *limitListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.m.open.Inc()
	if l.open.Add(1) >= l.max {
		l.m.limitReached.Inc()
	}
	return &countedConn{Conn: c, l: l}, nil
}

// countedConn decrements the open count once, on its first Close.
type countedConn struct {
	net.Conn
	l    *limitListener
	once sync.Once
}

func (c *countedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		c.l.open.Add(-1)
		c.l.m.open.Dec()
	})
	return err
}
