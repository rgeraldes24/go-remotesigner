// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/server"
)

// Path is the one route of the metrics listener.
const Path = "/metrics"

// Timeouts of the metrics listener. A scrape is small and quick.
const (
	listenerReadTimeout  = 5 * time.Second
	listenerWriteTimeout = 30 * time.Second
	listenerIdleTimeout  = 120 * time.Second
	listenerHeaderBytes  = 8 << 10
)

// ListenerConfig configures a Listener.
type ListenerConfig struct {
	// Addr is the host:port to listen on (--metrics-host, --metrics-port).
	Addr string
	// HostAllowlist holds the accepted Host header names
	// (--metrics-host-allowlist); "*" accepts any.
	HostAllowlist []string
	// Gatherer is scraped at Path.
	Gatherer prometheus.Gatherer
	// Log receives refusals and listener errors.
	Log *logrus.Logger
}

// Listener is the metrics listener: a separate http.Server, enabled by
// --metrics-enabled, that serves GET /metrics behind the host allowlist and
// answers 404 to every other path. It needs no token (a later release adds
// an optional one).
type Listener struct {
	http     *http.Server
	listener net.Listener
	addr     string
	errLog   interface{ Close() error }
}

// NewListener builds the listener. It does not listen yet.
func NewListener(cfg ListenerConfig) *Listener {
	if cfg.Log == nil {
		cfg.Log = logrus.New()
	}
	mux := http.NewServeMux()
	mux.Handle("GET "+Path, promhttp.HandlerFor(cfg.Gatherer, promhttp.HandlerOpts{}))
	errWriter := cfg.Log.WriterLevel(logrus.DebugLevel)
	return &Listener{
		addr:   cfg.Addr,
		errLog: errWriter,
		http: &http.Server{
			Handler:           server.RequireAllowedHost(cfg.HostAllowlist, cfg.Log, mux),
			ReadHeaderTimeout: listenerReadTimeout,
			ReadTimeout:       listenerReadTimeout,
			WriteTimeout:      listenerWriteTimeout,
			IdleTimeout:       listenerIdleTimeout,
			MaxHeaderBytes:    listenerHeaderBytes,
			ErrorLog:          log.New(errWriter, "", 0),
		},
	}
}

// Handler returns the listener's handler, for in-process tests.
func (l *Listener) Handler() http.Handler { return l.http.Handler }

// Listen binds the socket.
func (l *Listener) Listen() error {
	ln, err := net.Listen("tcp", l.addr)
	if err != nil {
		return fmt.Errorf("metrics: listen on %s: %w", l.addr, err)
	}
	l.listener = ln
	return nil
}

// Addr returns the bound address; it is valid after Listen.
func (l *Listener) Addr() *net.TCPAddr {
	return l.listener.Addr().(*net.TCPAddr)
}

// Serve serves until Shutdown, and returns nil after it.
func (l *Listener) Serve() error {
	if l.listener == nil {
		return errors.New("metrics: Serve before Listen")
	}
	if err := l.http.Serve(l.listener); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown stops the listener, waiting until ctx ends for scrapes in
// progress. It also releases a socket that was bound but never served.
func (l *Listener) Shutdown(ctx context.Context) error {
	defer func() { _ = l.errLog.Close() }()
	err := l.http.Shutdown(ctx)
	if err != nil {
		_ = l.http.Close()
	}
	if l.listener != nil {
		_ = l.listener.Close() // already closed when it was served
	}
	return err
}
