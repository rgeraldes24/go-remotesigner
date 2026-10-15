// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package server is the API listener: an http.Server with the timeouts and
// limits of docs/contract.md section 13, the fixed middleware order (access
// log, host allowlist, Origin refusal, auth, content type, body limit), JSON
// error responses with reason codes, a readiness gate, a connection cap and
// graceful shutdown.
//
// Handlers live in the api packages; this package only routes, guards and
// renders errors.
package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/server/auth"
)

// Timeouts and header limits (docs/contract.md section 13).
const (
	ReadHeaderTimeout  = 5 * time.Second
	MinRequestTimeout  = 5 * time.Second
	DefaultIdleTimeout = 120 * time.Second
	MaxHeaderBytes     = 64 << 10
	// HandlerDrainTimeout bounds the wait for handlers still running after
	// Shutdown has given up and closed their connections.
	HandlerDrainTimeout = 5 * time.Second
)

// ErrHandlersRunning is returned by Shutdown when handlers are still running
// after HandlerDrainTimeout. The caller must then not release what they use,
// such as the slashing-protection store or the keys.
var ErrHandlersRunning = errors.New("server: handlers still running after shutdown")

// ReadTimeout returns max(5 s, slot/4).
func ReadTimeout(secondsPerSlot uint64) time.Duration {
	return max(MinRequestTimeout, time.Duration(secondsPerSlot)*time.Second/4)
}

// WriteTimeout returns max(5 s, slot/3).
func WriteTimeout(secondsPerSlot uint64) time.Duration {
	return max(MinRequestTimeout, time.Duration(secondsPerSlot)*time.Second/3)
}

// Config configures a Server.
type Config struct {
	// Addr is the host:port to listen on.
	Addr string
	// HostAllowlist holds the accepted Host header names; "*" accepts any.
	HostAllowlist []string
	// Auth checks each route's scope.
	Auth *auth.Authenticator
	// Routes are the API endpoints. Admin routes need Auth.HasAdmin.
	Routes []Route
	// Ready reports whether routes with NeedsReady may serve.
	Ready func() bool
	// MaxConnections caps open connections; 0 means DefaultMaxConnections.
	MaxConnections int
	// LargeBodySlots bounds large bodies read at once; 0 means
	// DefaultLargeBodySlots.
	LargeBodySlots int
	// ReadTimeout and WriteTimeout bound a request; IdleTimeout a kept-alive
	// connection between requests (0 means DefaultIdleTimeout).
	ReadTimeout, WriteTimeout, IdleTimeout time.Duration
	// AccessLogs logs every request at INFO.
	AccessLogs bool
	// Log receives failures and access logs.
	Log *logrus.Logger
	// Registerer receives the connection metrics; nil leaves them
	// unregistered.
	Registerer prometheus.Registerer
}

// Server is the API listener.
type Server struct {
	cfg     Config
	log     logrus.FieldLogger
	hosts   hostAllowlist
	gate    *bodyGate
	handler http.Handler
	metrics *connMetrics

	http     *http.Server
	listener net.Listener
	errLog   interface{ Close() error }

	inflight     atomic.Int64 // handlers running
	drainTimeout time.Duration
}

// New builds the server. It does not listen yet.
func New(cfg Config) (*Server, error) {
	if cfg.Auth == nil {
		return nil, errors.New("server: no authenticator")
	}
	if cfg.Ready == nil {
		cfg.Ready = func() bool { return true }
	}
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = DefaultMaxConnections
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = DefaultIdleTimeout
	}
	if cfg.ReadTimeout <= 0 {
		cfg.ReadTimeout = MinRequestTimeout
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = MinRequestTimeout
	}
	if cfg.Log == nil {
		cfg.Log = logrus.New()
	}
	m, err := newConnMetrics(cfg.Registerer)
	if err != nil {
		return nil, fmt.Errorf("server: register metrics: %w", err)
	}
	s := &Server{
		cfg:     cfg,
		log:     cfg.Log,
		hosts:   newHostAllowlist(cfg.HostAllowlist),
		gate:    newBodyGate(cfg.LargeBodySlots),
		metrics: m,

		drainTimeout: HandlerDrainTimeout,
	}
	mux, err := s.newMux(cfg.Routes)
	if err != nil {
		return nil, err
	}
	s.handler = s.track(s.accessLog(s.hostCheck(s.originCheck(mux))))

	errWriter := cfg.Log.WriterLevel(logrus.DebugLevel)
	s.errLog = errWriter
	s.http = &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    MaxHeaderBytes,
		ErrorLog:          log.New(errWriter, "", 0),
	}
	return s, nil
}

// Handler returns the full middleware chain, for in-process tests.
func (s *Server) Handler() http.Handler { return s.handler }

// Listen binds the listening socket.
func (s *Server) Listen() error {
	l, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("server: listen on %s: %w", s.cfg.Addr, err)
	}
	s.listener = newLimitListener(l, s.cfg.MaxConnections, s.metrics)
	return nil
}

// Addr returns the bound address; it is valid after Listen.
func (s *Server) Addr() *net.TCPAddr {
	return s.listener.Addr().(*net.TCPAddr)
}

// Serve serves on the bound socket until Shutdown. It returns nil after a
// clean shutdown.
func (s *Server) Serve() error {
	if s.listener == nil {
		return errors.New("server: Serve before Listen")
	}
	err := s.http.Serve(s.listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown stops accepting connections and waits, until ctx ends, for
// in-flight requests to complete. Connections still active then are closed,
// and Shutdown waits up to HandlerDrainTimeout more for their handlers to
// return, since closing a connection does not stop its handler. If some are
// still running, the error wraps ErrHandlersRunning.
func (s *Server) Shutdown(ctx context.Context) error {
	defer func() { _ = s.errLog.Close() }()
	err := s.http.Shutdown(ctx)
	if err != nil {
		_ = s.http.Close()
	}
	if !s.drain(s.drainTimeout) {
		err = errors.Join(err, ErrHandlersRunning)
	}
	return err
}

// track counts the handlers running, for Shutdown.
func (s *Server) track(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.inflight.Add(1)
		defer s.inflight.Add(-1)
		next.ServeHTTP(w, r)
	})
}

// drain waits up to d for every handler to return, and reports whether
// they all did.
func (s *Server) drain(d time.Duration) bool {
	deadline := time.Now().Add(d)
	for s.inflight.Load() > 0 {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
	return true
}
