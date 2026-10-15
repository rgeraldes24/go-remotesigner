// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/server/auth"
)

// Route is one API endpoint.
type Route struct {
	// Method is GET, POST or DELETE. A GET route also answers HEAD.
	Method string
	// Pattern is a net/http ServeMux path pattern without a method, such as
	// "/upcheck" or "/api/v1/consensus/sign/{identifier}".
	Pattern string
	// Scope is the credential the route requires.
	Scope auth.Scope
	// BodyLimit is the largest body accepted; 0 means DefaultBodyLimit.
	BodyLimit int64
	// ReadsBody is set when the handler reads the body itself, with
	// ReadBody. Otherwise the body is read and discarded before the handler
	// runs.
	ReadsBody bool
	// NeedsReady makes the route answer 503 NOT_READY until the server is
	// ready.
	NeedsReady bool
	// WriteTimeout, when positive, replaces the server's write timeout.
	WriteTimeout time.Duration
	Handler      http.Handler
}

func (rt *Route) bodyLimit() int64 {
	if rt.BodyLimit > 0 {
		return rt.BodyLimit
	}
	return DefaultBodyLimit
}

// methods dispatches one path pattern by method, answering 405 with an
// Allow header for a method no route registers.
type methods struct {
	s      *Server
	byName map[string]http.Handler
	allow  string
}

func (m *methods) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	method := r.Method
	if method == http.MethodHead {
		method = http.MethodGet
	}
	h, ok := m.byName[method]
	if !ok {
		w.Header().Set("Allow", m.allow)
		writePlainError(w, m.s.log, r, http.StatusMethodNotAllowed)
		return
	}
	h.ServeHTTP(w, r)
}

// newMux builds the router. An unknown path is a JSON 404.
func (s *Server) newMux(routes []Route) (*http.ServeMux, error) {
	byPattern := map[string]*methods{}
	var order []string
	for i := range routes {
		rt := &routes[i]
		switch rt.Method {
		case http.MethodGet, http.MethodPost, http.MethodDelete:
		default:
			return nil, fmt.Errorf("server: route %s: unsupported method %q", rt.Pattern, rt.Method)
		}
		if rt.Handler == nil || !strings.HasPrefix(rt.Pattern, "/") || strings.ContainsAny(rt.Pattern, " \t") {
			return nil, fmt.Errorf("server: route %q %q: need a handler and a path pattern", rt.Method, rt.Pattern)
		}
		if rt.Scope == auth.ScopeAdmin && !s.cfg.Auth.HasAdmin() {
			return nil, fmt.Errorf("server: admin route %s %s needs an admin token", rt.Method, rt.Pattern)
		}
		m, ok := byPattern[rt.Pattern]
		if !ok {
			m = &methods{s: s, byName: map[string]http.Handler{}}
			byPattern[rt.Pattern] = m
			order = append(order, rt.Pattern)
		}
		if _, dup := m.byName[rt.Method]; dup {
			return nil, fmt.Errorf("server: duplicate route %s %s", rt.Method, rt.Pattern)
		}
		m.byName[rt.Method] = s.routeChain(rt)
	}

	mux := http.NewServeMux()
	for _, p := range order {
		m := byPattern[p]
		names := make([]string, 0, len(m.byName)+1)
		for name := range m.byName {
			names = append(names, name)
			if name == http.MethodGet {
				names = append(names, http.MethodHead)
			}
		}
		slices.Sort(names)
		m.allow = strings.Join(names, ", ")
		mux.Handle(p, m)
	}
	if _, ok := byPattern["/"]; !ok {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			writePlainError(w, s.log, r, http.StatusNotFound)
		})
	}
	return mux, nil
}
