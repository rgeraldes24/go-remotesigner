// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"mime"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
)

// The middleware runs in this order (docs/contract.md section 7, step 1):
//
//	access log → host allowlist → Origin refusal → auth → content type →
//	body limit → readiness → handler
//
// The router picks the route between the Origin refusal and auth, because
// the required scope is a property of the route, but it answers nothing
// itself before auth: a request that matches no path or method is
// authenticated first (Server.unrouted), so an unauthenticated caller gets
// 401, never 404 or 405.

// accessLog records every request after it completes, at INFO when access
// logs are enabled. It logs the route pattern, not the path.
func (s *Server) accessLog(next http.Handler) http.Handler {
	if !s.cfg.AccessLogs {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		s.log.WithFields(logrus.Fields{
			"method":   r.Method,
			"route":    routeOf(r),
			"status":   rec.status(),
			"duration": time.Since(start).String(),
			"remote":   r.RemoteAddr,
		}).Info("HTTP request")
	})
}

// hostCheck refuses a Host outside the allowlist with 403 HOST_NOT_ALLOWED.
func (s *Server) hostCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hosts.allows(r.Host) {
			WriteError(w, s.log, r, apierr.New(apierr.HostNotAllowed, "Host not in the allowlist"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// originCheck refuses any request that carries an Origin header with 403
// ORIGIN_NOT_ALLOWED. The API has no browser clients and offers no CORS.
func (s *Server) originCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Header["Origin"]; ok {
			WriteError(w, s.log, r, apierr.New(apierr.OriginNotAllowed, "request carries an Origin header"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// routeChain wraps a route's handler in the per-route middleware.
func (s *Server) routeChain(rt *Route) http.Handler {
	h := rt.Handler
	if rt.NeedsReady {
		h = s.readiness(h)
	}
	if rt.WriteTimeout > 0 {
		h = writeTimeout(rt.WriteTimeout, h)
	}
	h = s.limitBody(rt, h)
	if rt.Method == http.MethodPost {
		h = s.contentType(h)
	}
	return s.authenticate(rt, h)
}

func (s *Server) authenticate(rt *Route, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if e := s.cfg.Auth.Check(r, rt.Scope); e != nil {
			WriteError(w, s.log, r, e)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// contentType refuses a POST whose Content-Type is not application/json
// with 415 UNSUPPORTED_MEDIA_TYPE, even when the body is empty: a browser
// cannot send that type cross-site without a CORS preflight.
func (s *Server) contentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mt != "application/json" {
			WriteError(w, s.log, r, apierr.New(apierr.UnsupportedMediaType, "POST needs Content-Type application/json"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// readiness answers 503 NOT_READY until the first key load and the store
// open have finished.
func (s *Server) readiness(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.Ready() {
			WriteError(w, s.log, r, apierr.New(apierr.NotReady, "keys or store still loading"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// writeTimeout replaces the server's write deadline for one route, for
// responses that legitimately take longer (publicKeys at 21 MB).
func writeTimeout(d time.Duration, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(d))
		next.ServeHTTP(w, r)
	})
}

// statusRecorder captures the response status for the access log. It
// exposes the underlying writer to http.ResponseController.
type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.code == 0 {
		r.code = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.code == 0 {
		r.code = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (r *statusRecorder) status() int {
	if r.code == 0 {
		return http.StatusOK
	}
	return r.code
}
