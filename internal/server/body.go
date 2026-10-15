// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
)

// Body limits (docs/contract.md section 13).
const (
	// DefaultBodyLimit applies to routes that take no body: GETs and /reload.
	DefaultBodyLimit = 4 << 10
	// LargeBodyThreshold: a body above it, or of unknown length, needs a
	// large-body slot.
	LargeBodyThreshold = 64 << 10
	// DefaultLargeBodySlots is the number of large bodies read at once.
	DefaultLargeBodySlots = 8
)

// bodyGate bounds the number of large request bodies being read at once, and
// with it the memory they occupy. A request counts as large when its
// Content-Length exceeds LargeBodyThreshold or is unknown (a chunked HTTP/1.1
// body, or HTTP/2 without content-length), and also once more than
// LargeBodyThreshold bytes of its body have actually been read.
type bodyGate struct {
	slots chan struct{}
}

func newBodyGate(n int) *bodyGate {
	if n <= 0 {
		n = DefaultLargeBodySlots
	}
	return &bodyGate{slots: make(chan struct{}, n)}
}

// ticket is one request's claim on the gate.
type ticket struct {
	gate *bodyGate
	held bool
}

// acquire waits for a slot, or for ctx to end.
func (t *ticket) acquire(ctx context.Context) error {
	if t.held {
		return nil
	}
	select {
	case t.gate.slots <- struct{}{}:
		t.held = true
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *ticket) release() {
	if t.held {
		<-t.gate.slots
		t.held = false
	}
}

// gatedBody takes a slot before a read could cross LargeBodyThreshold.
type gatedBody struct {
	io.ReadCloser
	ctx    context.Context
	ticket *ticket
	read   int64
}

func (b *gatedBody) Read(p []byte) (int, error) {
	if !b.ticket.held && b.read+int64(len(p)) > LargeBodyThreshold {
		if err := b.ticket.acquire(b.ctx); err != nil {
			return 0, err
		}
	}
	n, err := b.ReadCloser.Read(p)
	b.read += int64(n)
	return n, err
}

// limitBody enforces the route's body limit and the large-body gate, and,
// for a route that takes no body, reads and discards the body (at most the
// limit) before the handler runs.
func (s *Server) limitBody(rt *Route, next http.Handler) http.Handler {
	limit := rt.bodyLimit()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > limit {
			WriteError(w, s.log, r, apierr.New(apierr.BodyTooLarge, "Content-Length over the route limit"))
			return
		}
		if r.Body == nil || r.Body == http.NoBody {
			next.ServeHTTP(w, r)
			return
		}
		t := &ticket{gate: s.gate}
		defer t.release()
		if r.ContentLength > LargeBodyThreshold || r.ContentLength < 0 {
			if err := t.acquire(r.Context()); err != nil {
				return // the client went away while waiting
			}
		}
		r.Body = &gatedBody{ReadCloser: http.MaxBytesReader(w, r.Body, limit), ctx: r.Context(), ticket: t}
		if !rt.ReadsBody {
			if _, e := ReadBody(r); e != nil {
				WriteError(w, s.log, r, e)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ReadBody reads the whole request body within the route's limit. A body
// over the limit is 413 BODY_TOO_LARGE; a body that cannot be read to the
// end (the client stopped sending, or a read timeout) is 400 MALFORMED_JSON.
func ReadBody(r *http.Request) ([]byte, *apierr.Error) {
	data, err := io.ReadAll(r.Body)
	var tooLarge *http.MaxBytesError
	switch {
	case err == nil:
		return data, nil
	case errors.As(err, &tooLarge):
		return nil, apierr.New(apierr.BodyTooLarge, "body over the route limit")
	default:
		return nil, apierr.New(apierr.MalformedJSON, "body could not be read")
	}
}
