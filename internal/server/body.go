// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
	"github.com/rgeraldes24/go-remotesigner/internal/server/auth"
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
// with it the memory they occupy. A request to an authenticated route counts
// as large when its Content-Length exceeds LargeBodyThreshold or is unknown
// (a chunked HTTP/1.1 body, or HTTP/2 without content-length), and also once
// more than LargeBodyThreshold bytes of its body have actually been read.
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

// gatedBody takes a slot once its body goes past LargeBodyThreshold bytes
// actually read. Without a slot it never reads past the threshold: a read is
// capped there, and at the threshold one byte is read to learn whether the
// body goes on before the slot is taken. A body of exactly the threshold
// therefore needs no slot.
type gatedBody struct {
	io.ReadCloser
	ctx    context.Context
	ticket *ticket
	read   int64
}

func (b *gatedBody) Read(p []byte) (int, error) {
	if b.ticket.held || len(p) == 0 {
		return b.count(b.ReadCloser.Read(p))
	}
	if rem := LargeBodyThreshold - b.read; rem > 0 {
		return b.count(b.ReadCloser.Read(p[:min(int64(len(p)), rem)]))
	}
	n, err := b.count(b.ReadCloser.Read(p[:1]))
	if n == 0 {
		return 0, err
	}
	if aerr := b.ticket.acquire(b.ctx); aerr != nil {
		return 0, aerr
	}
	return n, err
}

func (b *gatedBody) count(n int, err error) (int, error) {
	b.read += int64(n)
	return n, err
}

// limitBody enforces the route's body limit and the large-body gate, and,
// for a route that takes no body, reads and discards the body (at most the
// limit) before the handler runs.
//
// A route that needs no credential never takes a slot: anyone who passes
// the host check reaches it, so gating it would let an unauthenticated
// client hold every slot with slow chunked bodies. Its body limit, which
// newMux keeps at or under LargeBodyThreshold, bounds its memory instead.
func (s *Server) limitBody(rt *Route, next http.Handler) http.Handler {
	limit := rt.bodyLimit()
	gated := rt.Scope != auth.ScopeNone
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > limit {
			WriteError(w, s.log, r, apierr.New(apierr.BodyTooLarge, "Content-Length over the route limit"))
			return
		}
		if r.Body == nil || r.Body == http.NoBody {
			next.ServeHTTP(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		if gated {
			t := &ticket{gate: s.gate}
			defer t.release()
			if r.ContentLength > LargeBodyThreshold || r.ContentLength < 0 {
				if err := t.acquire(r.Context()); err != nil {
					return // the client went away while waiting
				}
			}
			r.Body = &gatedBody{ReadCloser: r.Body, ctx: r.Context(), ticket: t}
		}
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
