// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/secretfile"
)

// ErrRedirect is the error of a store response that redirects: no store
// client follows redirects, so that a credential is only ever sent to the
// configured endpoint.
var ErrRedirect = errors.New("the store answered with a redirect, which is not followed; configure the endpoint " +
	"the redirect points to")

// HTTPOptions configure a store's HTTP client.
type HTTPOptions struct {
	// Timeout bounds each request, from dialling to reading the body.
	Timeout time.Duration
	// TLS is the client's TLS configuration; nil is Go's default.
	TLS *tls.Config
	// HTTP1Only turns HTTP/2 off.
	HTTP1Only bool
}

// HTTPClient returns an HTTP client for a store: each request has a
// timeout, no redirect is followed, and a response body larger than
// MaxResponseSize fails to read. Proxies come from the environment
// (HTTPS_PROXY, NO_PROXY), as Go and the cloud SDKs default to.
func HTTPClient(o HTTPOptions) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	if o.TLS != nil {
		t.TLSClientConfig = o.TLS
	}
	if o.HTTP1Only {
		t.Protocols = new(http.Protocols)
		t.Protocols.SetHTTP1(true)
		t.ForceAttemptHTTP2 = false
	}
	return &http.Client{
		Transport:     LimitTransport{Base: t, Max: MaxResponseSize},
		Timeout:       o.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrRedirect },
	}
}

// LimitTransport bounds the response bodies of Base: a body that declares
// or holds more than Max bytes fails with ErrTooLarge.
type LimitTransport struct {
	Base http.RoundTripper
	Max  int64
}

// RoundTrip implements http.RoundTripper.
func (l LimitTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := l.Base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	if resp.ContentLength > l.Max {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("store response: %w: %d bytes, more than %d", ErrTooLarge, resp.ContentLength, l.Max)
	}
	resp.Body = &limitedBody{rc: resp.Body, max: l.Max, left: l.Max}
	return resp, nil
}

// limitedBody fails once more than max bytes have been read.
type limitedBody struct {
	rc        io.ReadCloser
	max, left int64
}

func (b *limitedBody) Read(p []byte) (int, error) {
	if b.left < 0 {
		return 0, b.tooLarge()
	}
	if int64(len(p)) > b.left+1 {
		p = p[:b.left+1]
	}
	n, err := b.rc.Read(p)
	b.left -= int64(n)
	if b.left < 0 {
		return n, b.tooLarge()
	}
	return n, err
}

func (b *limitedBody) tooLarge() error {
	return fmt.Errorf("store response: %w: more than %d bytes", ErrTooLarge, b.max)
}

func (b *limitedBody) Close() error { return b.rc.Close() }

// ReadBody reads a response body into one buffer sized from its declared
// length, at most max bytes, so that no copy of a secret is left behind by
// a growing buffer. The caller wipes the result.
func ReadBody(resp *http.Response, max int64) ([]byte, error) {
	limit := max
	if resp.ContentLength >= 0 && resp.ContentLength < max {
		limit = resp.ContentLength
	}
	b, err := secretfile.ReadLimited(resp.Body, limit)
	if errors.Is(err, secretfile.ErrTooLarge) {
		if limit < max {
			return nil, errors.New("store response: longer than its Content-Length")
		}
		return nil, fmt.Errorf("store response: %w: more than %d bytes", ErrTooLarge, max)
	}
	return b, err
}
