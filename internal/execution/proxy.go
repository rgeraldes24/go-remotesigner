// Copyright 2019 ConsenSys AG.
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
// core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/PassThroughHandler.java,
// core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/HeaderHelpers.java,
// core/src/main/java/tech/pegasys/web3signer/core/service/VertxRequestTransmitter.java and
// core/src/main/java/tech/pegasys/web3signer/core/service/ForwardedMessageResponder.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

//go:build !noexecution

package execution

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

// forwardedHeaders are the only client headers the downstream node sees.
// Credentials (Authorization, Cookie, Proxy-*), forwarding headers
// (Forwarded, X-Forwarded-*) and everything else stay with the signer;
// the signer's own downstream credentials replace them.
var forwardedHeaders = []string{"Content-Type", "Accept", "User-Agent"}

// errResponseTooLarge stops a downstream response at MaxResponseSize.
var errResponseTooLarge = errors.New("downstream response over the size limit")

// proxy forwards single requests with httputil.ReverseProxy and exchanges
// the forwarded part of a batch.
type proxy struct {
	ds  *downstream
	rp  *httputil.ReverseProxy
	log logrus.FieldLogger
}

// requestKey carries the JSON-RPC request into the proxy's error handler.
type requestKey struct{}

// newProxy builds the proxy. Its error log goes to logger at DEBUG; the
// writer is closed with closeLog.
func newProxy(ds *downstream, logger *logrus.Logger) (p *proxy, closeLog func()) {
	w := logger.WriterLevel(logrus.DebugLevel)
	p = &proxy{ds: ds, log: logger}
	p.rp = &httputil.ReverseProxy{
		Rewrite:        p.rewrite,
		Transport:      ds.transport,
		ModifyResponse: modifyResponse,
		ErrorHandler:   p.errorHandler,
		ErrorLog:       log.New(w, "", 0),
	}
	return p, func() { _ = w.Close() }
}

// rewrite points the request at the downstream node, Host included, and
// replaces its headers with the forwarded ones and the signer's own
// downstream credentials. The path and query of the client's request are
// not used.
func (p *proxy) rewrite(pr *httputil.ProxyRequest) {
	pr.Out.URL.Scheme = p.ds.target.Scheme
	pr.Out.URL.Host = p.ds.target.Host
	pr.Out.URL.Path, pr.Out.URL.RawPath, pr.Out.URL.RawQuery = p.ds.target.Path, "", ""
	pr.Out.Host = p.ds.target.Host
	pr.Out.Header = p.outHeader(pr.In.Header)
}

// outHeader builds the downstream request's headers from the client's.
func (p *proxy) outHeader(in http.Header) http.Header {
	h := http.Header{}
	for _, name := range forwardedHeaders {
		if v, ok := in[name]; ok {
			h[name] = append([]string(nil), v...)
		}
	}
	if p.ds.auth != nil {
		h.Set("Authorization", string(p.ds.auth))
	}
	return h
}

// modifyResponse drops the downstream's cookies and CORS headers, and caps
// the body at MaxResponseSize.
func modifyResponse(resp *http.Response) error {
	resp.Header.Del("Set-Cookie")
	for name := range resp.Header {
		if strings.HasPrefix(http.CanonicalHeaderKey(name), "Access-Control-") {
			delete(resp.Header, name)
		}
	}
	if resp.ContentLength > MaxResponseSize {
		return errResponseTooLarge
	}
	resp.Body = &cappedBody{ReadCloser: resp.Body, left: MaxResponseSize}
	return nil
}

// cappedBody fails a read once more than its limit has been read. A
// response cut off there never reaches the client whole: ReverseProxy
// aborts the connection.
type cappedBody struct {
	io.ReadCloser
	left int64
}

func (b *cappedBody) Read(p []byte) (int, error) {
	if b.left < 0 {
		return 0, errResponseTooLarge
	}
	if int64(len(p)) > b.left+1 {
		p = p[:b.left+1]
	}
	n, err := b.ReadCloser.Read(p)
	b.left -= int64(n)
	if b.left < 0 {
		return 0, errResponseTooLarge
	}
	return n, err
}

// forward proxies one request whose body has been read and decoded.
func (p *proxy) forward(w http.ResponseWriter, r *http.Request, req *Request, body []byte) {
	r = r.WithContext(context.WithValue(r.Context(), requestKey{}, req))
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	p.rp.ServeHTTP(w, r)
}

// errorHandler answers a request the proxy could not forward with a
// JSON-RPC error, as Web3Signer does: 504 when the node cannot be reached
// or does not answer in time, 502 for a TLS failure or an oversized
// response, 500 otherwise.
func (p *proxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	req, _ := r.Context().Value(requestKey{}).(*Request)
	status, e := classify(err)
	p.log.WithFields(logrus.Fields{"method": methodOf(req), "status": status}).WithError(err).
		Warn("Forwarding to the downstream node failed")
	writeResponse(w, status, encodeResult(req.responseID(), nil, e))
}

// classify maps a transport error to the status and JSON-RPC error of the
// response.
func classify(err error) (int, *Error) {
	var (
		netErr   net.Error
		opErr    *net.OpError
		unknown  x509.UnknownAuthorityError
		invalid  x509.CertificateInvalidError
		hostname x509.HostnameError
		verify   *tls.CertificateVerificationError
		record   tls.RecordHeaderError
		alert    tls.AlertError
	)
	switch {
	case errors.Is(err, errResponseTooLarge):
		return http.StatusBadGateway, ErrDownstreamResponse.with("response over 25 MB")
	case errors.As(err, &verify), errors.As(err, &unknown), errors.As(err, &invalid), errors.As(err, &hostname),
		errors.As(err, &record), errors.As(err, &alert):
		return http.StatusBadGateway, ErrDownstreamConnect
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return http.StatusGatewayTimeout, ErrDownstreamTimeout
	case errors.As(err, &opErr) && opErr.Op == "dial", errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return http.StatusGatewayTimeout, ErrDownstreamConnect
	default:
		return http.StatusInternalServerError, ErrInternal
	}
}

// exchange posts a batch of forwarded requests to the downstream node, with
// the same header rules as forward, and returns the response body. Only a
// 200 response within MaxResponseSize is a response; redirects are not
// followed.
func (p *proxy) exchange(ctx context.Context, in *http.Request, body []byte) ([]byte, *Error) {
	out, err := http.NewRequestWithContext(ctx, http.MethodPost, p.ds.target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, ErrInternal
	}
	out.Header = p.outHeader(in.Header)
	out.Header.Set("Content-Type", "application/json")
	if _, ok := out.Header["User-Agent"]; !ok {
		out.Header.Set("User-Agent", "") // not Go's default
	}
	resp, err := p.ds.transport.RoundTrip(out) // one round trip: no redirect is followed
	if err != nil {
		_, e := classify(err)
		p.log.WithError(err).Warn("Forwarding a batch to the downstream node failed")
		return nil, e
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, ErrDownstreamResponse.with("status " + strconv.Itoa(resp.StatusCode))
	}
	if resp.ContentLength > MaxResponseSize {
		return nil, ErrDownstreamResponse.with("response over 25 MB")
	}
	data, err := io.ReadAll(&cappedBody{ReadCloser: resp.Body, left: MaxResponseSize})
	if err != nil {
		_, e := classify(err)
		return nil, e
	}
	return data, nil
}

func methodOf(req *Request) string {
	if req == nil {
		return "-"
	}
	return req.Method
}

// writeResponse writes a JSON-RPC response body.
func writeResponse(w http.ResponseWriter, status int, body []byte) {
	h := w.Header()
	h.Set("Content-Type", contentTypeJSON)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// contentTypeJSON is the Content-Type of the signer's own responses.
const contentTypeJSON = "application/json"
