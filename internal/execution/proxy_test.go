// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package execution

import (
	"bufio"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secretfile"
)

// clientHeaders are what a client sends: credentials, cookies, proxy and
// forwarding headers, and the three that are forwarded.
func clientHeaders() http.Header {
	return http.Header{
		"Authorization":       {"Bearer 0xclienttoken"},
		"Cookie":              {"session=secret"},
		"Proxy-Authorization": {"Basic cHJveHk6cHc="},
		"Proxy-Connection":    {"keep-alive"},
		"Forwarded":           {"for=192.0.2.60;proto=http;by=203.0.113.43"},
		"X-Forwarded-For":     {"192.0.2.60"},
		"X-Forwarded-Host":    {"evil.example"},
		"X-Forwarded-Proto":   {"https"},
		"X-Real-Ip":           {"192.0.2.60"},
		"X-Custom":            {"anything"},
		"Accept":              {"application/json"},
		"User-Agent":          {"qrl-wallet/1.0"},
	}
}

// transportHeaders are what Go's transport adds on its own.
var transportHeaders = map[string]bool{"Accept-Encoding": true, "Content-Length": true}

// Only Content-Type, Accept and User-Agent reach the node, with the
// signer's own downstream credential in place of the client's; the node
// sees its own host in Host. This holds for single requests and batches.
func TestProxyRequestHeaders(t *testing.T) {
	nd := newNode(t)
	d := downstreamOf(t, nd.Server)
	authFile := filepath.Join(t.TempDir(), "downstream-auth")
	if err := os.WriteFile(authFile, []byte("Bearer node-credential\nignored second line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d.AuthHeaderFile = authFile
	f := newFixtureWith(t, 1, defaultAllow, d, nd)

	f.post(call(1, "qrl_blockNumber"), clientHeaders())
	f.post(batch(call(1, "qrl_blockNumber"), call(2, MethodHealthStatus)), clientHeaders())
	got := nd.received()
	if len(got) != 2 {
		t.Fatalf("the node received %d requests", len(got))
	}
	host := strings.TrimPrefix(nd.URL, "http://")
	for i, r := range got {
		for name := range r.header {
			switch {
			case transportHeaders[name]:
			case name == "Content-Type" || name == "Accept" || name == "User-Agent" || name == "Authorization":
			default:
				t.Errorf("request %d: header %s reached the node", i, name)
			}
		}
		if a := r.header.Get("Authorization"); a != "Bearer node-credential" {
			t.Errorf("request %d: Authorization %q, want the downstream credential", i, a)
		}
		if r.header.Get("Cookie") != "" || r.header.Get("X-Forwarded-For") != "" {
			t.Errorf("request %d: client cookie or forwarding header reached the node", i)
		}
		if r.header.Get("Accept") != "application/json" || r.header.Get("User-Agent") != "qrl-wallet/1.0" ||
			!strings.HasPrefix(r.header.Get("Content-Type"), "application/json") {
			t.Errorf("request %d: forwarded headers %v", i, r.header)
		}
		if r.host != host {
			t.Errorf("request %d: Host %q, want the node's %q", i, r.host, host)
		}
	}

	// Without a downstream credential no Authorization header is sent at
	// all, and Go's default User-Agent is not added.
	g := newFixture(t, 0, defaultAllow)
	h := clientHeaders()
	delete(h, "User-Agent")
	g.post(call(1, "qrl_blockNumber"), h)
	g.post(batch(call(1, "qrl_blockNumber")), h)
	for _, r := range g.node.received() {
		if _, ok := r.header["Authorization"]; ok {
			t.Error("the client's Authorization reached the node")
		}
		if ua := r.header.Get("User-Agent"); ua != "" {
			t.Errorf("User-Agent %q reached the node", ua)
		}
	}
}

// Nor do they reach it as trailers of a chunked request: the node gets the
// signer's body with its length, and no trailer. This holds for single
// requests and batches.
func TestProxyRequestTrailers(t *testing.T) {
	f := newFixture(t, 0, defaultAllow)
	srv := httptest.NewServer(f.handler)
	defer srv.Close()
	for _, body := range []string{call(1, "qrl_blockNumber"), batch(call(1, "qrl_blockNumber"))} {
		c, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fmt.Fprintf(c, "POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"+
			"Transfer-Encoding: chunked\r\nTrailer: Authorization, Cookie, X-Forwarded-For\r\n\r\n"+
			"%x\r\n%s\r\n0\r\nAuthorization: Bearer 0xclienttoken\r\nCookie: session=secret\r\n"+
			"X-Forwarded-For: 192.0.2.60\r\n\r\n", len(body), body)
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		_ = c.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %v %v", body, resp, err)
		}
	}
	got := f.node.received()
	if len(got) != 2 {
		t.Fatalf("the node received %d requests", len(got))
	}
	for i, r := range got {
		if len(r.trailer) != 0 || len(r.transferEncoding) != 0 || r.contentLength != int64(len(r.body)) {
			t.Errorf("request %d: trailer %v, transfer encoding %v, length %d for %d bytes", i, r.trailer,
				r.transferEncoding, r.contentLength, len(r.body))
		}
		if r.header.Get("Authorization") != "" || r.header.Get("Cookie") != "" || r.header.Get("X-Forwarded-For") != "" {
			t.Errorf("request %d: headers %v", i, r.header)
		}
	}
}

// The node's Set-Cookie and Access-Control-* headers never reach the
// client; its other headers and its status do.
func TestProxyResponseHeaders(t *testing.T) {
	f := newFixture(t, 0, defaultAllow)
	f.node.setHandler(func(w http.ResponseWriter, _ *http.Request) {
		h := w.Header()
		h.Add("Set-Cookie", "a=b")
		h.Add("Set-Cookie", "c=d")
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Credentials", "true")
		h.Set("access-control-expose-headers", "X")
		h.Add("Random", "firstValue")
		h.Add("Random", "secondValue")
		h.Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x1"}`))
	})
	w := f.post(call(1, "qrl_blockNumber"), nil)
	if w.Code != http.StatusTeapot || w.Body.String() != `{"jsonrpc":"2.0","id":1,"result":"0x1"}` {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	for name := range w.Header() {
		if name == "Set-Cookie" || strings.HasPrefix(name, "Access-Control-") {
			t.Errorf("header %s reached the client", name)
		}
	}
	if got := w.Header().Values("Random"); len(got) != 2 {
		t.Errorf("multi-value header: %v", got)
	}
}

// Nor do they reach it another way: the node's interim (1xx) responses are
// not relayed, and its trailers, announced or not, are not passed back.
func TestProxyDropsInterimResponsesAndTrailers(t *testing.T) {
	f := newFixture(t, 0, defaultAllow)
	f.node.setHandler(func(w http.ResponseWriter, _ *http.Request) {
		h := w.Header()
		h.Set("Set-Cookie", "early=1")
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Link", "</a.css>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints)
		clear(h)
		h.Set("Trailer", "Set-Cookie, Access-Control-Allow-Origin")
		h.Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x1"}`))
		h.Set("Set-Cookie", "trailer=1")
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set(http.TrailerPrefix+"X-Unannounced", "x")
	})
	srv := httptest.NewServer(f.handler)
	defer srv.Close()

	var (
		mu      sync.Mutex
		interim []textproto.MIMEHeader
	)
	trace := &httptrace.ClientTrace{Got1xxResponse: func(_ int, h textproto.MIMEHeader) error {
		mu.Lock()
		defer mu.Unlock()
		interim = append(interim, h)
		return nil
	}}
	ctx := httptrace.WithClientTrace(context.Background(), trace)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, strings.NewReader(call(1, "qrl_blockNumber")))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || string(body) != `{"jsonrpc":"2.0","id":1,"result":"0x1"}` {
		t.Fatalf("%d %q %v", resp.StatusCode, body, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(interim) != 0 {
		t.Errorf("an interim response reached the client: %v", interim)
	}
	if len(resp.Trailer) != 0 {
		t.Errorf("trailers reached the client: %v", resp.Trailer)
	}
	for name := range resp.Header {
		if name == "Set-Cookie" || name == "Trailer" || strings.HasPrefix(name, "Access-Control-") {
			t.Errorf("header %s reached the client", name)
		}
	}
}

// A client cannot open a tunnel to the node: its Upgrade header is not
// forwarded, and a 101 from the node is refused rather than relayed.
func TestProxyRefusesUpgrades(t *testing.T) {
	f := newFixture(t, 0, defaultAllow)
	f.node.setHandler(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Upgrade", "websocket")
		w.WriteHeader(http.StatusSwitchingProtocols)
	})
	srv := httptest.NewServer(f.handler)
	defer srv.Close()
	c, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	body := call(1, "qrl_blockNumber")
	_, _ = fmt.Fprintf(c, "POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nConnection: Upgrade\r\n"+
		"Upgrade: websocket\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode == http.StatusSwitchingProtocols {
		t.Fatal("a 101 from the node reached the client")
	}
	for _, r := range f.node.received() {
		if r.header.Get("Upgrade") != "" || r.header.Get("Connection") != "" {
			t.Fatalf("the node received %v", r.header)
		}
	}
}

// A redirect from the node is passed back as it is, and nothing follows
// it: the redirect target sees no request.
func TestProxyFollowsNoRedirects(t *testing.T) {
	var metadataHits atomic.Int32
	metadata := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		metadataHits.Add(1)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"stolen"}`))
	}))
	defer metadata.Close()
	f := newFixture(t, 1, defaultAllow)
	f.node.setHandler(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, metadata.URL+"/latest/meta-data/", http.StatusFound)
	})
	w := f.post(call(1, "qrl_blockNumber"), nil)
	if w.Code != http.StatusFound || w.Header().Get("Location") != metadata.URL+"/latest/meta-data/" {
		t.Fatalf("single request: %d %v", w.Code, w.Header())
	}
	rs := decodeBatch(t, f.post(batch(call(1, "qrl_blockNumber")), nil).Body.Bytes())
	if len(rs) != 1 || rs[0].Error == nil || rs[0].Error.Data != "status 302" {
		t.Fatalf("batch: %+v", rs)
	}
	if n := metadataHits.Load(); n != 0 {
		t.Fatalf("the redirect target was requested %d times", n)
	}
	if n := len(f.node.received()); n != 2 {
		t.Fatalf("the node received %d requests, want 2 (no retries)", n)
	}
}

// A response over 25 MB never reaches the client whole: with a
// Content-Length it is refused with 502, and a streamed one is cut off.
func TestProxyResponseLimit(t *testing.T) {
	big := strings.Repeat("a", MaxResponseSize)
	f := newFixture(t, 0, defaultAllow)

	f.node.setHandler(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(big)+1))
		_, _ = io.WriteString(w, big+"a")
	})
	w := f.post(call(1, "qrl_getLogs"), nil)
	if r := decodeOne(t, w.Body.Bytes()); w.Code != http.StatusBadGateway || r.Error == nil ||
		r.Error.Code != ErrDownstreamResponse.Code || string(r.ID) != "1" {
		t.Fatalf("with Content-Length: %d %.200s", w.Code, w.Body)
	}

	f.node.setHandler(func(w http.ResponseWriter, _ *http.Request) {
		w.(http.Flusher).Flush() // no Content-Length: chunked
		_, _ = io.WriteString(w, big)
		_, _ = io.WriteString(w, "overflow")
	})
	if rec := f.post(call(1, "qrl_getLogs"), nil); rec.Body.Len() > MaxResponseSize {
		t.Fatalf("a streamed response of %d bytes reached the client", rec.Body.Len())
	}
	rs := decodeBatch(t, f.post(batch(call(1, "qrl_getLogs")), nil).Body.Bytes())
	if len(rs) != 1 || rs[0].Error == nil || rs[0].Error.Code != ErrDownstreamResponse.Code {
		t.Fatalf("batch over the limit: %+v", rs)
	}

	// Exactly the limit passes.
	f.node.setHandler(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, big) })
	if rec := f.post(call(1, "qrl_getLogs"), nil); rec.Code != http.StatusOK || rec.Body.Len() != MaxResponseSize {
		t.Fatalf("a response of exactly the limit: %d, %d bytes", rec.Code, rec.Body.Len())
	}
}

// A node that cannot be reached is 504 "Failed to connect", one that does
// not answer in time 504 "timed out", as in Web3Signer.
func TestProxyDownstreamErrors(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := l.Addr().(*net.TCPAddr)
	_ = l.Close()
	d := config.Downstream{Host: "127.0.0.1", Port: uint16(closed.Port), Path: "/", Timeout: time.Second}
	f := newFixtureWith(t, 1, defaultAllow, d, nil)
	w := f.post(call(5, "qrl_blockNumber"), nil)
	if r := decodeOne(t, w.Body.Bytes()); w.Code != http.StatusGatewayTimeout || r.Error == nil ||
		r.Error.Message != ErrDownstreamConnect.Message || string(r.ID) != "5" {
		t.Fatalf("connection refused: %d %s", w.Code, w.Body)
	}
	rs := decodeBatch(t, f.post(batch(call(5, "qrl_blockNumber"), call(6, MethodHealthStatus)), nil).Body.Bytes())
	if rs[0].Error == nil || rs[0].Error.Message != ErrDownstreamConnect.Message || string(rs[1].Result) != `"OK"` {
		t.Fatalf("batch, connection refused: %+v", rs)
	}

	slow := newNode(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	slow.setHandler(func(http.ResponseWriter, *http.Request) { <-release })
	d = downstreamOf(t, slow.Server)
	d.Timeout = 100 * time.Millisecond
	g := newFixtureWith(t, 0, defaultAllow, d, slow)
	w = g.post(call("t", "qrl_blockNumber"), nil)
	if r := decodeOne(t, w.Body.Bytes()); w.Code != http.StatusGatewayTimeout || r.Error == nil ||
		r.Error.Message != ErrDownstreamTimeout.Message || string(r.ID) != `"t"` {
		t.Fatalf("timeout: %d %s", w.Code, w.Body)
	}
}

// within runs f and fails the test if it does not return within d.
func within(t *testing.T, d time.Duration, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %s", what, d)
	}
}

// A node that stops sending in the middle of its response is cut off once
// the downstream timeout passes without data, as Web3Signer's idle timeout
// does: a batch gets the timeout error in place of the forwarded answers,
// and its local answers still arrive.
func TestProxyStalledResponse(t *testing.T) {
	nd := newNode(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	nd.setHandler(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `[{"jsonrpc":"2.0",`)
		w.(http.Flusher).Flush()
		<-release
	})
	d := downstreamOf(t, nd.Server)
	d.Timeout = 200 * time.Millisecond
	f := newFixtureWith(t, 0, defaultAllow, d, nd)

	var w *httptest.ResponseRecorder
	within(t, 10*time.Second, "a batch", func() {
		w = f.post(batch(call(1, "qrl_blockNumber"), call(2, MethodHealthStatus)), nil)
	})
	rs := decodeBatch(t, w.Body.Bytes())
	if len(rs) != 2 || rs[0].Error == nil || rs[0].Error.Message != ErrDownstreamTimeout.Message ||
		string(rs[1].Result) != `"OK"` {
		t.Fatalf("batch: %s", w.Body)
	}
	within(t, 10*time.Second, "a single request", func() { w = f.post(call(1, "qrl_blockNumber"), nil) })
	if w.Body.String() != `[{"jsonrpc":"2.0",` {
		t.Fatalf("single request: %q", w.Body)
	}
}

// A node that keeps sending, too slowly to ever finish, is cut off at the
// request's deadline, the endpoint's write timeout.
func TestProxyRequestDeadline(t *testing.T) {
	nd := newNode(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	nd.setHandler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		for {
			_, _ = io.WriteString(w, " ")
			w.(http.Flusher).Flush()
			select {
			case <-release:
				return
			case <-r.Context().Done():
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	})
	f := newFixtureWith(t, 0, defaultAllow, downstreamOf(t, nd.Server), nd)
	if want := WriteTimeout(2 * time.Second); f.handler.deadline != want {
		t.Fatalf("deadline %s, want the write timeout %s", f.handler.deadline, want)
	}
	f.handler.deadline = 300 * time.Millisecond
	within(t, 10*time.Second, "a batch", func() { f.post(batch(call(1, "qrl_blockNumber")), nil) })
	within(t, 10*time.Second, "a single request", func() { f.post(call(1, "qrl_blockNumber"), nil) })
}

// --downstream-http-tls-enabled connects with https, against the system
// roots or --downstream-http-tls-ca-file.
func TestProxyTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(echo(body))
	}))
	defer srv.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	d := downstreamOf(t, srv)
	d.TLS = true
	untrusted := newFixtureWith(t, 0, defaultAllow, d, nil)
	if w := untrusted.post(call(1, "qrl_blockNumber"), nil); w.Code != http.StatusBadGateway {
		t.Fatalf("a certificate outside the system roots: %d %s", w.Code, w.Body)
	}
	d.TLSCAFile = ca
	trusted := newFixtureWith(t, 0, defaultAllow, d, nil)
	if r := decodeOne(t, trusted.post(call(1, "qrl_blockNumber"), nil).Body.Bytes()); string(r.Result) != `"node:qrl_blockNumber"` {
		t.Fatalf("with the CA file: %+v", r)
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	d.TLSCAFile = bad
	if _, err := newDownstream(d, secretfile.Policy{}); err == nil {
		t.Fatal("a CA file without a certificate was accepted")
	}
}

// --downstream-http-proxy-host sends requests through an HTTP proxy.
func TestProxyThroughHTTPProxy(t *testing.T) {
	var seen atomic.Value
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Store(r.URL.String())
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(echo(body))
	}))
	defer proxySrv.Close()
	pd := downstreamOf(t, proxySrv)
	d := config.Downstream{Host: "gqrl.internal", Port: 8545, Path: "/rpc", Timeout: time.Second,
		ProxyHost: pd.Host, ProxyPort: pd.Port}
	f := newFixtureWith(t, 0, defaultAllow, d, nil)
	if r := decodeOne(t, f.post(call(1, "qrl_blockNumber"), nil).Body.Bytes()); string(r.Result) != `"node:qrl_blockNumber"` {
		t.Fatalf("through the proxy: %+v", r)
	}
	if got, _ := seen.Load().(string); got != "http://gqrl.internal:8545/rpc" {
		t.Fatalf("the proxy saw %q", got)
	}
}

func TestAuthHeaderFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	strict := secretfile.Policy{Strict: true}
	for _, tt := range []struct {
		name, content string
		mode          os.FileMode
		ok            bool
	}{
		{"bearer", "Bearer abc\n", 0o600, true},
		{"crlf", "Basic dXNlcjpwdw==\r\n", 0o600, true},
		{"empty", "\n", 0o600, false},
		{"control character", "Bearer a\x00b\n", 0o600, false},
		{"group-readable", "Bearer abc\n", 0o640, false},
	} {
		_, err := readAuthHeader(write(tt.name, tt.content, tt.mode), strict)
		if (err == nil) != tt.ok {
			t.Errorf("%s: err = %v", tt.name, err)
		}
		if err != nil && strings.Contains(err.Error(), "abc") {
			t.Errorf("%s: the error shows the credential: %v", tt.name, err)
		}
	}
	if _, err := readAuthHeader(filepath.Join(dir, "missing"), strict); err == nil {
		t.Error("a missing file was accepted")
	}
}

func TestDownstreamPathCheck(t *testing.T) {
	for p, ok := range map[string]bool{
		"/": true, "/rpc": true, "rpc/v1": true, "": true,
		"/rpc?x=1": false, "/rpc#a": false, "/a%2fb": false, "http://x/": false, "//host/p": false, "/a;b": false,
	} {
		if err := CheckDownstreamPath(p); (err == nil) != ok {
			t.Errorf("CheckDownstreamPath(%q) = %v", p, err)
		}
	}
}

func TestClassify(t *testing.T) {
	for _, tt := range []struct {
		err    error
		status int
		e      *Error
	}{
		{errResponseTooLarge, http.StatusBadGateway, ErrDownstreamResponse},
		{&net.OpError{Op: "dial", Err: errors.New("refused")}, http.StatusGatewayTimeout, ErrDownstreamConnect},
		{io.ErrUnexpectedEOF, http.StatusGatewayTimeout, ErrDownstreamConnect},
		{errors.New("other"), http.StatusInternalServerError, ErrInternal},
	} {
		status, e := classify(tt.err)
		if status != tt.status || e.Message != tt.e.Message {
			t.Errorf("classify(%v) = %d %v", tt.err, status, e)
		}
	}
}
