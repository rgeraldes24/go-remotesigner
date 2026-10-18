// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package execution

import (
	"bufio"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
