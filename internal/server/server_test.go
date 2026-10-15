// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
	"github.com/rgeraldes24/go-remotesigner/internal/server/auth"
)

const (
	signTok  = "0x1111111111111111111111111111111111111111111111111111111111111111"
	adminTok = "0x2222222222222222222222222222222222222222222222222222222222222222"
)

func testAuth(t *testing.T, mode auth.Mode, admin bool) *auth.Authenticator {
	t.Helper()
	dir := t.TempDir()
	cfg := auth.Config{Mode: mode, SignTokenFile: filepath.Join(dir, "sign")}
	if err := os.WriteFile(cfg.SignTokenFile, []byte(signTok), 0o600); err != nil {
		t.Fatal(err)
	}
	if admin {
		cfg.AdminTokenFile = filepath.Join(dir, "admin")
		if err := os.WriteFile(cfg.AdminTokenFile, []byte(adminTok), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a, err := auth.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func quietLog() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l
}

func ok(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }

// testRoutes are a sign GET, a gated GET, an admin POST and a sign POST
// that reads up to 2 MiB.
func testRoutes(release <-chan struct{}) []Route {
	return []Route{
		{Method: http.MethodGet, Pattern: "/open", Scope: auth.ScopeNone, Handler: http.HandlerFunc(ok)},
		{Method: http.MethodGet, Pattern: "/sign", Scope: auth.ScopeSign, Handler: http.HandlerFunc(ok)},
		{Method: http.MethodGet, Pattern: "/gated", Scope: auth.ScopeSign, NeedsReady: true, Handler: http.HandlerFunc(ok)},
		{Method: http.MethodPost, Pattern: "/admin", Scope: auth.ScopeAdmin, Handler: http.HandlerFunc(ok)},
		{Method: http.MethodPost, Pattern: "/body/{identifier}", Scope: auth.ScopeSign, BodyLimit: 2 << 20, ReadsBody: true,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, e := ReadBody(r)
				if e != nil {
					WriteError(w, nil, r, e)
					return
				}
				if release != nil {
					<-release
				}
				_, _ = fmt.Fprintf(w, "%d", len(body))
			})},
	}
}

func newTestServer(t *testing.T, mutate func(*Config)) *Server {
	t.Helper()
	cfg := Config{
		Addr:          "127.0.0.1:0",
		HostAllowlist: []string{"localhost", "127.0.0.1", "::1"},
		Auth:          testAuth(t, auth.ModeToken, true),
		Routes:        testRoutes(nil),
		Log:           quietLog(),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type errResp struct {
	Code    int           `json:"code"`
	Message string        `json:"message"`
	Reason  apierr.Reason `json:"reason"`
}

func decodeErr(t *testing.T, rec *httptest.ResponseRecorder) errResp {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != ContentTypeJSON {
		t.Fatalf("Content-Type = %q, want %q", ct, ContentTypeJSON)
	}
	var e errResp
	dec := json.NewDecoder(rec.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		t.Fatal(err)
	}
	if e.Code != rec.Code {
		t.Fatalf("body code %d, status %d", e.Code, rec.Code)
	}
	return e
}

// The middleware refuses in the order access log, host, Origin, auth,
// content type, body limit (G4 S1, S4, S5).
func TestMiddlewareOrder(t *testing.T) {
	s := newTestServer(t, func(c *Config) { c.Ready = func() bool { return false } })
	tests := []struct {
		name    string
		method  string
		path    string
		host    string
		origin  string
		token   string
		ctype   string
		body    string
		status  int
		reason  apierr.Reason
		wwwAuth bool
	}{
		{name: "bad host first", method: "POST", path: "/admin", host: "evil.example", origin: "https://x", status: 403, reason: apierr.HostNotAllowed},
		{name: "origin before auth", method: "POST", path: "/admin", origin: "null", status: 403, reason: apierr.OriginNotAllowed},
		{name: "auth before content type", method: "POST", path: "/admin", ctype: "text/plain", status: 401, reason: apierr.Unauthenticated, wwwAuth: true},
		{name: "wrong token", method: "GET", path: "/sign", token: "0x" + strings.Repeat("9", 64), status: 401, reason: apierr.Unauthenticated, wwwAuth: true},
		{name: "sign token on admin route", method: "POST", path: "/admin", token: signTok, ctype: "application/json", status: 403, reason: apierr.ForbiddenScope},
		{name: "admin token on sign route", method: "GET", path: "/sign", token: adminTok, status: 401, reason: apierr.Unauthenticated, wwwAuth: true},
		{name: "content type before body limit", method: "POST", path: "/admin", token: adminTok, ctype: "text/plain", body: strings.Repeat("x", 5000), status: 415, reason: apierr.UnsupportedMediaType},
		{name: "missing content type", method: "POST", path: "/admin", token: adminTok, status: 415, reason: apierr.UnsupportedMediaType},
		{name: "body over the default limit", method: "POST", path: "/admin", token: adminTok, ctype: "application/json", body: strings.Repeat("x", DefaultBodyLimit+1), status: 413, reason: apierr.BodyTooLarge},
		{name: "readiness after auth", method: "GET", path: "/gated", token: signTok, status: 503, reason: apierr.NotReady},
		{name: "readiness needs auth first", method: "GET", path: "/gated", status: 401, reason: apierr.Unauthenticated, wwwAuth: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(tt.method, "http://localhost:9000"+tt.path, strings.NewReader(tt.body))
			if tt.host != "" {
				r.Host = tt.host
			}
			if tt.origin != "" {
				r.Header.Set("Origin", tt.origin)
			}
			if tt.token != "" {
				r.Header.Set("Authorization", "Bearer "+tt.token)
			}
			if tt.ctype != "" {
				r.Header.Set("Content-Type", tt.ctype)
			}
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, r)
			if rec.Code != tt.status {
				t.Fatalf("status %d, want %d (%s)", rec.Code, tt.status, rec.Body)
			}
			e := decodeErr(t, rec)
			if e.Reason != tt.reason || e.Message != tt.reason.Message() {
				t.Fatalf("body %+v, want reason %s with its fixed message", e, tt.reason)
			}
			if got := rec.Header().Get("WWW-Authenticate") == "Bearer"; got != tt.wwwAuth {
				t.Fatalf("WWW-Authenticate %q", rec.Header().Get("WWW-Authenticate"))
			}
			if tt.status == 503 && rec.Header().Get("Retry-After") == "" {
				t.Fatal("503 without Retry-After")
			}
		})
	}
}

func TestSuccessAndRouting(t *testing.T) {
	s := newTestServer(t, nil)
	do := func(method, path, tok, ctype, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://localhost:9000"+path, strings.NewReader(body))
		if tok != "" {
			r.Header.Set("Authorization", "Bearer "+tok)
		}
		if ctype != "" {
			r.Header.Set("Content-Type", ctype)
		}
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, r)
		return rec
	}
	if rec := do("GET", "/open", "", "", ""); rec.Code != 200 || rec.Body.String() != "ok" {
		t.Errorf("open route: %d %q", rec.Code, rec.Body)
	}
	if rec := do("HEAD", "/sign", signTok, "", ""); rec.Code != 200 {
		t.Errorf("HEAD on a GET route: %d", rec.Code)
	}
	if rec := do("GET", "/gated", signTok, "", ""); rec.Code != 200 {
		t.Errorf("gated route when ready: %d", rec.Code)
	}
	if rec := do("POST", "/admin", adminTok, "application/json; charset=utf-8", "{}"); rec.Code != 200 {
		t.Errorf("admin POST: %d %s", rec.Code, rec.Body)
	}
	if rec := do("POST", "/body/0x12", signTok, "application/json", strings.Repeat("a", 1<<20)); rec.Code != 200 || rec.Body.String() != "1048576" {
		t.Errorf("1 MiB body: %d %s", rec.Code, rec.Body)
	}
	if rec := do("POST", "/body/0x12", signTok, "application/json", strings.Repeat("a", 2<<20+1)); rec.Code != 413 {
		t.Errorf("2 MiB + 1 body: %d", rec.Code)
	}

	rec := do("GET", "/nope", signTok, "", "")
	if rec.Code != 404 {
		t.Fatalf("unknown path: %d", rec.Code)
	}
	if e := decodeErr(t, rec); e.Message != "Not Found" || e.Reason != "" {
		t.Errorf("unknown path body %+v", e)
	}
	rec = do("DELETE", "/sign", signTok, "", "")
	if rec.Code != 405 || rec.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("wrong method: %d, Allow %q", rec.Code, rec.Header().Get("Allow"))
	}
	if e := decodeErr(t, rec); e.Message != "Method Not Allowed" {
		t.Errorf("wrong method body %+v", e)
	}
}

func TestHostAllowlist(t *testing.T) {
	l := newHostAllowlist([]string{"localhost", "127.0.0.1", "::1", "Signer.Internal"})
	tests := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"LOCALHOST:9000", true},
		{"127.0.0.1:9000", true},
		{"[::1]:9000", true},
		{"[::1]", true},
		{"signer.internal:443", true},
		{"evil.example", false},
		{"localhost.evil.example", false},
		{"127.0.0.2", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := l.allows(tt.host); got != tt.want {
			t.Errorf("allows(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
	if !newHostAllowlist([]string{"*"}).allows("") {
		t.Error(`"*" refused a request without Host`)
	}
	if newHostAllowlist(nil).allows("localhost") {
		t.Error("an empty allowlist admitted a host")
	}
}

func TestAdminRouteNeedsAdminToken(t *testing.T) {
	_, err := New(Config{Auth: testAuth(t, auth.ModeToken, false), Routes: testRoutes(nil)})
	if err == nil || !strings.Contains(err.Error(), "admin token") {
		t.Fatalf("New = %v, want an admin-token error", err)
	}
	for _, routes := range [][]Route{
		{{Method: "POST", Pattern: "/x", Scope: auth.ScopeNone, BodyLimit: LargeBodyThreshold + 1, Handler: http.HandlerFunc(ok)}},
		{{Method: "PUT", Pattern: "/x", Handler: http.HandlerFunc(ok)}},
		{{Method: "GET", Pattern: "x", Handler: http.HandlerFunc(ok)}},
		{{Method: "GET", Pattern: "/x"}},
		{{Method: "GET", Pattern: "/x", Handler: http.HandlerFunc(ok)}, {Method: "GET", Pattern: "/x", Handler: http.HandlerFunc(ok)}},
	} {
		if _, err := New(Config{Auth: testAuth(t, auth.ModeToken, true), Routes: routes}); err == nil {
			t.Errorf("New accepted routes %+v", routes)
		}
	}
}

func TestTimeouts(t *testing.T) {
	tests := []struct {
		slot        uint64
		read, write time.Duration
	}{
		{6, 5 * time.Second, 5 * time.Second},
		{10, 5 * time.Second, 5 * time.Second},
		{60, 15 * time.Second, 20 * time.Second},
	}
	for _, tt := range tests {
		if r, w := ReadTimeout(tt.slot), WriteTimeout(tt.slot); r != tt.read || w != tt.write {
			t.Errorf("slot %d s: read %v write %v, want %v %v", tt.slot, r, w, tt.read, tt.write)
		}
	}
	s := newTestServer(t, nil)
	if s.http.MaxHeaderBytes != 64<<10 || s.http.ReadHeaderTimeout != 5*time.Second || s.http.IdleTimeout != 120*time.Second {
		t.Errorf("http.Server limits: %+v", s.http)
	}
}

// serve starts s on a loopback port and returns its base URL; the server is
// shut down when the test ends.
func serve(t *testing.T, s *Server) string {
	t.Helper()
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return "http://" + s.Addr().String()
}

func postChunked(url string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+signTok)
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = -1
	req.Host = "localhost"
	return http.DefaultClient.Do(req)
}

// A chunked body takes a large-body slot; with all 8 taken, the 9th waits
// until one is released (G4 S7).
func TestLargeBodyGateChunked(t *testing.T) {
	s := newTestServer(t, nil)
	base := serve(t, s)

	type held struct {
		w    *io.PipeWriter
		resp chan *http.Response
	}
	var hs []held
	for i := 0; i < DefaultLargeBodySlots; i++ {
		pr, pw := io.Pipe()
		h := held{w: pw, resp: make(chan *http.Response, 1)}
		go func() {
			resp, err := postChunked(base+"/body/0x01", pr)
			if err != nil {
				t.Error(err)
				close(h.resp)
				return
			}
			h.resp <- resp
		}()
		if _, err := pw.Write([]byte("{")); err != nil {
			t.Fatal(err)
		}
		hs = append(hs, h)
	}
	waitFor(t, func() bool { return len(s.gate.slots) == DefaultLargeBodySlots })

	ninth := make(chan *http.Response, 1)
	go func() {
		resp, err := postChunked(base+"/body/0x01", bytes.NewReader(make([]byte, 1<<20)))
		if err != nil {
			t.Error(err)
			close(ninth)
			return
		}
		ninth <- resp
	}()
	select {
	case <-ninth:
		t.Fatal("the 9th large body was served while 8 slots were taken")
	case <-time.After(300 * time.Millisecond):
	}

	_ = hs[0].w.Close()
	if resp := <-hs[0].resp; resp == nil || resp.StatusCode != 200 {
		t.Fatalf("released request: %v", resp)
	}
	select {
	case resp := <-ninth:
		if resp == nil || resp.StatusCode != 200 {
			t.Fatalf("9th request: %v", resp)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(b) != "1048576" {
			t.Fatalf("9th request read %s bytes", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the 9th request did not proceed after a slot was released")
	}
	for _, h := range hs[1:] {
		_ = h.w.Close()
		if resp := <-h.resp; resp != nil {
			_ = resp.Body.Close()
		}
	}
	waitFor(t, func() bool { return len(s.gate.slots) == 0 })
}

// A body needs a slot only once more than 64 KiB of it have actually been
// read, however large the reader's buffer.
func TestGatedBodyCrossing(t *testing.T) {
	newBody := func(ctx context.Context, g *bodyGate, size int) *gatedBody {
		return &gatedBody{ReadCloser: io.NopCloser(bytes.NewReader(make([]byte, size))), ctx: ctx, ticket: &ticket{gate: g}}
	}
	// io.ReadAll grows its buffer past the bytes read; that alone must not
	// take a slot.
	for _, size := range []int{50 << 10, 60 << 10, LargeBodyThreshold} {
		g := newBodyGate(1)
		b := newBody(context.Background(), g, size)
		data, err := io.ReadAll(b)
		if err != nil || len(data) != size {
			t.Fatalf("ReadAll of %d bytes: %d, %v", size, len(data), err)
		}
		if b.ticket.held || len(g.slots) != 0 {
			t.Fatalf("a %d-byte body took a slot", size)
		}
	}

	g := newBodyGate(1)
	b := newBody(context.Background(), g, 100<<10)
	buf := make([]byte, 48<<10)
	for _, want := range []int{48 << 10, 16 << 10} {
		if n, err := b.Read(buf); err != nil || n != want {
			t.Fatalf("read %d, %v; want %d", n, err, want)
		}
	}
	if b.ticket.held {
		t.Fatal("slot taken at 64 KiB read")
	}
	if _, err := b.Read(buf); err != nil {
		t.Fatal(err)
	}
	if !b.ticket.held || len(g.slots) != 1 {
		t.Fatal("no slot taken past 64 KiB")
	}
	if _, err := io.Copy(io.Discard, b); err != nil || b.read != 100<<10 {
		t.Fatalf("rest of the body: %d bytes read in all, %v", b.read, err)
	}

	// With the gate full, a crossing read waits and gives up with its context.
	ctx, cancel := context.WithCancel(context.Background())
	other := newBody(ctx, g, 100<<10)
	cancel()
	if n, err := other.Read(make([]byte, 65<<10)); err != nil || n != LargeBodyThreshold {
		t.Fatalf("read below the threshold: %d, %v", n, err)
	}
	if _, err := other.Read(make([]byte, 1)); err == nil {
		t.Fatal("a read past the threshold proceeded without a slot")
	}
	b.ticket.release()
	if len(g.slots) != 0 {
		t.Fatal("release did not free the slot")
	}
}

// Routes that need no credential never take a large-body slot, so tokenless
// chunked bodies trickled to /open cannot hold the gate against
// authenticated large bodies.
func TestOpenRouteNotGated(t *testing.T) {
	s := newTestServer(t, nil)
	base := serve(t, s)
	addr := strings.TrimPrefix(base, "http://")

	for range DefaultLargeBodySlots {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		if _, err := io.WriteString(c, "GET /open HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n"); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(200 * time.Millisecond) // the requests are in limitBody, reading
	if n := len(s.gate.slots); n != 0 {
		t.Fatalf("%d slots taken by tokenless requests", n)
	}

	start := time.Now()
	resp, err := postChunked(base+"/body/0x01", bytes.NewReader(make([]byte, 1<<20)))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || time.Since(start) > 2*time.Second {
		t.Fatalf("authenticated chunked body: %d after %v", resp.StatusCode, time.Since(start))
	}
}

func gather(t *testing.T, reg *prometheus.Registry, name string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		m := mf.GetMetric()[0]
		if g := m.GetGauge(); g != nil {
			return g.GetValue()
		}
		return m.GetCounter().GetValue()
	}
	t.Fatalf("metric %s not registered", name)
	return 0
}

// With --http-max-connections=4, a 5th connection is not served until one
// closes, and the limit-reached counter increments (G4 S7).
func TestMaxConnections(t *testing.T) {
	reg := prometheus.NewRegistry()
	s := newTestServer(t, func(c *Config) { c.MaxConnections = 4; c.Registerer = reg })
	addr := strings.TrimPrefix(serve(t, s), "http://")

	get := "GET /open HTTP/1.1\r\nHost: localhost\r\n\r\n"
	var conns []net.Conn
	for range 4 {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		readStatus(t, c, get)
		conns = append(conns, c)
	}
	if got := gather(t, reg, "http_connections_open"); got != 4 {
		t.Fatalf("http_connections_open = %v, want 4", got)
	}
	if got := gather(t, reg, "http_connections_limit_reached_total"); got != 1 {
		t.Fatalf("http_connections_limit_reached_total = %v, want 1", got)
	}

	fifth, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fifth.Close() }()
	if _, err := io.WriteString(fifth, get); err != nil {
		t.Fatal(err)
	}
	_ = fifth.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := fifth.Read(make([]byte, 1)); err == nil {
		t.Fatal("the 5th connection was served while 4 were open")
	}

	_ = conns[0].Close()
	_ = fifth.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := bufio.NewReader(fifth).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "HTTP/1.1 200") {
		t.Fatalf("5th connection after one closed: %q, %v", line, err)
	}
	if got := gather(t, reg, "http_connections_limit_reached_total"); got != 2 {
		t.Fatalf("http_connections_limit_reached_total = %v, want 2", got)
	}
}

func readStatus(t *testing.T, c net.Conn, req string) {
	t.Helper()
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	_ = c.SetReadDeadline(time.Time{})
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

// Shutdown lets an in-flight request finish.
func TestShutdownCompletesInFlight(t *testing.T) {
	release := make(chan struct{})
	s := newTestServer(t, func(c *Config) { c.Routes = testRoutes(release) })
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- s.Serve() }()
	base := "http://" + s.Addr().String()

	respc := make(chan *http.Response, 1)
	go func() {
		resp, err := postChunked(base+"/body/0x01", strings.NewReader("{}"))
		if err != nil {
			t.Error(err)
		}
		respc <- resp
	}()
	time.Sleep(100 * time.Millisecond) // the request is in the handler, waiting on release

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	}()
	time.Sleep(100 * time.Millisecond)
	close(release)
	resp := <-respc
	if resp == nil || resp.StatusCode != 200 {
		t.Fatalf("in-flight request: %v", resp)
	}
	_ = resp.Body.Close()
	wg.Wait()
	if err := <-served; err != nil {
		t.Fatalf("Serve after Shutdown = %v", err)
	}
}

func TestWritePortsFile(t *testing.T) {
	dir := t.TempDir()
	path, err := WritePortsFile(dir, 9123)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if filepath.Base(path) != PortsFileName || !strings.Contains(string(data), "\nhttp-port=9123\n") {
		t.Fatalf("%s: %q", path, data)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
