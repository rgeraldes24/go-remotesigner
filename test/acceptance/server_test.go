// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package acceptance

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

func reasonOf(t *testing.T, body string) string {
	t.Helper()
	var e struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Reason  string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		t.Fatalf("error body %q: %v", body, err)
	}
	return e.Reason
}

// G4 S1, S2, S4, S5: authentication, the scope matrix of the token modes,
// content type, Origin and Host.
func TestRequestRefusals(t *testing.T) {
	s := start(t, options{})
	s.waitReady()
	sign, admin, wrong := s.signToken(), s.adminToken(), "0x"+strings.Repeat("e", 64)
	const pubkeys = "/api/v1/consensus/publicKeys"
	tests := []struct {
		name   string
		req    request
		status int
		reason string
	}{
		{"no token", request{path: pubkeys}, 401, "UNAUTHENTICATED"},
		{"wrong token", request{path: pubkeys, token: wrong}, 401, "UNAUTHENTICATED"},
		{"wrong token on capabilities", request{path: "/api/v1/consensus/capabilities", token: wrong}, 401, "UNAUTHENTICATED"},
		{"admin token on a sign route", request{path: pubkeys, token: admin}, 401, "UNAUTHENTICATED"},
		{"sign token on an admin route", request{method: "POST", path: "/reload", token: sign, contentType: "application/json"}, 403, "FORBIDDEN_SCOPE"},
		{"no token on an admin route", request{method: "POST", path: "/reload", contentType: "application/json"}, 401, "UNAUTHENTICATED"},
		{"non-JSON POST", request{method: "POST", path: "/reload", token: admin, contentType: "text/plain", body: strings.NewReader("x")}, 415, "UNSUPPORTED_MEDIA_TYPE"},
		{"POST without content type", request{method: "POST", path: "/reload", token: admin}, 415, "UNSUPPORTED_MEDIA_TYPE"},
		{"Origin", request{path: pubkeys, token: sign, origin: "https://evil.example"}, 403, "ORIGIN_NOT_ALLOWED"},
		{"Origin null", request{path: "/upcheck", origin: "null"}, 403, "ORIGIN_NOT_ALLOWED"},
		{"bad Host", request{path: "/upcheck", host: "evil.example:" + s.port}, 403, "HOST_NOT_ALLOWED"},
		{"rebinding Host", request{path: pubkeys, token: sign, host: "localhost.evil.example"}, 403, "HOST_NOT_ALLOWED"},
		{"oversized body", request{method: "POST", path: "/reload", token: admin, contentType: "application/json", body: strings.NewReader(strings.Repeat(" ", 4097))}, 413, "BODY_TOO_LARGE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, body, h := s.do(tt.req)
			if code != tt.status || reasonOf(t, body) != tt.reason {
				t.Fatalf("%d %s, want %d %s", code, body, tt.status, tt.reason)
			}
			if code == 401 && h.Get("WWW-Authenticate") != "Bearer" {
				t.Fatalf("401 without WWW-Authenticate: Bearer")
			}
		})
	}
	// And the allowed paths through the same routes.
	if code, _, _ := s.do(request{path: pubkeys, token: sign}); code != 200 {
		t.Errorf("sign token on publicKeys: %d", code)
	}
	if code, body, _ := s.do(request{method: "POST", path: "/reload", token: admin, contentType: "application/json"}); code != 202 && code != 409 {
		t.Errorf("admin token on POST /reload: %d %s", code, body)
	}
	if code, _, _ := s.do(request{path: "/upcheck", host: "127.0.0.1:" + s.port}); code != 200 {
		t.Errorf("Host 127.0.0.1: %d", code)
	}
}

// G4 S3: the startup refusals. None of them has a way around it except the
// documented override flags, and disabled protection has none.
func TestStartupRefusals(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "genesis.ssz")
	state := make([]byte, 64) // genesis time 0, the end-to-end fork version
	copy(state[48:], []byte{0, 0, 0, 0xfd, 0, 0, 0, 0xfd})
	if err := os.WriteFile(stateFile, state, 0o600); err != nil {
		t.Fatal(err)
	}
	remote := []string{"--http-listen-host=0.0.0.0", "--Xallow-plaintext-token-auth", "--http-host-allowlist=signer.internal"}
	sharedToken := filepath.Join(t.TempDir(), "token")
	tests := []struct {
		name string
		o    options
		code int
		want string
	}{
		{"auth none on 0.0.0.0", options{global: []string{"--http-listen-host=0.0.0.0", "--http-auth-mode=none"}}, 1,
			"--http-auth-mode=none is allowed only on a loopback listener"},
		{"protection disabled on a non-loopback listener", options{global: remote, consensus: []string{"--slashing-protection-enabled=false", "--Xallow-gvr-tofu"}}, 1,
			"--slashing-protection-enabled=false is allowed only when every listener is loopback"},
		{"non-loopback listener with the default allowlist", options{global: []string{"--http-listen-host=0.0.0.0", "--Xallow-plaintext-token-auth"}, consensus: []string{"--Xallow-gvr-tofu"}}, 1,
			"host allowlist of loopback names only"},
		{"plaintext token on a non-loopback listener", options{global: []string{"--http-listen-host=0.0.0.0", "--http-host-allowlist=signer.internal"}, consensus: []string{"--Xallow-gvr-tofu"}}, 1,
			"token auth over plaintext HTTP"},
		{"TOFU on a non-loopback listener", options{global: remote}, 1, "--Xallow-gvr-tofu"},
		{"conflicting genesis sources", options{consensus: []string{"--network-genesis-state=" + stateFile}}, 1,
			"genesis time from --network-genesis-time (1760000000) disagrees with --network-genesis-state (0)"},
		{"unknown network", options{consensus: []string{"--network=no-such-network"}}, 1, "unknown network"},
		{"missing --network", options{env: []string{"REMOTESIGNER_CONSENSUS_NETWORK="}, consensus: []string{"--network="}}, 2, "--network is required"},
		{"unknown flag", options{consensus: []string{"--nope"}}, 2, "usage error"},
		{"one token file for both scopes", options{global: []string{"--http-auth-token-file=" + sharedToken, "--http-admin-token-file=" + sharedToken}}, 1,
			"the sign and admin tokens must differ"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := launch(t, tt.o)
			if code := s.exitCode(10 * time.Second); code != tt.code {
				t.Fatalf("exit %d, want %d\n%s", code, tt.code, s.output.String())
			}
			if !strings.Contains(s.output.String(), tt.want) {
				t.Fatalf("output lacks %q:\n%s", tt.want, s.output.String())
			}
			if _, err := os.Stat(filepath.Join(s.data, "remotesigner.ports")); err == nil {
				t.Fatal("a refused start wrote a ports file")
			}
		})
	}
}

// 256 file-raw keys reach /upcheck 200 in under 2 s, and publicKeys returns
// the 256 canonical keys sorted, plain and gzipped.
func TestKeysLoadAndPublicKeys(t *testing.T) {
	keys := t.TempDir()
	ids := writeKeys(t, keys, 256)
	slices.Sort(ids)
	s := start(t, options{keys: keys})
	took := s.waitReady()
	t.Logf("256 keys: /upcheck 200 %v after process start", took)
	if took > 2*time.Second {
		t.Errorf("/upcheck 200 after %v, want under 2 s", took)
	}

	code, body, _ := s.do(request{path: "/api/v1/consensus/publicKeys", token: s.signToken()})
	var got []string
	if err := json.Unmarshal([]byte(body), &got); code != 200 || err != nil {
		t.Fatalf("publicKeys: %d %v", code, err)
	}
	if !slices.Equal(got, ids) {
		t.Fatalf("publicKeys returned %d keys, not the 256 sorted canonical keys", len(got))
	}

	req, _ := http.NewRequest(http.MethodGet, s.base+"/api/v1/consensus/publicKeys", nil)
	req.Header.Set("Authorization", "Bearer "+s.signToken())
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := (&http.Transport{DisableCompression: true}).RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("Content-Encoding %q", resp.Header.Get("Content-Encoding"))
	}
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	got = nil
	if err := json.NewDecoder(zr).Decode(&got); err != nil || !slices.Equal(got, ids) {
		t.Fatalf("gzipped publicKeys: %d keys, %v", len(got), err)
	}
}

// postHeld starts a chunked POST /reload whose body stays open until the
// returned writer is closed.
func postHeld(s *signer, admin string, body io.Reader) <-chan int {
	codes := make(chan int, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodPost, s.base+"/reload", body)
		req.Header.Set("Authorization", "Bearer "+admin)
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = -1 // chunked
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			codes <- 0
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		codes <- resp.StatusCode
	}()
	return codes
}

// G4 S7: a chunked body takes a large-body slot; with 8 held, the 9th waits.
func TestLargeBodyGate(t *testing.T) {
	s := start(t, options{})
	s.waitReady()
	admin := s.adminToken()

	var writers []*io.PipeWriter
	var held []<-chan int
	for range 8 {
		pr, pw := io.Pipe()
		held = append(held, postHeld(s, admin, pr))
		if _, err := pw.Write([]byte("{")); err != nil {
			t.Fatal(err)
		}
		writers = append(writers, pw)
	}
	t.Cleanup(func() {
		for _, w := range writers {
			_ = w.Close()
		}
	})
	time.Sleep(200 * time.Millisecond) // all 8 are reading their bodies

	ninth := postHeld(s, admin, strings.NewReader(strings.Repeat(" ", 1<<20)))
	select {
	case code := <-ninth:
		t.Fatalf("the 9th chunked body was served (%d) while 8 slots were held", code)
	case <-time.After(500 * time.Millisecond):
	}
	_ = writers[0].Close()
	if code := <-held[0]; code != 202 && code != 409 {
		t.Fatalf("released request: %d", code)
	}
	select {
	case code := <-ninth:
		if code != 413 {
			t.Fatalf("9th request: %d, want 413 once it got a slot", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the 9th request still waits after a slot was released")
	}
}

// Tokenless chunked bodies trickled to /upcheck take no large-body slot, so
// they cannot hold the gate against authenticated large bodies.
func TestTokenlessBodiesTakeNoSlot(t *testing.T) {
	s := start(t, options{})
	s.waitReady()
	for range 8 {
		c, err := net.Dial("tcp", "127.0.0.1:"+s.port)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		if _, err := io.WriteString(c, "GET /upcheck HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n"); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(200 * time.Millisecond) // all 8 are reading their bodies

	pr, pw := io.Pipe()
	code := postHeld(s, s.adminToken(), pr)
	go func() {
		_, _ = pw.Write([]byte("{}"))
		_ = pw.Close()
	}()
	select {
	case c := <-code:
		if c != 202 && c != 409 {
			t.Fatalf("admin chunked POST /reload: %d", c)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("an authenticated chunked body waited behind tokenless ones")
	}
}

// With --http-max-connections=4 a 5th connection is not served until one of
// the four closes.
func TestMaxConnections(t *testing.T) {
	s := start(t, options{global: []string{"--http-max-connections=4"}})
	s.waitReady()
	http.DefaultClient.CloseIdleConnections() // free the slot waitReady's connection holds
	time.Sleep(100 * time.Millisecond)
	addr := "127.0.0.1:" + s.port
	get := "GET /upcheck HTTP/1.1\r\nHost: localhost\r\n\r\n"

	var conns []net.Conn
	for range 4 {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		if _, err := io.WriteString(c, get); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("connection %d: %v %v", len(conns), resp, err)
		}
		conns = append(conns, c)
	}

	fifth, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fifth.Close() }()
	if _, err := io.WriteString(fifth, get); err != nil {
		t.Fatal(err)
	}
	_ = fifth.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := fifth.Read(make([]byte, 1)); err == nil {
		t.Fatal("the 5th connection was served while 4 were open")
	}
	_ = conns[0].Close()
	_ = fifth.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := bufio.NewReader(fifth).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "HTTP/1.1 200") {
		t.Fatalf("5th connection after one closed: %q %v", line, err)
	}
}

// SIGTERM during an in-flight request: the request completes and the
// process exits 0.
func TestSIGTERMDrainsInFlight(t *testing.T) {
	s := start(t, options{})
	s.waitReady()
	pr, pw := io.Pipe()
	codes := postHeld(s, s.adminToken(), pr)
	if _, err := pw.Write([]byte("{")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)

	s.signal(syscall.SIGTERM)
	time.Sleep(300 * time.Millisecond)
	select {
	case <-s.done:
		t.Fatal("exited before the in-flight request finished")
	default:
	}
	_, _ = pw.Write([]byte("}"))
	_ = pw.Close()
	if code := <-codes; code != 202 && code != 409 {
		t.Fatalf("in-flight request: %d", code)
	}
	if code := s.exitCode(15 * time.Second); code != 0 {
		t.Fatalf("exit %d after SIGTERM\n%s", code, s.output.String())
	}
	if _, err := os.Stat(filepath.Join(s.data, "remotesigner.ports")); !os.IsNotExist(err) {
		t.Fatalf("ports file left after shutdown: %v", err)
	}
}

// SIGHUP re-reads the token files.
func TestSIGHUPRotatesTokens(t *testing.T) {
	s := start(t, options{})
	s.waitReady()
	old := s.signToken()
	fresh := "0x" + strings.Repeat("5a", 32)
	if err := os.WriteFile(filepath.Join(s.data, "auth-token"), []byte(fresh+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.signal(syscall.SIGHUP)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if code, _, _ := s.do(request{path: "/reload", token: fresh}); code == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("rotated token never accepted\n%s", s.output.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if code, _, _ := s.do(request{path: "/reload", token: old}); code != 401 {
		t.Fatalf("old token after SIGHUP: %d", code)
	}
}

// Generated token files are 0600, and the environment and config file feed
// the flags.
func TestTokenFilesAndConfigSources(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "signer.yaml")
	if err := os.WriteFile(cfg, []byte("http-max-connections: 64\nconsensus:\n  network-genesis-time: 1760000000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := start(t, options{
		global:    []string{"--config-file=" + cfg},
		noNetwork: true,
		env:       []string{"REMOTESIGNER_CONSENSUS_NETWORK=" + networkFile(t)},
	})
	s.waitReady()
	for _, name := range []string{"auth-token", "admin-token"} {
		fi, err := os.Stat(filepath.Join(s.data, name))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", name, fi, err)
		}
	}
	code, body, _ := s.do(request{path: "/api/v1/consensus/capabilities", token: s.signToken()})
	if code != 200 || !strings.Contains(body, `"genesis_time":"1760000000"`) || !strings.Contains(body, `"genesis_validators_root":null`) {
		t.Fatalf("capabilities: %d %s", code, body)
	}
}
