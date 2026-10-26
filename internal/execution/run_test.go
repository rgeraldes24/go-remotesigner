// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package execution

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/api/ops"
	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/argon"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystoretest"
	"github.com/rgeraldes24/go-remotesigner/internal/logging"
	"github.com/rgeraldes24/go-remotesigner/internal/runner"
	"github.com/rgeraldes24/go-remotesigner/internal/server"
	"github.com/rgeraldes24/go-remotesigner/internal/server/auth"
	"github.com/rgeraldes24/go-remotesigner/internal/server/tlsconf"
)

// execConfig is an execution configuration on loopback, forwarding to nd.
func execConfig(t *testing.T, nd *node) *config.Config {
	t.Helper()
	return &config.Config{
		DataPath:              t.TempDir(),
		KeyConfigPath:         t.TempDir(),
		StrictFilePermissions: true,
		HTTP: config.HTTP{
			ListenHost:     "127.0.0.1",
			HostAllowlist:  []string{"localhost", "127.0.0.1", "::1"},
			AuthMode:       auth.ModeToken,
			MaxConnections: 64,
			IdleTimeout:    server.DefaultIdleTimeout,
		},
		Execution: config.Execution{Downstream: downstreamOf(t, nd.Server), AllowedMethods: defaultAllow, ChainID: testChainID,
			NonceCrosscheck: true},
	}
}

// writeAccount writes a file-raw key config of account i's extended seed.
func writeAccount(t *testing.T, dir string, i int) string {
	t.Helper()
	ext := keystoretest.ExtendedSeed("run", i)
	content := "type: file-raw\nkeyType: ML_DSA_87\nprivateKey: \"0x" + hex.EncodeToString(ext[:]) + "\"\n"
	if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("account-%d.yaml", i)), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	addr, err := keystoretest.Address(ext)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

type running struct {
	base, sign, admin string
	hup               chan struct{}
	stop              func() error
}

func startExec(t *testing.T, cfg *config.Config) *running {
	t.Helper()
	return startExecLogging(t, cfg, quiet())
}

// startExecLogging is startExec with the signer logging to log.
func startExecLogging(t *testing.T, cfg *config.Config, log *logrus.Logger) *running {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	hup := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, log, hup) }()
	ports := filepath.Join(cfg.DataPath, server.PortsFileName)
	var port string
	for deadline := time.Now().Add(5 * time.Second); port == ""; time.Sleep(5 * time.Millisecond) {
		select {
		case err := <-done:
			cancel()
			t.Fatalf("Run returned early: %v", err)
		default:
		}
		if data, err := os.ReadFile(ports); err == nil {
			for line := range strings.SplitSeq(string(data), "\n") {
				if p, ok := strings.CutPrefix(line, "http-port="); ok {
					port = p
				}
			}
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("no ports file")
		}
	}
	r := &running{base: "http://localhost:" + port, hup: hup}
	if cfg.HTTP.AuthMode.SignToken() {
		r.sign = readToken(t, cfg.SignTokenFile())
	}
	r.admin = readToken(t, cfg.AdminTokenFile())
	var once sync.Once
	var stopErr error
	r.stop = func() error {
		once.Do(func() {
			cancel()
			select {
			case stopErr = <-done:
			case <-time.After(15 * time.Second):
				stopErr = errors.New("Run did not return")
			}
		})
		return stopErr
	}
	t.Cleanup(func() {
		if err := r.stop(); err != nil {
			t.Error(err)
		}
	})
	return r
}

func readToken(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

// req is one HTTP request to a running signer.
type req struct {
	method, path, body, contentType, host, origin string
	header                                        http.Header
}

func (r *running) do(t *testing.T, q req) (int, string) {
	t.Helper()
	if q.method == "" {
		q.method = http.MethodPost
	}
	hr, err := http.NewRequest(q.method, r.base+q.path, strings.NewReader(q.body))
	if err != nil {
		t.Fatal(err)
	}
	if q.method == http.MethodPost {
		hr.Header.Set("Content-Type", "application/json")
	}
	if q.contentType != "" {
		hr.Header.Set("Content-Type", q.contentType)
	}
	for k, v := range q.header {
		hr.Header[k] = v
	}
	if q.host != "" {
		hr.Host = q.host
	}
	if q.origin != "" {
		hr.Header.Set("Origin", q.origin)
	}
	resp, err := http.DefaultClient.Do(hr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func (r *running) bearer() http.Header { return http.Header{"Authorization": {"Bearer " + r.sign}} }

func (r *running) waitReady(t *testing.T) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if code, _ := r.do(t, req{method: http.MethodGet, path: "/upcheck"}); code == http.StatusOK {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("never ready")
		}
	}
}

// The endpoint sits behind the same guards as consensus mode: a bearer
// token (no Basic auth, no token in the URL), the host allowlist, the
// Origin refusal, the JSON content type and the 5 MiB body limit. Paths
// other than / are 404 after authentication; Web3Signer's eth1 REST,
// signing-extension and Commit-Boost paths do not exist.
func TestRunEndpointGuards(t *testing.T) {
	nd := newNode(t)
	cfg := execConfig(t, nd)
	writeAccount(t, cfg.KeyConfigPath, 0)
	r := startExec(t, cfg)
	r.waitReady(t)
	ok := call(1, MethodHealthStatus)
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:"+r.sign))
	tests := []struct {
		name   string
		q      req
		status int
		reason string
	}{
		{"bearer token", req{path: "/", body: ok, header: r.bearer()}, 200, ""},
		{"no token", req{path: "/", body: ok}, 401, "UNAUTHENTICATED"},
		{"basic auth with the token as password", req{path: "/", body: ok, header: http.Header{"Authorization": {basic}}}, 401, "UNAUTHENTICATED"},
		{"token without a scheme", req{path: "/", body: ok, header: http.Header{"Authorization": {r.sign}}}, 401, "UNAUTHENTICATED"},
		{"token in the query", req{path: "/?token=" + r.sign, body: ok}, 401, "UNAUTHENTICATED"},
		{"wrong token", req{path: "/", body: ok, header: http.Header{"Authorization": {"Bearer 0x" + strings.Repeat("ab", 32)}}}, 401, "UNAUTHENTICATED"},
		{"admin token", req{path: "/", body: ok, header: http.Header{"Authorization": {"Bearer " + r.admin}}}, 401, "UNAUTHENTICATED"},
		{"host not allowed", req{path: "/", body: ok, header: r.bearer(), host: "evil.example"}, 403, "HOST_NOT_ALLOWED"},
		{"origin", req{path: "/", body: ok, header: r.bearer(), origin: "https://dapp.example"}, 403, "ORIGIN_NOT_ALLOWED"},
		{"text/plain", req{path: "/", body: ok, header: r.bearer(), contentType: "text/plain"}, 415, "UNSUPPORTED_MEDIA_TYPE"},
		{"body over 5 MiB", req{path: "/", body: strings.Repeat(" ", BodyLimit+1), header: r.bearer()}, 413, "BODY_TOO_LARGE"},
		{"GET /", req{method: http.MethodGet, path: "/", header: r.bearer()}, 405, ""},
		{"other path", req{path: "/login", body: ok, header: r.bearer()}, 404, ""},
		{"other path without a token", req{path: "/login", body: ok}, 401, "UNAUTHENTICATED"},
		{"eth1 REST sign", req{path: "/api/v1/eth1/sign/0x00", body: `{"data":"0x00"}`, header: r.bearer()}, 404, ""},
		{"eth1 REST publicKeys", req{method: http.MethodGet, path: "/api/v1/eth1/publicKeys", header: r.bearer()}, 404, ""},
		{"signing extension", req{path: "/api/v1/eth2/ext/sign/0x00", body: `{}`, header: r.bearer()}, 404, ""},
		{"Commit-Boost", req{method: http.MethodGet, path: "/signer/v1/get_pubkeys", header: r.bearer()}, 404, ""},
		{"consensus sign", req{path: "/api/v1/consensus/sign/0x00", body: `{}`, header: r.bearer()}, 404, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, body := r.do(t, tt.q)
			if code != tt.status || !strings.Contains(body, tt.reason) {
				t.Fatalf("%d %.300s, want %d %s", code, body, tt.status, tt.reason)
			}
		})
	}
	if n := len(nd.clientCalls()); n != 0 {
		t.Fatalf("the node received %d requests", n)
	}
}

// Over HTTP: qrl_accounts lists the configured accounts, qrl_sign signs
// with them, publicKeys gives the public key that verifies the signature,
// and forwarded methods reach the node.
func TestRunServesAccounts(t *testing.T) {
	nd := newNode(t)
	cfg := execConfig(t, nd)
	addrs := map[string]bool{}
	for i := range 3 {
		addrs[strings.ToLower(writeAccount(t, cfg.KeyConfigPath, i))] = true
	}
	r := startExec(t, cfg)
	r.waitReady(t)

	_, body := r.do(t, req{path: "/", body: call(1, MethodAccounts), header: r.bearer()})
	var accounts []string
	if err := json.Unmarshal(decodeOne(t, []byte(body)).Result, &accounts); err != nil || len(accounts) != 3 {
		t.Fatalf("qrl_accounts: %s", body)
	}
	for _, a := range accounts {
		if !addrs[strings.ToLower(a)] {
			t.Errorf("unexpected account %s", a)
		}
	}

	code, list := r.do(t, req{method: http.MethodGet, path: PublicKeysPath, header: r.bearer()})
	var keys []struct {
		Address   string `json:"address"`
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal([]byte(list), &keys); code != 200 || err != nil || len(keys) != 3 {
		t.Fatalf("publicKeys: %d %.200s", code, list)
	}
	for i, k := range keys {
		pkBytes, err := hex.DecodeString(strings.TrimPrefix(k.PublicKey, "0x"))
		if err != nil {
			t.Fatal(err)
		}
		pk, err := mldsa87.ParsePublicKey(pkBytes)
		if err != nil {
			t.Fatal(err)
		}
		if k.Address != accounts[i] || mldsa87.ChecksumAddress(pk.Address()) != k.Address {
			t.Fatalf("publicKeys entry %d: %s does not match qrl_accounts %s", i, k.Address, accounts[i])
		}
	}

	_, body = r.do(t, req{path: "/", body: call(2, MethodSign, keys[0].Address, "0xc0ffee"), header: r.bearer()})
	var sigHex string
	if err := json.Unmarshal(decodeOne(t, []byte(body)).Result, &sigHex); err != nil {
		t.Fatalf("qrl_sign: %s", body)
	}
	sig, _ := hex.DecodeString(strings.TrimPrefix(sigHex, "0x"))
	pkBytes, _ := hex.DecodeString(strings.TrimPrefix(keys[0].PublicKey, "0x"))
	pk, _ := mldsa87.ParsePublicKey(pkBytes)
	digest := TextHash([]byte{0xc0, 0xff, 0xee})
	if !mldsa87.Verify(&pk, digest[:], sig) {
		t.Fatal("the signature does not verify under the published public key")
	}

	_, body = r.do(t, req{path: "/", body: batch(call(1, "qrl_blockNumber"), call(2, "admin_peers")), header: r.bearer()})
	rs := decodeBatch(t, []byte(body))
	if len(rs) != 2 || string(rs[0].Result) != `"node:qrl_blockNumber"` || rs[1].Error == nil ||
		rs[1].Error.Code != ErrMethodNotFound.Code {
		t.Fatalf("batch: %s", body)
	}
}

// Execution mode loads only account keys: a 48-byte validator seed is
// refused and counts as a load error, while extended seeds and go-qrl
// account keystores load.
func TestRunKeySources(t *testing.T) {
	nd := newNode(t)
	cfg := execConfig(t, nd)
	addr := writeAccount(t, cfg.KeyConfigPath, 0)
	seed := keystoretest.Seed("run", 9)
	validator := "type: file-raw\nprivateKey: \"0x" + hex.EncodeToString(seed[:]) + "\"\n"
	if err := os.WriteFile(filepath.Join(cfg.KeyConfigPath, "validator.yaml"), []byte(validator), 0o600); err != nil {
		t.Fatal(err)
	}
	ksDir, pwDir := t.TempDir(), t.TempDir()
	s, err := keystoretest.NewSealer("pw", keystoretest.Cheapest)
	if err != nil {
		t.Fatal(err)
	}
	ext := keystoretest.ExtendedSeed("run", 5)
	ksAddr, err := keystoretest.Address(ext)
	if err != nil {
		t.Fatal(err)
	}
	data, err := s.Account(ext, ksAddr)
	if err != nil {
		t.Fatal(err)
	}
	for dir, name := range map[string]string{ksDir: "UTC--a.json", pwDir: "UTC--a.txt"} {
		content := string(data)
		if dir == pwDir {
			content = "pw\n"
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg.Execution.Keystores = config.Keystores{Path: ksDir, PasswordsPath: pwDir}
	r := startExec(t, cfg)
	r.waitReady(t)

	_, body := r.do(t, req{path: "/", body: call(1, MethodAccounts), header: r.bearer()})
	var accounts []string
	_ = json.Unmarshal(decodeOne(t, []byte(body)).Result, &accounts)
	got := map[string]bool{}
	for _, a := range accounts {
		got[strings.ToLower(a)] = true
	}
	if len(accounts) != 2 || !got[strings.ToLower(addr)] || !got[strings.ToLower(ksAddr)] {
		t.Fatalf("accounts %v, want the extended seed's and the keystore's", accounts)
	}
	code, health := r.do(t, req{method: http.MethodGet, path: "/healthcheck", header: r.bearer()})
	if code != http.StatusServiceUnavailable ||
		!strings.Contains(health, `{"id":"keys-check/config-files-loading","status":"DOWN","data":{"error-count":1,"keys-loaded":1}}`) ||
		!strings.Contains(health, `{"id":"keys-check/keystores-bulk-loading","status":"UP","data":{"error-count":0,"keys-loaded":1}}`) {
		t.Fatalf("healthcheck: %d %s", code, health)
	}
}

// The JSON-RPC endpoint and publicKeys wait for the startup load and need
// the sign scope; the endpoint takes bodies up to 5 MiB and matches "/"
// alone. POST /reload exists only with an admin token.
func TestRoutes(t *testing.T) {
	f := newFixture(t, 0, defaultAllow)
	dir := t.TempDir()
	cfg := &config.Config{}
	loader := runner.NewKeyLoader(cfg, runner.KeySources{Execution: true}, argon.New(1, 1<<30), f.keys,
		runner.LoadHooks{}, quiet())
	reloader := ops.NewReloader(loader.Load, quiet())
	defer reloader.Close()
	for _, admin := range []bool{true, false} {
		ac := auth.Config{Mode: auth.ModeToken, SignTokenFile: filepath.Join(dir, "sign")}
		if admin {
			ac.AdminTokenFile = filepath.Join(dir, "admin")
		}
		authn, err := auth.New(ac)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]server.Route{}
		for _, rt := range routes(f.handler, f.accounts, loader, reloader, authn, func() bool { return true }, quiet()) {
			got[rt.Method+" "+rt.Pattern] = rt
		}
		rpc := got["POST /{$}"]
		if rpc.Scope != auth.ScopeSign || !rpc.NeedsReady || rpc.BodyLimit != 5<<20 || !rpc.ReadsBody {
			t.Errorf("POST /: %+v", rpc)
		}
		if pk := got["GET "+PublicKeysPath]; pk.Scope != auth.ScopeSign || !pk.NeedsReady {
			t.Errorf("publicKeys: %+v", pk)
		}
		for _, open := range []string{"GET /upcheck", "GET /healthcheck"} {
			if got[open].Scope != auth.ScopeNone || got[open].NeedsReady {
				t.Errorf("%s: %+v", open, got[open])
			}
		}
		if _, ok := got["POST /reload"]; ok != admin {
			t.Errorf("POST /reload with admin token %v: present %v", admin, ok)
		}
		if len(got) != 5+map[bool]int{true: 1}[admin] {
			t.Errorf("routes %v", got)
		}
	}
}

// The connection cap applies: with --http-max-connections=1, a second
// connection waits until the first closes.
func TestRunConnectionCap(t *testing.T) {
	nd := newNode(t)
	cfg := execConfig(t, nd)
	cfg.HTTP.MaxConnections = 1
	r := startExec(t, cfg)
	r.waitReady(t)
	// The kept-alive connection of waitReady would hold the one slot.
	http.DefaultClient.CloseIdleConnections()
	var hold net.Conn
	for deadline := time.Now().Add(5 * time.Second); hold == nil; {
		c, err := net.Dial("tcp", strings.TrimPrefix(r.base, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		// A request on the held connection proves it was accepted.
		_ = c.SetDeadline(time.Now().Add(time.Second))
		_, _ = fmt.Fprintf(c, "GET /upcheck HTTP/1.1\r\nHost: localhost\r\n\r\n")
		if resp, err := http.ReadResponse(bufio.NewReader(c), nil); err == nil && resp.StatusCode == 200 {
			_ = c.SetDeadline(time.Time{})
			hold = c
			break
		}
		_ = c.Close()
		if time.Now().After(deadline) {
			t.Fatal("no connection was accepted")
		}
	}
	client := &http.Client{Timeout: 300 * time.Millisecond, Transport: &http.Transport{}}
	if resp, err := client.Get(r.base + "/upcheck"); err == nil {
		_ = resp.Body.Close()
		t.Fatal("a second connection was served while the cap was reached")
	}
	_ = hold.Close()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		resp, err := client.Get(r.base + "/upcheck")
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no connection after the first closed: %v", err)
		}
	}
	client.CloseIdleConnections()
}

// mTLS works as in consensus mode: the client certificate is the sign
// credential in mode mtls.
func TestRunMTLS(t *testing.T) {
	nd := newNode(t)
	cfg := execConfig(t, nd)
	vc := selfSignedClient(t)
	known := filepath.Join(cfg.DataPath, "known-clients")
	if err := os.WriteFile(known, []byte("wallet "+tlsconf.FingerprintOf(vc.Certificate[0]).String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.HTTP.AuthMode = auth.ModeMTLS
	cfg.TLS = tlsconf.Config{GenerateSelfSigned: true, KnownClientsFile: known}
	r := startExec(t, cfg)
	pemData, err := os.ReadFile(filepath.Join(cfg.SelfSignedTLSPath(), tlsconf.SelfSignedCertFile))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pemData)
	base := strings.Replace(r.base, "http://", "https://", 1)
	post := func(certs []tls.Certificate) (int, error) {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: certs}}}
		resp, err := c.Post(base+"/", "application/json", strings.NewReader(call(1, MethodHealthStatus)))
		if err != nil {
			return 0, err
		}
		_ = resp.Body.Close()
		return resp.StatusCode, nil
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if code, err := post([]tls.Certificate{vc}); err == nil && code == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("never served the known client")
		}
	}
	if code, err := post(nil); err == nil {
		t.Fatalf("a client without a certificate got %d", code)
	}
}

func selfSignedClient(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "wallet"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// Startup refusals: the listener fail-safes, an unreadable downstream
// credential and a bad allowlist.
func TestRunRefusals(t *testing.T) {
	nd := newNode(t)
	tests := []struct {
		name   string
		mutate func(*config.Config)
		want   string
	}{
		{"auth none beyond loopback", func(c *config.Config) {
			c.HTTP.ListenHost, c.HTTP.AuthMode, c.HTTP.HostAllowlist = "0.0.0.0", auth.ModeNone, []string{"signer"}
		}, "--http-auth-mode=none"},
		{"plaintext token beyond loopback", func(c *config.Config) {
			c.HTTP.ListenHost, c.HTTP.HostAllowlist = "0.0.0.0", []string{"signer"}
		}, "plaintext"},
		{"loopback allowlist beyond loopback", func(c *config.Config) {
			c.HTTP.ListenHost, c.AllowPlaintextTokenAuth = "0.0.0.0", true
		}, "loopback names only"},
		{"missing credentials file", func(c *config.Config) {
			c.Execution.Downstream.AuthHeaderFile = filepath.Join(t.TempDir(), "missing")
		}, "--downstream-http-auth-header-file"},
		{"bad allowlist", func(c *config.Config) { c.Execution.AllowedMethods = []string{"qrl_*_x"} }, "allowed-methods"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := execConfig(t, nd)
			tt.mutate(cfg)
			err := Run(context.Background(), cfg, quiet(), nil)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Run = %v, want a refusal mentioning %q", err, tt.want)
			}
		})
	}
}

// logBuffer collects a running signer's log output safely.
type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// With --metrics-enabled and --metrics-auth-token-file, execution mode's
// metrics listener line says that a scrape needs the token as
// token-required=true, a field the redaction hook does not hide, and the
// startup warns that every scrape sends the token in clear only on a
// non-loopback --metrics-host, as in consensus mode
// (runner.WarnMetricsTokenInClear). On loopback, a scrape without the
// token gets 401 and one with it 200.
func TestRunMetricsListenerToken(t *testing.T) {
	const inClear = "metrics token in clear"
	for _, tt := range []struct {
		name, host string
		allow      []string
		warns      bool
	}{
		{"loopback", "127.0.0.1", []string{"localhost", "127.0.0.1"}, false},
		{"non-loopback", "0.0.0.0", []string{"prometheus"}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := execConfig(t, newNode(t))
			tokenFile := filepath.Join(t.TempDir(), "metrics-token")
			cfg.Metrics = config.Metrics{Enabled: true, Host: tt.host, HostAllowlist: tt.allow, AuthTokenFile: tokenFile}
			var out logBuffer
			log := logrus.New()
			log.SetOutput(&out)
			log.AddHook(logging.RedactHook{})
			r := startExecLogging(t, cfg, log)
			r.waitReady(t)
			var listening string
			for line := range strings.SplitSeq(out.String(), "\n") {
				if strings.Contains(line, "Metrics listener is listening") {
					listening = line
				}
			}
			if !strings.Contains(listening, "token-required=true") {
				t.Errorf("the metrics listener line does not say a token is required: %q\n%s", listening, out.String())
			}
			if got := strings.Contains(out.String(), inClear); got != tt.warns {
				t.Errorf("warned that the token is sent in clear: %v, want %v\n%s", got, tt.warns, out.String())
			}
			if tt.warns && !strings.Contains(out.String(), "level=warning") {
				t.Errorf("the warning is not a WARN:\n%s", out.String())
			}
			if !tt.warns {
				scrapeNeedsToken(t, cfg, readToken(t, tokenFile))
			}
		})
	}
}

// scrapeNeedsToken checks that the loopback metrics listener of a running
// signer answers 401 without the metrics token and 200 with it.
func scrapeNeedsToken(t *testing.T, cfg *config.Config, token string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(cfg.DataPath, server.PortsFileName))
	if err != nil {
		t.Fatal(err)
	}
	var port string
	for line := range strings.SplitSeq(string(data), "\n") {
		if p, ok := strings.CutPrefix(line, "metrics-port="); ok {
			port = p
		}
	}
	for tok, want := range map[string]int{"": http.StatusUnauthorized, token: http.StatusOK} {
		hr, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+port+"/metrics", nil)
		if err != nil {
			t.Fatal(err)
		}
		if tok != "" {
			hr.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := http.DefaultClient.Do(hr)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("scrape with token %v: %d, want %d", tok != "", resp.StatusCode, want)
		}
	}
}
