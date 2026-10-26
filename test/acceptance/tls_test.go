// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package acceptance

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// The TLS acceptance tests: TLS 1.3, mTLS and its scope matrix, the
// generated certificate, SIGHUP reloads, the metrics token and the absence
// of key labels, all against the built binary.

// tlsPair is a test certificate and its key.
type tlsPair struct {
	cert *x509.Certificate
	key  crypto.Signer
}

type certSpec struct {
	cn     string
	parent *tlsPair // nil: self-signed
	ca     bool
	usage  x509.ExtKeyUsage
	dns    []string
	ips    []net.IP
	rsa    bool
}

func newPair(t *testing.T, s certSpec) tlsPair {
	t.Helper()
	var key crypto.Signer
	var err error
	if s.rsa {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: s.cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		DNSNames:              s.dns,
		IPAddresses:           s.ips,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	if s.rsa {
		tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	if s.ca {
		tmpl.IsCA = true
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{s.usage}
	}
	parentCert, parentKey := tmpl, key
	if s.parent != nil {
		parentCert, parentKey = s.parent.cert, s.parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tlsPair{cert: c, key: key}
}

func serverCert(t *testing.T, rsaKey bool) tlsPair {
	return newPair(t, certSpec{cn: "signer", usage: x509.ExtKeyUsageServerAuth, dns: []string{"localhost"},
		ips: []net.IP{net.ParseIP("127.0.0.1")}, rsa: rsaKey})
}

func clientCertOf(t *testing.T, cn string, parent *tlsPair) tlsPair {
	return newPair(t, certSpec{cn: cn, parent: parent, usage: x509.ExtKeyUsageClientAuth})
}

func (p tlsPair) tls() tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{p.cert.Raw}, PrivateKey: p.key, Leaf: p.cert}
}

func (p tlsPair) fingerprint() string { return colonHex(sha256.Sum256(p.cert.Raw)) }

func colonHex(sum [32]byte) string {
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

func pemCerts(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

func writeTestFile(t *testing.T, path string, data []byte) string {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// writePEMPair writes p as PEM certificate and key files.
func writePEMPair(t *testing.T, dir, name string, p tlsPair) (string, string) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(p.key)
	if err != nil {
		t.Fatal(err)
	}
	return writeTestFile(t, filepath.Join(dir, name+".crt"), pemCerts(p.cert)),
		writeTestFile(t, filepath.Join(dir, name+".key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func writeKnownClients(t *testing.T, path string, clients ...tlsPair) string {
	t.Helper()
	var b strings.Builder
	for i, c := range clients {
		// Web3Signer's format: a host label, then the lower-case fingerprint.
		fmt.Fprintf(&b, "localhost %s\n# client %d\n", strings.ToLower(c.fingerprint()), i)
	}
	return writeTestFile(t, path, []byte(b.String()))
}

// tlsClient trusts roots and presents client, if any. Each client has its
// own transport, so its connections and session tickets are its own.
func tlsClient(roots *x509.CertPool, client *tls.Certificate, cache tls.ClientSessionCache) *http.Client {
	cfg := &tls.Config{RootCAs: roots, ClientSessionCache: cache}
	if client != nil {
		cfg.Certificates = []tls.Certificate{*client}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = cfg
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func poolOf(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

func (s *signer) tlsBase() string { return "https://localhost:" + s.port }

// call makes one request with client and returns the status and body, or
// the transport error.
func call(client *http.Client, method, url, token string) (int, string, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return 0, "", err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), nil
}

// waitReadyTLS waits for /upcheck over client.
func (s *signer) waitReadyTLS(client *http.Client) {
	s.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		code, _, err := call(client, http.MethodGet, s.tlsBase()+"/upcheck", "")
		if err == nil && code == 200 {
			return
		}
		if time.Now().After(deadline) {
			s.t.Fatalf("never ready over TLS: %d %v\n%s", code, err, s.output.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// servedFingerprint handshakes without verification and returns the
// fingerprint of the certificate the signer serves.
func (s *signer) servedFingerprint() string {
	s.t.Helper()
	c, err := tls.Dial("tcp", "127.0.0.1:"+s.port, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // reads the served certificate
	if err != nil {
		s.t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	return colonHex(sha256.Sum256(c.ConnectionState().PeerCertificates[0].Raw))
}

// stop sends SIGTERM and waits for a clean exit.
func (s *signer) stop() {
	s.t.Helper()
	s.signal(syscall.SIGTERM)
	if code := s.exitCode(15 * time.Second); code != 0 {
		s.t.Fatalf("exit %d\n%s", code, s.output.String())
	}
}

// --tls-generate-self-signed writes a 0600 certificate and key once, logs
// the SHA-256 fingerprint, and reuses them on restart; a mounted
// certificate takes precedence. TLS 1.2 is refused.
func TestTLSGenerateSelfSigned(t *testing.T) {
	data := t.TempDir()
	s := start(t, options{data: data, global: []string{"--tls-generate-self-signed"}})
	certFile := filepath.Join(data, "tls", "cert.pem")
	for _, name := range []string{"cert.pem", "key.pem"} {
		fi, err := os.Stat(filepath.Join(data, "tls", name))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", name, fi, err)
		}
	}
	pemData, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemData)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	fp := colonHex(sha256.Sum256(leaf.Raw))
	if _, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Fatalf("generated key %T, want ECDSA P-256", leaf.PublicKey)
	}
	client := tlsClient(poolOf(leaf), nil, nil)
	s.waitReadyTLS(client)
	if out := s.output.String(); !strings.Contains(out, "Generated a self-signed TLS certificate") ||
		!strings.Contains(out, "sha256-fingerprint=") || !strings.Contains(out, fp) || !strings.Contains(out, "tls=enabled") {
		t.Fatalf("the log lacks the generation and its fingerprint %s:\n%s", fp, out)
	}
	if code, body, err := call(client, http.MethodGet, s.tlsBase()+"/api/v1/consensus/publicKeys", s.signToken()); err != nil || code != 200 {
		t.Fatalf("token auth over TLS: %d %s %v", code, body, err)
	}
	// TLS 1.2 is refused.
	if c, err := tls.Dial("tcp", "127.0.0.1:"+s.port, &tls.Config{RootCAs: poolOf(leaf), ServerName: "localhost", MaxVersion: tls.VersionTLS12}); err == nil {
		_ = c.Close()
		t.Fatal("a TLS 1.2 handshake succeeded")
	}
	// Plaintext HTTP gets no API.
	if code, _, err := call(http.DefaultClient, http.MethodGet, s.base+"/upcheck", ""); err == nil && code == 200 {
		t.Fatal("plaintext HTTP served on the TLS port")
	}
	s.stop()

	// A restart reuses the files.
	again := start(t, options{data: data, global: []string{"--tls-generate-self-signed"}})
	again.waitReadyTLS(client)
	if again.servedFingerprint() != fp || strings.Contains(again.output.String(), "Generated a self-signed") {
		t.Fatalf("restart did not reuse the certificate:\n%s", again.output.String())
	}
	if after, _ := os.ReadFile(certFile); !bytes.Equal(after, pemData) {
		t.Fatal("the certificate file changed on restart")
	}
	again.stop()

	// A mounted certificate takes precedence.
	mounted := serverCert(t, false)
	cf, kf := writePEMPair(t, t.TempDir(), "mounted", mounted)
	third := start(t, options{data: data, global: []string{"--tls-generate-self-signed", "--tls-cert-file=" + cf, "--tls-key-file=" + kf}})
	third.waitReadyTLS(tlsClient(poolOf(mounted.cert), nil, nil))
	if third.servedFingerprint() != mounted.fingerprint() {
		t.Fatal("the generated certificate was served instead of the mounted one")
	}
}

// countingCache counts the sessions a client offers for resumption.
type countingCache struct {
	tls.ClientSessionCache
	offered atomic.Int32
}

func (c *countingCache) Get(key string) (*tls.ClientSessionState, bool) {
	s, ok := c.ClientSessionCache.Get(key)
	if ok {
		c.offered.Add(1)
	}
	return s, ok
}

// The mTLS scope matrix (contract §6) on the built binary. In mtls a known
// client certificate reaches the sign routes and gets 403 on admin routes
// without the admin token; in token+mtls each scope needs the certificate
// and its token. An unknown certificate is refused at the handshake, and a
// client removed by SIGHUP can neither use its open connection nor resume
// its session.
func TestMTLSScopeMatrix(t *testing.T) {
	srv := serverCert(t, false)
	vc, other := clientCertOf(t, "vc", nil), clientCertOf(t, "intruder", nil)
	for _, mode := range []string{"mtls", "token+mtls"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			cf, kf := writePEMPair(t, dir, "server", srv)
			known := writeKnownClients(t, filepath.Join(dir, "known-clients"), vc)
			s := start(t, options{global: []string{"--http-auth-mode=" + mode, "--tls-cert-file=" + cf, "--tls-key-file=" + kf,
				"--tls-known-clients-file=" + known}})
			roots := poolOf(srv.cert)
			vcCert := vc.tls()
			cache := &countingCache{ClientSessionCache: tls.NewLRUClientSessionCache(8)}
			withCert := tlsClient(roots, &vcCert, cache)
			s.waitReadyTLS(withCert)
			sign, admin := "", s.adminToken()
			if mode == "token+mtls" {
				sign = s.signToken()
			} else if _, err := os.Stat(filepath.Join(s.data, "auth-token")); err == nil {
				t.Fatal("mode mtls generated a sign token")
			}
			const keys, reload = "/api/v1/consensus/publicKeys", "/reload"
			type row struct {
				method, path, token string
				want                int
			}
			var rows []row
			if mode == "mtls" {
				rows = []row{
					{http.MethodGet, keys, "", 200},
					{http.MethodPost, reload, "", 403},
					{http.MethodPost, reload, admin, 202},
				}
			} else {
				rows = []row{
					{http.MethodGet, keys, "", 401},
					{http.MethodGet, keys, admin, 401},
					{http.MethodGet, keys, sign, 200},
					{http.MethodPost, reload, "", 401},
					{http.MethodPost, reload, sign, 403},
					{http.MethodPost, reload, admin, 202},
				}
			}
			for _, r := range rows {
				code, body, err := call(withCert, r.method, s.tlsBase()+r.path, r.token)
				if err != nil || code != r.want {
					t.Errorf("%s %s with the certificate and token %.6s: %d %v, want %d (%.120s)", r.method, r.path, r.token, code, err, r.want, body)
				}
			}
			// Without a known certificate there is no connection at all, whatever the token.
			otherCert := other.tls()
			for _, c := range []*http.Client{tlsClient(roots, &otherCert, nil), tlsClient(roots, nil, nil)} {
				if code, _, err := call(c, http.MethodGet, s.tlsBase()+keys, sign); err == nil {
					t.Errorf("a client without a known certificate got %d", code)
				}
			}

			// The known client resumes; after it is removed and SIGHUP, its
			// open connection gets 401 and its resumption is refused.
			resumed := tlsClient(roots, &vcCert, cache)
			before := cache.offered.Load()
			if _, _, err := call(resumed, http.MethodGet, s.tlsBase()+"/upcheck", ""); err != nil {
				t.Fatal(err)
			}
			if cache.offered.Load() == before {
				t.Fatal("the known client offered no session ticket to resume")
			}
			writeKnownClients(t, known, other)
			s.signal(syscall.SIGHUP)
			deadline := time.Now().Add(5 * time.Second)
			for {
				code, _, err := call(withCert, http.MethodGet, s.tlsBase()+keys, sign)
				if err == nil && code == 401 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("the removed client's open connection still got %d %v", code, err)
				}
				time.Sleep(20 * time.Millisecond)
			}
			// Every route of the open connection refuses it, the
			// credential-less ones included.
			for _, path := range []string{"/upcheck", "/healthcheck", "/api/v1/consensus/capabilities", "/no-such-route"} {
				if code, _, err := call(withCert, http.MethodGet, s.tlsBase()+path, sign); err != nil || code != 401 {
					t.Errorf("the removed client's open connection: GET %s got %d %v, want 401", path, code, err)
				}
			}
			before = cache.offered.Load()
			if _, _, err := call(tlsClient(roots, &vcCert, cache), http.MethodGet, s.tlsBase()+"/upcheck", ""); err == nil {
				t.Fatal("the removed client resumed its session")
			}
			if cache.offered.Load() == before {
				t.Fatal("no session was offered, so the resumed handshake was not exercised")
			}
		})
	}
}

// Revoking the only client with SIGHUP. Emptying the known-clients file
// (or the client CA file) is a valid reload that trusts nobody, and
// deleting it fails closed: either way the client's new handshakes are
// refused and the connection it already has open gets 401, and the log
// says why. Restoring the file lets the client back in on the same
// connection.
func TestMTLSRevokeTheOnlyClient(t *testing.T) {
	srv := serverCert(t, false)
	ca := newPair(t, certSpec{cn: "ca", ca: true})
	vc := clientCertOf(t, "vc", &ca)
	for _, flag := range []string{"--tls-known-clients-file", "--tls-client-ca-file"} {
		t.Run(strings.TrimPrefix(flag, "--tls-"), func(t *testing.T) {
			dir := t.TempDir()
			cf, kf := writePEMPair(t, dir, "server", srv)
			trust := filepath.Join(dir, "trust")
			restore := func() {
				if flag == "--tls-known-clients-file" {
					writeKnownClients(t, trust, vc)
				} else {
					writeTestFile(t, trust, pemCerts(ca.cert))
				}
			}
			restore()
			s := start(t, options{global: []string{"--http-auth-mode=mtls", "--tls-cert-file=" + cf, "--tls-key-file=" + kf,
				flag + "=" + trust}})
			roots := poolOf(srv.cert)
			vcCert := vc.tls()
			open := tlsClient(roots, &vcCert, nil)
			s.waitReadyTLS(open)
			const keys = "/api/v1/consensus/publicKeys"
			// waitOpen polls path on the client's open connection until it
			// answers want. A 401 can only come over that connection: a new
			// handshake would be refused.
			waitOpen := func(path string, want int) {
				t.Helper()
				deadline := time.Now().Add(5 * time.Second)
				for {
					code, _, err := call(open, http.MethodGet, s.tlsBase()+path, "")
					if err == nil && code == want {
						return
					}
					if time.Now().After(deadline) {
						t.Fatalf("%s on the open connection: %d %v, want %d\n%s", path, code, err, want, s.output.String())
					}
					time.Sleep(20 * time.Millisecond)
				}
			}
			waitLog := func(want string) {
				t.Helper()
				deadline := time.Now().Add(5 * time.Second)
				for !strings.Contains(s.output.String(), want) {
					if time.Now().After(deadline) {
						t.Fatalf("the log lacks %q:\n%s", want, s.output.String())
					}
					time.Sleep(20 * time.Millisecond)
				}
			}
			revocations := []struct {
				name   string
				revoke func()
				log    string
			}{
				{"emptied", func() { writeTestFile(t, trust, []byte("# vc revoked\n")) },
					"The TLS client trust lists no client and no CA"},
				{"deleted", func() {
					if err := os.Remove(trust); err != nil {
						t.Fatal(err)
					}
				}, "Reloading the TLS client trust failed"},
			}
			for _, r := range revocations {
				r.revoke()
				s.signal(syscall.SIGHUP)
				waitOpen(keys, 401)
				waitOpen("/upcheck", 401)
				waitLog(r.log)
				if code, _, err := call(tlsClient(roots, &vcCert, nil), http.MethodGet, s.tlsBase()+keys, ""); err == nil {
					t.Fatalf("%s: the revoked client opened a new connection: %d", r.name, code)
				}
				restore()
				s.signal(syscall.SIGHUP)
				waitOpen(keys, 200)
				if code, _, err := call(tlsClient(roots, &vcCert, nil), http.MethodGet, s.tlsBase()+keys, ""); err != nil || code != 200 {
					t.Fatalf("%s, then restored: a new connection got %d %v", r.name, code, err)
				}
			}
		})
	}
}

// CA mode accepts the clients of --tls-client-ca-file only, and SIGHUP
// reloads the server certificate.
func TestTLSClientCAAndCertificateReload(t *testing.T) {
	dir := t.TempDir()
	ca, otherCA := newPair(t, certSpec{cn: "ca", ca: true}), newPair(t, certSpec{cn: "other-ca", ca: true})
	issued, foreign := clientCertOf(t, "vc", &ca), clientCertOf(t, "vc", &otherCA)
	first, second := serverCert(t, false), serverCert(t, true)
	cf, kf := writePEMPair(t, dir, "server", first)
	caFile := writeTestFile(t, filepath.Join(dir, "client-ca.pem"), pemCerts(ca.cert))
	s := start(t, options{global: []string{"--http-auth-mode=mtls", "--tls-cert-file=" + cf, "--tls-key-file=" + kf, "--tls-client-ca-file=" + caFile}})
	issuedCert, foreignCert := issued.tls(), foreign.tls()
	roots := poolOf(first.cert, second.cert)
	good := tlsClient(roots, &issuedCert, nil)
	s.waitReadyTLS(good)
	if code, _, err := call(good, http.MethodGet, s.tlsBase()+"/api/v1/consensus/capabilities", ""); err != nil || code != 200 {
		t.Fatalf("CA-issued client: %d %v", code, err)
	}
	if _, _, err := call(tlsClient(roots, &foreignCert, nil), http.MethodGet, s.tlsBase()+"/upcheck", ""); err == nil {
		t.Fatal("a client of another CA connected")
	}
	if s.servedFingerprint() != first.fingerprint() {
		t.Fatal("not the first certificate")
	}
	writePEMPair(t, dir, "server", second)
	s.signal(syscall.SIGHUP)
	deadline := time.Now().Add(5 * time.Second)
	for s.servedFingerprint() != second.fingerprint() {
		if time.Now().After(deadline) {
			t.Fatalf("SIGHUP did not reload the certificate\n%s", s.output.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(s.output.String(), "TLS files reloaded") {
		t.Fatal("no reload log line")
	}
}

// CA mode never trusts the system roots: the signer runs with a system
// root store (SSL_CERT_FILE, which Go reads on Linux and the other Unix
// systems except macOS) that holds a CA, and a client issued by that CA is
// refused, while a client of the --tls-client-ca-file CA connects.
func TestTLSClientCANeverTrustsSystemRoots(t *testing.T) {
	dir := t.TempDir()
	systemCA, fileCA := newPair(t, certSpec{cn: "system-ca", ca: true}), newPair(t, certSpec{cn: "file-ca", ca: true})
	bySystem, byFile := clientCertOf(t, "vc", &systemCA), clientCertOf(t, "vc", &fileCA)
	srv := serverCert(t, false)
	cf, kf := writePEMPair(t, dir, "server", srv)
	bundle := writeTestFile(t, filepath.Join(dir, "system-roots.pem"), pemCerts(systemCA.cert, srv.cert))
	caFile := writeTestFile(t, filepath.Join(dir, "client-ca.pem"), pemCerts(fileCA.cert))
	s := start(t, options{
		global: []string{"--http-auth-mode=mtls", "--tls-cert-file=" + cf, "--tls-key-file=" + kf, "--tls-client-ca-file=" + caFile},
		env:    []string{"SSL_CERT_FILE=" + bundle, "SSL_CERT_DIR=" + t.TempDir()},
	})
	roots := poolOf(srv.cert)
	good, bad := byFile.tls(), bySystem.tls()
	s.waitReadyTLS(tlsClient(roots, &good, nil))
	if code, _, err := call(tlsClient(roots, &bad, nil), http.MethodGet, s.tlsBase()+"/upcheck", ""); err == nil {
		t.Fatalf("a client issued by a system root connected: %d", code)
	}
}

// The TLS startup refusals and usage errors.
func TestTLSStartupRefusals(t *testing.T) {
	dir := t.TempDir()
	srv := serverCert(t, false)
	cf, kf := writePEMPair(t, dir, "server", srv)
	_, otherKey := writePEMPair(t, dir, "other", serverCert(t, false))
	tests := []struct {
		name   string
		global []string
		code   int
		want   string
	}{
		{"mtls without TLS", []string{"--http-auth-mode=mtls"}, 2, "need TLS"},
		{"mtls without client trust", []string{"--http-auth-mode=mtls", "--tls-cert-file=" + cf, "--tls-key-file=" + kf}, 2,
			"need --tls-known-clients-file or --tls-client-ca-file"},
		{"key of another certificate", []string{"--tls-cert-file=" + cf, "--tls-key-file=" + otherKey}, 1, "refusing to start: TLS"},
		{"self-signed for a wildcard allowlist", []string{"--tls-generate-self-signed", "--http-host-allowlist=*"}, 1, "a wildcard names none"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := launch(t, options{global: tt.global})
			if code := s.exitCode(10 * time.Second); code != tt.code {
				t.Fatalf("exit %d, want %d\n%s", code, tt.code, s.output.String())
			}
			if !strings.Contains(s.output.String(), tt.want) {
				t.Fatalf("output lacks %q:\n%s", tt.want, s.output.String())
			}
		})
	}
}

// On a non-loopback listener, token auth over TLS needs no plaintext
// override, while every other fail-safe still applies. The listener never
// binds: the start is refused for the TOFU pin, and the refusal lists no
// plaintext-token refusal.
func TestTLSLiftsOnlyThePlaintextRefusal(t *testing.T) {
	remote := []string{"--http-listen-host=0.0.0.0", "--http-host-allowlist=signer.internal"}
	plain := launch(t, options{global: remote})
	if code := plain.exitCode(10 * time.Second); code != 1 || !strings.Contains(plain.output.String(), "token auth over plaintext HTTP") {
		t.Fatalf("plaintext: exit %d\n%s", code, plain.output.String())
	}
	withTLS := launch(t, options{global: append(remote, "--tls-generate-self-signed")})
	out := withTLS.output
	if code := withTLS.exitCode(10 * time.Second); code != 1 || strings.Contains(out.String(), "token auth over plaintext HTTP") ||
		!strings.Contains(out.String(), "--Xallow-gvr-tofu") {
		t.Fatalf("TLS: exit %d\n%s", code, out.String())
	}
	none := launch(t, options{global: append(remote, "--tls-generate-self-signed", "--http-auth-mode=none")})
	if code := none.exitCode(10 * time.Second); code != 1 || !strings.Contains(none.output.String(), "--http-auth-mode=none is allowed only on a loopback listener") {
		t.Fatalf("auth none over TLS: exit %d\n%s", code, none.output.String())
	}
}

var (
	keyLabel  = regexp.MustCompile(`(?i)\b(pubkey|public_key|key|identifier|validator|url)="`)
	longHex   = regexp.MustCompile(`0x[0-9a-fA-F]{16,}`)
	labelLine = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*\{(.*)\} `)
)

// assertNoKeyLabels fails t when a metric of the scrape text carries a key:
// a key-like label name, a long hex label value, or any of the forms of
// pubkeys (hex prefix, the logs' short form, id prefix) anywhere in it.
func assertNoKeyLabels(t *testing.T, text string, pubkeys ...string) {
	t.Helper()
	for line := range strings.SplitSeq(text, "\n") {
		m := labelLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if keyLabel.MatchString(m[1]) || longHex.MatchString(m[1]) {
			t.Errorf("metric with a key-like label: %s", line)
		}
	}
	lower := strings.ToLower(text)
	for _, pk := range pubkeys {
		id := sha256.Sum256(mustHex(t, pk))
		for _, needle := range []string{pk[2:18], "0x" + pk[2:12], fmt.Sprintf("%x", id[:8])} {
			if strings.Contains(lower, strings.ToLower(needle)) {
				t.Errorf("the scrape contains key material %s", needle)
			}
		}
	}
}

// With --metrics-auth-token-file a scrape needs the token, which SIGHUP
// rotates; no metric carries a key: no key-like label name, and no long
// hex label value, after signing (TestIntegrationEveryRequestType applies
// the same check after every request type and RANDAO outcome).
func TestMetricsTokenAndNoKeyLabels(t *testing.T) {
	keys := t.TempDir()
	c := writeInteropKey(t, keys)
	tokenFile := filepath.Join(t.TempDir(), "metrics-token")
	s := start(t, options{keys: keys, global: []string{"--metrics-enabled", "--metrics-port=0", "--metrics-auth-token-file=" + tokenFile}})
	s.waitReady()
	if fi, err := os.Stat(tokenFile); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("generated metrics token: %v %v", fi, err)
	}
	// The startup line says that the token is required; the field is not
	// one the redaction hook hides.
	if !strings.Contains(s.output.String(), "token-required=true") {
		t.Fatalf("the metrics listener line does not say a token is required:\n%s", s.output.String())
	}
	// On loopback the token never leaves the host, so there is no warning
	// that it is sent in clear (runner.WarnMetricsTokenInClear).
	if strings.Contains(s.output.String(), "metrics token in clear") {
		t.Fatalf("a loopback metrics listener warned that the token is sent in clear:\n%s", s.output.String())
	}
	data, _ := os.ReadFile(tokenFile)
	token := strings.TrimSpace(string(data))
	if code, body, _ := s.do(request{method: "POST", path: "/api/v1/consensus/sign/" + c.Pubkey, token: s.signToken(),
		contentType: "application/json", body: bytes.NewReader(c.RequestJSON)}); code != 200 {
		t.Fatalf("sign: %d %.120s", code, body)
	}
	url := "http://127.0.0.1:" + s.metricsPort() + "/metrics"
	for tok, want := range map[string]int{"": 401, s.signToken(): 401, s.adminToken(): 401, token: 200} {
		code, _, err := call(http.DefaultClient, http.MethodGet, url, tok)
		if err != nil || code != want {
			t.Errorf("scrape with token %.6s: %d %v, want %d", tok, code, err, want)
		}
	}
	_, text, err := call(http.DefaultClient, http.MethodGet, url, token)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, `signing_requests_total{result="ok",type="AGGREGATION_SLOT"} 1`) {
		t.Fatal("the scrape does not show the signed request")
	}
	assertNoKeyLabels(t, text, c.Pubkey)

	// Rotation: a new token in the file and SIGHUP; the old one stops
	// working.
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	rotated := fmt.Sprintf("0x%x", raw)
	writeTestFile(t, tokenFile, []byte(rotated+"\n"))
	s.signal(syscall.SIGHUP)
	deadline := time.Now().Add(5 * time.Second)
	for {
		code, _, err := call(http.DefaultClient, http.MethodGet, url, rotated)
		if err == nil && code == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the rotated metrics token never worked: %d %v\n%s", code, err, s.output.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if code, _, err := call(http.DefaultClient, http.MethodGet, url, token); err != nil || code != 401 {
		t.Fatalf("the replaced metrics token after SIGHUP: %d %v, want 401", code, err)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	var b []byte
	if _, err := fmt.Sscanf(strings.TrimPrefix(s, "0x"), "%x", &b); err != nil {
		t.Fatal(err)
	}
	return b
}
