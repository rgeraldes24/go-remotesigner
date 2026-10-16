// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package tlsconf

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		mtls bool
		want error
	}{
		{"plaintext", Config{}, false, nil},
		{"pem", Config{CertFile: "c", KeyFile: "k"}, false, nil},
		{"pkcs12", Config{KeystoreFile: "p", KeystorePasswordFile: "pw"}, false, nil},
		{"self-signed", Config{GenerateSelfSigned: true}, false, nil},
		{"cert without key", Config{CertFile: "c"}, false, ErrCertWithoutKey},
		{"key without cert", Config{KeyFile: "k"}, false, ErrCertWithoutKey},
		{"keystore without password", Config{KeystoreFile: "p"}, false, ErrKeystoreNoPassword},
		{"password without keystore", Config{KeystorePasswordFile: "pw"}, false, ErrKeystoreNoPassword},
		{"pem and pkcs12", Config{CertFile: "c", KeyFile: "k", KeystoreFile: "p", KeystorePasswordFile: "pw"}, false, ErrTwoCertificates},
		{"mtls without TLS", Config{KnownClientsFile: "kc"}, true, ErrMTLSWithoutTLS},
		{"mtls without trust", Config{GenerateSelfSigned: true}, true, ErrMTLSWithoutTrust},
		{"mtls, known clients", Config{GenerateSelfSigned: true, KnownClientsFile: "kc"}, true, nil},
		{"mtls, CA", Config{CertFile: "c", KeyFile: "k", ClientCAFile: "ca"}, true, nil},
		{"mtls, both", Config{CertFile: "c", KeyFile: "k", ClientCAFile: "ca", KnownClientsFile: "kc"}, true, nil},
		{"known clients without TLS", Config{KnownClientsFile: "kc"}, false, ErrClientTrustWithoutTLS},
		{"CA in token mode", Config{GenerateSelfSigned: true, ClientCAFile: "ca"}, false, ErrClientTrustNotMTLS},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cfg.Validate(tt.mtls); !errors.Is(err, tt.want) {
				t.Fatalf("Validate = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestFingerprint(t *testing.T) {
	var f Fingerprint
	for i := range f {
		f[i] = byte(i * 9)
	}
	s := f.String()
	if !strings.HasPrefix(s, "00:09:12:1B:") || len(s) != 95 {
		t.Fatalf("String = %s", s)
	}
	for _, in := range []string{s, strings.ToLower(s), strings.ReplaceAll(s, ":", "")} {
		if got, err := ParseFingerprint(in); err != nil || got != f {
			t.Errorf("ParseFingerprint(%s) = %v, %v", in, got, err)
		}
	}
	for _, in := range []string{"", s[:94], s + ":00", strings.Replace(s, "00", "zz", 1)} {
		if _, err := ParseFingerprint(in); err == nil {
			t.Errorf("ParseFingerprint(%q) accepted", in)
		}
	}
}

func TestLoadKnownClients(t *testing.T) {
	dir := t.TempDir()
	a, b := FingerprintOf([]byte("a")), FingerprintOf([]byte("b"))
	ok := writeFile(t, filepath.Join(dir, "ok"), []byte(fmt.Sprintf(
		"# Web3Signer format\n\nlocalhost %s\n127.0.0.1:9000 %s\n  vc-2   %s  \n",
		strings.ToLower(a.String()), a, strings.ReplaceAll(b.String(), ":", ""))))
	known, err := loadKnownClients(ok)
	if err != nil {
		t.Fatal(err)
	}
	if len(known) != 2 {
		t.Fatalf("%d clients, want 2", len(known))
	}
	for _, f := range []Fingerprint{a, b} {
		if _, ok := known[f]; !ok {
			t.Errorf("%s missing", f)
		}
	}
	bad := map[string]string{
		"one field":   a.String() + "\n",
		"three":       "x " + a.String() + " y\n",
		"short":       "x 00:11\n",
		"not hex":     "x " + strings.Repeat("zz", 32) + "\n",
		"second line": "x " + a.String() + "\ny\n",
	}
	for name, content := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := loadKnownClients(writeFile(t, filepath.Join(dir, "bad"), []byte(content))); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, err := loadKnownClients(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file accepted")
	}
	// A file that lists nobody parses to an empty set; New refuses it at
	// startup (TestNewRefusesEmptyTrust), and a reload accepts it.
	if known, err := loadKnownClients(writeFile(t, filepath.Join(dir, "nobody"), []byte("# nobody\n\n"))); err != nil || known == nil || len(known) != 0 {
		t.Fatalf("a file listing nobody: %v, %v", known, err)
	}
}

// At startup a known-clients file that lists nobody, or a CA file without a
// certificate, is a mistake and refuses the start.
func TestNewRefusesEmptyTrust(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writePEM(t, dir, "server", serverPair(t))
	empty := writeFile(t, filepath.Join(dir, "empty"), []byte("# nobody yet\n"))
	for _, tt := range []struct {
		cfg  Config
		want string
	}{
		{Config{KnownClientsFile: empty}, "lists no client"},
		{Config{ClientCAFile: empty}, "no PEM certificate"},
	} {
		tt.cfg.CertFile, tt.cfg.KeyFile = certFile, keyFile
		if _, err := New(tt.cfg, Options{RequireClientCert: true}); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("New(%+v) = %v, want %q", tt.cfg, err, tt.want)
		}
	}
}

// TLS 1.2 and below are refused; TLS 1.3 negotiates X25519MLKEM768 when
// the client offers it (Go's default).
func TestTLS13Only(t *testing.T) {
	dir := t.TempDir()
	srv := serverPair(t)
	certFile, keyFile := writePEM(t, dir, "server", srv)
	s, err := New(Config{CertFile: certFile, KeyFile: keyFile}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	addr := serve(t, s.TLSConfig())
	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12} {
		cfg := clientConfig(srv, nil)
		cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS10, v
		if _, err := connect(addr, cfg); !isRefused(err) {
			t.Errorf("version %x: %v, want a refused handshake", v, err)
		}
	}
	cs, err := connect(addr, clientConfig(srv, nil))
	if err != nil {
		t.Fatal(err)
	}
	if cs.Version != tls.VersionTLS13 || cs.CurveID != tls.X25519MLKEM768 {
		t.Fatalf("version %x, group %v", cs.Version, cs.CurveID)
	}
	if info := s.Info(); info.Source != SourcePEM || info.Fingerprint != srv.fingerprint() || info.ClientAuth != ClientAuthNone {
		t.Fatalf("Info %+v", info)
	}
}

func TestPKCS12(t *testing.T) {
	dir := t.TempDir()
	ca := issue(t, nil, "ca", true, 0)
	srv := issue(t, &ca, "server", false, x509.ExtKeyUsageServerAuth, "localhost")
	other := serverPair(t)
	password := writeFile(t, filepath.Join(dir, "password"), []byte("s3cret\nignored second line\n"))
	encoders := map[string]*pkcs12.Encoder{"modern": pkcs12.Modern, "legacy": pkcs12.LegacyRC2}
	for name, enc := range encoders {
		t.Run(name, func(t *testing.T) {
			data, err := enc.Encode(srv.key, srv.cert, []*x509.Certificate{ca.cert}, "s3cret")
			if err != nil {
				t.Fatal(err)
			}
			ks := writeFile(t, filepath.Join(dir, name+".p12"), data)
			s, err := New(Config{KeystoreFile: ks, KeystorePasswordFile: password}, Options{})
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			roots.AddCert(ca.cert)
			cs, err := connect(serve(t, s.TLSConfig()), &tls.Config{RootCAs: roots, ServerName: "localhost"})
			if err != nil {
				t.Fatal(err)
			}
			if len(cs.PeerCertificates) != 2 || s.Info().Source != SourcePKCS12 {
				t.Fatalf("chain of %d, Info %+v", len(cs.PeerCertificates), s.Info())
			}
		})
	}

	good, _ := pkcs12.Modern.Encode(srv.key, srv.cert, nil, "s3cret")
	mismatched, _ := pkcs12.Modern.Encode(other.key, srv.cert, nil, "s3cret")
	refusals := []struct {
		name, keystore, password string
		want                     string
	}{
		{"wrong password", writeFile(t, filepath.Join(dir, "good.p12"), good), writeFile(t, filepath.Join(dir, "wrong"), []byte("nope\n")), "decryption password incorrect"},
		{"empty password file", filepath.Join(dir, "good.p12"), writeFile(t, filepath.Join(dir, "empty"), nil), "empty file"},
		{"missing keystore", filepath.Join(dir, "missing.p12"), password, "no such file"},
		{"key of another certificate", writeFile(t, filepath.Join(dir, "mismatched.p12"), mismatched), password, "does not match"},
	}
	for _, tt := range refusals {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(Config{KeystoreFile: tt.keystore, KeystorePasswordFile: tt.password}, Options{})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("New = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestPEMRefusals(t *testing.T) {
	dir := t.TempDir()
	certFile, _ := writePEM(t, dir, "a", serverPair(t))
	_, otherKey := writePEM(t, dir, "b", serverPair(t))
	if _, err := New(Config{CertFile: certFile, KeyFile: otherKey}, Options{}); err == nil {
		t.Fatal("a key of another certificate was accepted")
	}
	if _, err := New(Config{CertFile: certFile, KeyFile: filepath.Join(dir, "missing")}, Options{}); err == nil {
		t.Fatal("a missing key was accepted")
	}
}

// --tls-generate-self-signed writes a 0600 P-256 certificate and key once,
// valid for the allowlist names, and reuses them on the next start; a
// configured certificate takes precedence.
func TestSelfSigned(t *testing.T) {
	data := t.TempDir()
	dir := filepath.Join(data, "tls")
	hosts := []string{"localhost", "127.0.0.1", "::1", "Signer.Internal"}
	s, err := New(Config{GenerateSelfSigned: true}, Options{SelfSignedDir: dir, SelfSignedHosts: hosts})
	if err != nil {
		t.Fatal(err)
	}
	info := s.Info()
	if !info.Generated || info.Source != SourceSelfSigned || info.Path != filepath.Join(dir, SelfSignedCertFile) || len(info.Uncovered) != 0 {
		t.Fatalf("Info %+v", info)
	}
	for _, name := range []string{SelfSignedCertFile, SelfSignedKeyFile} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", name, fi, err)
		}
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("directory: %v %v", fi, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Fatalf("directory holds %d files, want 2", len(entries))
	}

	pemData, _ := os.ReadFile(filepath.Join(dir, SelfSignedCertFile))
	block, _ := pem.Decode(pemData)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if FingerprintOf(leaf.Raw) != info.Fingerprint {
		t.Fatal("the logged fingerprint is not the file's")
	}
	if leaf.PublicKeyAlgorithm != x509.ECDSA || leaf.NotAfter.Before(time.Now().Add(9*365*24*time.Hour)) {
		t.Fatalf("algorithm %v, not after %v", leaf.PublicKeyAlgorithm, leaf.NotAfter)
	}
	if !slices.Equal(leaf.DNSNames, []string{"localhost", "signer.internal"}) || len(leaf.IPAddresses) != 2 {
		t.Fatalf("SANs %v %v", leaf.DNSNames, leaf.IPAddresses)
	}

	// A client pinning the certificate file as its CA connects by every name.
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pemData)
	addr := serve(t, s.TLSConfig())
	for _, name := range []string{"localhost", "signer.internal", "127.0.0.1", "::1"} {
		if _, err := connect(addr, &tls.Config{RootCAs: roots, ServerName: name}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	// The next start reuses the files, and warns about a name it lacks.
	again, err := New(Config{GenerateSelfSigned: true}, Options{SelfSignedDir: dir, SelfSignedHosts: append(hosts, "new.example")})
	if err != nil {
		t.Fatal(err)
	}
	if ai := again.Info(); ai.Generated || ai.Fingerprint != info.Fingerprint || !slices.Equal(ai.Uncovered, []string{"new.example"}) {
		t.Fatalf("reuse Info %+v", ai)
	}

	// A mounted certificate takes precedence and nothing is generated.
	mounted := t.TempDir()
	srv := serverPair(t)
	certFile, keyFile := writePEM(t, mounted, "server", srv)
	other := filepath.Join(t.TempDir(), "tls")
	m, err := New(Config{CertFile: certFile, KeyFile: keyFile, GenerateSelfSigned: true}, Options{SelfSignedDir: other, SelfSignedHosts: hosts})
	if err != nil {
		t.Fatal(err)
	}
	if m.Info().Source != SourcePEM || m.Info().Fingerprint != srv.fingerprint() {
		t.Fatalf("Info %+v", m.Info())
	}
	if _, err := os.Stat(other); !os.IsNotExist(err) {
		t.Fatalf("a certificate was generated next to a mounted one: %v", err)
	}
}

func TestSelfSignedRefusals(t *testing.T) {
	if _, err := New(Config{GenerateSelfSigned: true}, Options{SelfSignedDir: t.TempDir(), SelfSignedHosts: []string{"*"}}); !errors.Is(err, ErrNoHostNames) {
		t.Fatalf("wildcard allowlist: %v", err)
	}
	if _, err := New(Config{GenerateSelfSigned: true}, Options{SelfSignedHosts: []string{"localhost"}}); err == nil {
		t.Fatal("no directory accepted")
	}
	// A certificate whose key is gone is refused, not replaced.
	dir := filepath.Join(t.TempDir(), "tls")
	if _, err := New(Config{GenerateSelfSigned: true}, Options{SelfSignedDir: dir, SelfSignedHosts: []string{"localhost"}}); err != nil {
		t.Fatal(err)
	}
	certBefore, _ := os.ReadFile(filepath.Join(dir, SelfSignedCertFile))
	if err := os.Remove(filepath.Join(dir, SelfSignedKeyFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{GenerateSelfSigned: true}, Options{SelfSignedDir: dir, SelfSignedHosts: []string{"localhost"}}); err == nil ||
		!strings.Contains(err.Error(), "without") {
		t.Fatalf("certificate without key: %v", err)
	}
	if certAfter, _ := os.ReadFile(filepath.Join(dir, SelfSignedCertFile)); string(certAfter) != string(certBefore) {
		t.Fatal("the pinned certificate was replaced")
	}
	// A key without its certificate (an interrupted first start) is replaced.
	if err := os.Remove(filepath.Join(dir, SelfSignedCertFile)); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, SelfSignedKeyFile), []byte("stale"), 0o600)
	s, err := New(Config{GenerateSelfSigned: true}, Options{SelfSignedDir: dir, SelfSignedHosts: []string{"localhost"}})
	if err != nil || !s.Info().Generated {
		t.Fatalf("stale key: %v", err)
	}
}

// Rotating the generated certificate: after both files are deleted, a
// reload generates a new pair; a reload with the files in place keeps the
// pinned certificate.
func TestSelfSignedRotation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	s, err := New(Config{GenerateSelfSigned: true}, Options{SelfSignedDir: dir, SelfSignedHosts: []string{"localhost"}})
	if err != nil {
		t.Fatal(err)
	}
	first := s.Info().Fingerprint
	info, err := s.Reload()
	if err != nil || info.Generated || info.Fingerprint != first {
		t.Fatalf("reload with the files in place: %+v %v", info, err)
	}
	for _, name := range []string{SelfSignedCertFile, SelfSignedKeyFile} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	info, err = s.Reload()
	if err != nil || !info.Generated || info.Fingerprint == first || s.Info().Fingerprint != info.Fingerprint {
		t.Fatalf("reload after deleting the files: %+v %v", info, err)
	}
}

// mtlsServer starts a server that requires a client certificate under cfg.
func mtlsServer(t *testing.T, cfg Config) (*Server, pair, string) {
	t.Helper()
	srv := serverPair(t)
	cfg.CertFile, cfg.KeyFile = writePEM(t, t.TempDir(), "server", srv)
	s, err := New(cfg, Options{RequireClientCert: true})
	if err != nil {
		t.Fatal(err)
	}
	return s, srv, serve(t, s.TLSConfig())
}

func knownClientsFile(t *testing.T, path string, clients ...pair) string {
	t.Helper()
	var b strings.Builder
	for i, c := range clients {
		fmt.Fprintf(&b, "client-%d %s\n", i, c.fingerprint())
	}
	return writeFile(t, path, []byte(b.String()))
}

// Fingerprint mode: a known client connects; an unknown certificate and no
// certificate are refused.
func TestKnownClients(t *testing.T) {
	known, unknown := clientPair(t, nil, "vc"), clientPair(t, nil, "intruder")
	s, srv, addr := mtlsServer(t, Config{KnownClientsFile: knownClientsFile(t, filepath.Join(t.TempDir(), "known"), known)})
	if info := s.Info(); info.ClientAuth != ClientAuthKnownClients || info.KnownClients != 1 {
		t.Fatalf("Info %+v", info)
	}
	kc, uc := known.tlsCert(), unknown.tlsCert()
	if _, err := connect(addr, clientConfig(srv, &kc)); err != nil {
		t.Fatalf("known client: %v", err)
	}
	if _, err := connect(addr, clientConfig(srv, &uc)); !isRefused(err) {
		t.Fatalf("unknown client: %v", err)
	}
	if _, err := connect(addr, clientConfig(srv, nil)); !isRefused(err) {
		t.Fatalf("no client certificate: %v", err)
	}
	for _, c := range []struct {
		cert pair
		want error
	}{{known, nil}, {unknown, ErrUnknownClient}} {
		if err := s.VerifyClient(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{c.cert.cert}}); !errors.Is(err, c.want) {
			t.Errorf("VerifyClient(%s) = %v, want %v", c.cert.cert.Subject.CommonName, err, c.want)
		}
	}
	if err := s.VerifyClient(&tls.ConnectionState{}); !errors.Is(err, ErrNoClientCert) {
		t.Errorf("VerifyClient without a certificate = %v", err)
	}
}

// countingCache records the sessions the client offers for resumption.
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

// G4 S6: a client whose trust is withdrawn by a reload cannot resume its
// session. Session tickets survive a reload (the control case below
// resumes after one), so the refusal comes from VerifyConnection, which
// runs on resumed handshakes too.
func TestResumedSessionRechecked(t *testing.T) {
	for _, mode := range []string{"known-clients", "ca"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			ca := issue(t, nil, "ca", true, 0)
			other := issue(t, nil, "other-ca", true, 0)
			client, bystander := clientPair(t, &ca, "vc"), clientPair(t, &other, "bystander")
			path := filepath.Join(dir, "trust")
			trustAll := func(withClient bool) {
				switch {
				case mode == "ca" && withClient:
					writeFile(t, path, certPEM(ca.cert, other.cert))
				case mode == "ca":
					writeFile(t, path, certPEM(other.cert))
				case withClient:
					knownClientsFile(t, path, client, bystander)
				default:
					knownClientsFile(t, path, bystander)
				}
			}
			trustAll(true)
			cfg := Config{KnownClientsFile: path}
			if mode == "ca" {
				cfg = Config{ClientCAFile: path}
			}
			s, srv, addr := mtlsServer(t, cfg)
			cc := client.tlsCert(ca)
			clientCfg := clientConfig(srv, &cc)
			cache := &countingCache{ClientSessionCache: tls.NewLRUClientSessionCache(4)}
			clientCfg.ClientSessionCache = cache

			if cs, err := connect(addr, clientCfg); err != nil || cs.DidResume {
				t.Fatalf("first handshake: resumed %v, %v", cs.DidResume, err)
			}
			cs, err := connect(addr, clientCfg)
			if err != nil || !cs.DidResume {
				t.Fatalf("second handshake: resumed %v, %v", cs.DidResume, err)
			}
			// Control: a reload that keeps the client still lets it resume.
			if _, err := s.Reload(); err != nil {
				t.Fatal(err)
			}
			if cs, err := connect(addr, clientCfg); err != nil || !cs.DidResume {
				t.Fatalf("after a reload keeping the client: resumed %v, %v", cs.DidResume, err)
			}
			// Withdraw the client's trust: its offered session is refused.
			trustAll(false)
			if _, err := s.Reload(); err != nil {
				t.Fatal(err)
			}
			before := cache.offered.Load()
			if _, err := connect(addr, clientCfg); !isRefused(err) {
				t.Fatalf("resumed handshake after removal: %v, want refused", err)
			}
			if cache.offered.Load() == before {
				t.Fatal("the client offered no session, so resumption was not exercised")
			}
			if err := s.VerifyClient(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{client.cert, ca.cert}}); !errors.Is(err, ErrUnknownClient) {
				t.Fatalf("VerifyClient after removal = %v", err)
			}
		})
	}
}

// CA mode verifies client chains against --tls-client-ca-file only: a
// client of another CA, a server-auth-only certificate, and a system root
// are refused, and the pool Go verifies with is the file's.
func TestClientCA(t *testing.T) {
	ca := issue(t, nil, "ca", true, 0)
	inter := issue(t, &ca, "intermediate", true, 0)
	direct, chained := clientPair(t, &ca, "vc-1"), clientPair(t, &inter, "vc-2")
	foreign := clientPair(t, nil, "self-signed")
	serverOnly := issue(t, &ca, "not-a-client", false, x509.ExtKeyUsageServerAuth)
	s, srv, addr := mtlsServer(t, Config{ClientCAFile: writeFile(t, filepath.Join(t.TempDir(), "ca.pem"), certPEM(ca.cert))})
	g := s.cur.Load()
	if g.config.ClientAuth != tls.RequireAndVerifyClientCert || g.config.ClientCAs == nil || g.config.ClientCAs != g.trust.pool {
		t.Fatalf("CA mode config: %v, pool %p", g.config.ClientAuth, g.config.ClientCAs)
	}
	ok := []tls.Certificate{direct.tlsCert(), chained.tlsCert(inter)}
	for i := range ok {
		if _, err := connect(addr, clientConfig(srv, &ok[i])); err != nil {
			t.Errorf("client %d: %v", i, err)
		}
	}
	refused := []tls.Certificate{foreign.tlsCert(), serverOnly.tlsCert(), chained.tlsCert()}
	for i := range refused {
		if _, err := connect(addr, clientConfig(srv, &refused[i])); !isRefused(err) {
			t.Errorf("refused client %d: %v", i, err)
		}
	}
}

// The system roots never vouch for a client. The pool Go verifies CA-mode
// handshakes with is exactly the certificates of --tls-client-ca-file (a nil
// pool would mean the system roots), and a root certificate of the host's
// bundle fails the client check in both CA modes.
func TestClientCANeverTrustsSystemRoots(t *testing.T) {
	ca := issue(t, nil, "ca", true, 0)
	caFile := writeFile(t, filepath.Join(t.TempDir(), "ca.pem"), certPEM(ca.cert))
	want := x509.NewCertPool()
	want.AddCert(ca.cert)
	s, _, _ := mtlsServer(t, Config{ClientCAFile: caFile})
	g := s.cur.Load()
	if g.config.ClientCAs == nil || !g.config.ClientCAs.Equal(want) || !g.trust.pool.Equal(want) {
		t.Fatal("the CA-mode pool is not exactly the --tls-client-ca-file certificates")
	}
	if sys, err := x509.SystemCertPool(); err == nil && g.config.ClientCAs.Equal(sys) {
		t.Fatal("the CA-mode pool is the system pool")
	}
	both, _, _ := mtlsServer(t, Config{
		ClientCAFile:     caFile,
		KnownClientsFile: knownClientsFile(t, filepath.Join(t.TempDir(), "known"), clientPair(t, nil, "vc")),
	})
	if gb := both.cur.Load(); gb.config.ClientCAs != nil || !gb.trust.pool.Equal(want) {
		t.Fatal("known-clients+ca: Go must not verify the chain, and the pool must be the file's")
	}
	root := bundleRoot(t)
	if root == nil {
		t.Log("no root certificate bundle on this host; the pool checks above still apply")
		return
	}
	for name, srv := range map[string]*Server{"ca": s, "known-clients+ca": both} {
		if err := srv.VerifyClient(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{root}}); !errors.Is(err, ErrUnknownClient) {
			t.Errorf("%s: a root of the host's bundle was accepted: %v", name, err)
		}
	}
}

// bundleRoot returns a CA certificate without extended key usages (so one
// valid for client auth) from the host's root bundle, or nil.
func bundleRoot(t *testing.T) *x509.Certificate {
	t.Helper()
	for _, bundle := range []string{"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"} {
		data, err := os.ReadFile(bundle)
		if err != nil {
			continue
		}
		for rest := data; ; {
			var block *pem.Block
			if block, rest = pem.Decode(rest); block == nil {
				break
			}
			if c, err := x509.ParseCertificate(block.Bytes); err == nil && c.IsCA && len(c.ExtKeyUsage) == 0 {
				return c
			}
		}
	}
	return nil
}

// Both trust sources together: either accepts a client.
func TestKnownClientsAndCA(t *testing.T) {
	ca := issue(t, nil, "ca", true, 0)
	pinned, issued, neither := clientPair(t, nil, "pinned"), clientPair(t, &ca, "issued"), clientPair(t, nil, "neither")
	s, srv, addr := mtlsServer(t, Config{
		ClientCAFile:     writeFile(t, filepath.Join(t.TempDir(), "ca.pem"), certPEM(ca.cert)),
		KnownClientsFile: knownClientsFile(t, filepath.Join(t.TempDir(), "known"), pinned),
	})
	if s.Info().ClientAuth != ClientAuthKnownClientsCA {
		t.Fatalf("Info %+v", s.Info())
	}
	for _, c := range []struct {
		p  pair
		ok bool
	}{{pinned, true}, {issued, true}, {neither, false}} {
		tc := c.p.tlsCert()
		_, err := connect(addr, clientConfig(srv, &tc))
		if c.ok != (err == nil) {
			t.Errorf("%s: %v", c.p.cert.Subject.CommonName, err)
		}
	}
}

// Reload swaps the certificate; a failed reload keeps the previous one.
func TestReload(t *testing.T) {
	dir := t.TempDir()
	first, second := serverPair(t), serverPair(t)
	certFile, keyFile := writePEM(t, dir, "server", first)
	s, err := New(Config{CertFile: certFile, KeyFile: keyFile}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	addr := serve(t, s.TLSConfig())
	peer := func() Fingerprint {
		t.Helper()
		cs, err := connect(addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // the test reads the served certificate
		if err != nil {
			t.Fatal(err)
		}
		return FingerprintOf(cs.PeerCertificates[0].Raw)
	}
	if peer() != first.fingerprint() {
		t.Fatal("not the first certificate")
	}
	writePEM(t, dir, "server", second)
	info, err := s.Reload()
	if err != nil || info.Fingerprint != second.fingerprint() || peer() != second.fingerprint() {
		t.Fatalf("after reload: %+v %v", info, err)
	}
	if err := os.WriteFile(keyFile, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = s.Reload()
	if re := (*ReloadError)(nil); !errors.As(err, &re) || re.Certificate == nil || re.ClientTrust != nil {
		t.Fatalf("a broken key reloaded: %v", err)
	}
	if peer() != second.fingerprint() || s.Info().Fingerprint != second.fingerprint() {
		t.Fatal("a failed reload replaced the certificate")
	}
}

// Removing the last client by a reload revokes it. Emptying the trust file
// is a valid reload that accepts nobody; a trust file that fails to load
// (deleted, or a line that does not parse) fails closed and refuses every
// client. Either way the removed client can neither handshake nor resume,
// and VerifyClient refuses its open connections; a later good reload
// restores it.
func TestReloadRevokesTheLastClient(t *testing.T) {
	for _, mode := range []string{"known-clients", "ca", "known-clients+ca"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			ca := issue(t, nil, "ca", true, 0)
			client := clientPair(t, &ca, "vc")
			knownPath, caPath := filepath.Join(dir, "known"), filepath.Join(dir, "ca.pem")
			var cfg Config
			// trust lists the client in every configured file, or nobody.
			trust := func(withClient bool) {
				if mode != "ca" {
					cfg.KnownClientsFile = knownPath
					if withClient {
						knownClientsFile(t, knownPath, client)
					} else {
						writeFile(t, knownPath, []byte("# vc revoked\n"))
					}
				}
				if mode != "known-clients" {
					cfg.ClientCAFile = caPath
					if withClient {
						writeFile(t, caPath, certPEM(ca.cert))
					} else {
						writeFile(t, caPath, []byte("# no CA\n"))
					}
				}
			}
			trust(true)
			s, srv, addr := mtlsServer(t, cfg)
			cc := client.tlsCert(ca)
			clientCfg := clientConfig(srv, &cc)
			cache := &countingCache{ClientSessionCache: tls.NewLRUClientSessionCache(4)}
			clientCfg.ClientSessionCache = cache
			open := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{client.cert, ca.cert}}
			accepted := func(when string) {
				t.Helper()
				if _, err := connect(addr, clientCfg); err != nil {
					t.Fatalf("%s: handshake: %v", when, err)
				}
				if err := s.VerifyClient(open); err != nil {
					t.Fatalf("%s: VerifyClient = %v", when, err)
				}
			}
			refused := func(when string) {
				t.Helper()
				before := cache.offered.Load()
				if _, err := connect(addr, clientCfg); !isRefused(err) {
					t.Fatalf("%s: resumed handshake %v, want refused", when, err)
				}
				if cache.offered.Load() == before {
					t.Fatalf("%s: the client offered no session, so resumption was not exercised", when)
				}
				if _, err := connect(addr, clientConfig(srv, &cc)); !isRefused(err) {
					t.Fatalf("%s: full handshake %v, want refused", when, err)
				}
				if err := s.VerifyClient(open); !errors.Is(err, ErrUnknownClient) {
					t.Fatalf("%s: VerifyClient on an open connection = %v, want %v", when, err, ErrUnknownClient)
				}
			}
			accepted("start")
			accepted("resumed") // leaves a session ticket in the cache

			trust(false)
			info, err := s.Reload()
			if err != nil || info.KnownClients != 0 || info.ClientCAs != 0 || info.ClientAuth != s.Info().ClientAuth || info.ClientAuth == ClientAuthRefused {
				t.Fatalf("reload of an emptied trust: %+v %v", info, err)
			}
			refused("emptied")

			trust(true)
			if _, err := s.Reload(); err != nil {
				t.Fatal(err)
			}
			accepted("restored")

			broken := map[string]func(){
				"deleted": func() { _ = os.Remove(knownPath); _ = os.Remove(caPath) },
				"garbage": func() {
					if mode != "ca" {
						writeFile(t, knownPath, []byte("vc not-a-fingerprint\n"))
					}
					if mode != "known-clients" {
						writeFile(t, caPath, []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))
					}
				},
			}
			for _, name := range []string{"deleted", "garbage"} {
				broken[name]()
				info, err := s.Reload()
				var re *ReloadError
				if !errors.As(err, &re) || re.ClientTrust == nil || re.Certificate != nil {
					t.Fatalf("%s: reload error %v, want a client-trust ReloadError", name, err)
				}
				if info.ClientAuth != ClientAuthRefused || s.Info().ClientAuth != ClientAuthRefused || info.Fingerprint != srv.fingerprint() {
					t.Fatalf("%s: Info %+v", name, info)
				}
				refused(name)
				trust(true)
				if _, err := s.Reload(); err != nil {
					t.Fatal(err)
				}
				accepted(name + ", then restored")
			}
		})
	}
}

// A certificate that fails to reload keeps the previous one, while the
// client trust reloaded with it still takes effect.
func TestReloadBrokenCertificateStillAppliesTrust(t *testing.T) {
	dir := t.TempDir()
	client := clientPair(t, nil, "vc")
	known := knownClientsFile(t, filepath.Join(dir, "known"), client)
	srv := serverPair(t)
	certFile, keyFile := writePEM(t, dir, "server", srv)
	s, err := New(Config{CertFile: certFile, KeyFile: keyFile, KnownClientsFile: known}, Options{RequireClientCert: true})
	if err != nil {
		t.Fatal(err)
	}
	addr := serve(t, s.TLSConfig())
	cc := client.tlsCert()
	if _, err := connect(addr, clientConfig(srv, &cc)); err != nil {
		t.Fatal(err)
	}
	writeFile(t, keyFile, []byte("garbage"))
	writeFile(t, known, []byte("# vc revoked\n"))
	info, err := s.Reload()
	var re *ReloadError
	if !errors.As(err, &re) || re.Certificate == nil || re.ClientTrust != nil {
		t.Fatalf("reload error %v, want a certificate ReloadError", err)
	}
	if info.Fingerprint != srv.fingerprint() || info.KnownClients != 0 || info.ClientAuth != ClientAuthKnownClients {
		t.Fatalf("Info %+v", info)
	}
	if _, err := connect(addr, clientConfig(srv, &cc)); !isRefused(err) {
		t.Fatalf("the revoked client connected: %v", err)
	}
}

func TestNewNeedsACertificate(t *testing.T) {
	if _, err := New(Config{}, Options{}); err == nil {
		t.Fatal("New without TLS succeeded")
	}
	if _, err := New(Config{GenerateSelfSigned: true}, Options{SelfSignedDir: t.TempDir(), SelfSignedHosts: []string{"localhost"}, RequireClientCert: true}); !errors.Is(err, ErrMTLSWithoutTrust) {
		t.Fatalf("mtls without trust: %v", err)
	}
}
