// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/server/auth"
	"github.com/rgeraldes24/go-remotesigner/internal/server/tlsconf"
)

// clientCert makes a self-signed client certificate.
func clientCert(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func knownClients(t *testing.T, path string, certs ...tls.Certificate) {
	t.Helper()
	var b strings.Builder
	for i, c := range certs {
		fmt.Fprintf(&b, "client-%d %s\n", i, tlsconf.FingerprintOf(c.Certificate[0]))
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The API over TLS in mode mtls: h2 is negotiated, a known client
// certificate grants the sign scope only, and a client removed by a reload
// loses its scope on the connection it already has open.
func TestServeMTLS(t *testing.T) {
	dir := t.TempDir()
	vc := clientCert(t, "vc")
	known := filepath.Join(dir, "known-clients")
	knownClients(t, known, vc)
	tc, err := tlsconf.New(tlsconf.Config{GenerateSelfSigned: true, KnownClientsFile: known}, tlsconf.Options{
		SelfSignedDir: filepath.Join(dir, "tls"), SelfSignedHosts: []string{"localhost"}, RequireClientCert: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	adminFile := filepath.Join(dir, "admin")
	if err := os.WriteFile(adminFile, []byte(adminTok), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := auth.New(auth.Config{Mode: auth.ModeMTLS, AdminTokenFile: adminFile, VerifyClient: tc.VerifyClient})
	if err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t, func(c *Config) { c.Auth, c.TLS = a, tc.TLSConfig() })
	base := "https://localhost:" + strings.TrimPrefix(serve(t, s), "http://127.0.0.1:")

	pemData, err := os.ReadFile(filepath.Join(dir, "tls", tlsconf.SelfSignedCertFile))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pemData)
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{vc}},
		ForceAttemptHTTP2: true,
	}}
	do := func(method, path, tok string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, base+path, nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		if resp.ProtoMajor != 2 {
			t.Errorf("%s %s over %s, want h2", method, path, resp.Proto)
		}
		return resp.StatusCode, string(body)
	}

	if code, body := do(http.MethodGet, "/sign", ""); code != 200 || body != "ok" {
		t.Fatalf("sign route with the certificate: %d %s", code, body)
	}
	if code, body := do(http.MethodPost, "/admin", ""); code != 403 || !strings.Contains(body, "FORBIDDEN_SCOPE") {
		t.Fatalf("admin route with the certificate alone: %d %s", code, body)
	}
	if code, _ := do(http.MethodPost, "/admin", adminTok); code != 200 {
		t.Fatalf("admin route with the certificate and the admin token: %d", code)
	}

	// Remove the client and reload: the open h2 connection is refused at its
	// next request.
	knownClients(t, known, clientCert(t, "someone-else"))
	if _, err := tc.Reload(); err != nil {
		t.Fatal(err)
	}
	if code, body := do(http.MethodGet, "/sign", ""); code != 401 || !strings.Contains(body, "UNAUTHENTICATED") {
		t.Fatalf("removed client on its open connection: %d %s", code, body)
	}

	// Plaintext HTTP is not served on the TLS port.
	resp, err := http.Get(strings.Replace(base, "https://", "http://", 1) + "/open")
	if err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("plaintext request: %d", resp.StatusCode)
		}
	}
}
