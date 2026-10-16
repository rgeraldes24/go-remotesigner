// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package runner

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

	"github.com/rgeraldes24/go-remotesigner/internal/consensus/signingroot"
	"github.com/rgeraldes24/go-remotesigner/internal/hygiene"
	"github.com/rgeraldes24/go-remotesigner/internal/server/auth"
	"github.com/rgeraldes24/go-remotesigner/internal/server/tlsconf"
)

// G4 S16 over the full pipeline: a repeated hedged attestation gets the
// bytes released the first time, from the response cache, without a second
// slashing check.
func TestRunResponseCache(t *testing.T) {
	cfg := baseConfig(t)
	cfg.Metrics.Enabled, cfg.Metrics.Host, cfg.Metrics.HostAllowlist = true, "127.0.0.1", []string{"localhost"}
	writeInteropKeys(t, cfg.KeyConfigPath)
	r := start(t, cfg)
	r.waitReady(t)
	att := goldenCase(t, "minimal", signingroot.Attestation, "typical")
	var bodies []string
	for range 3 {
		code, body := r.post(t, signPath(att), r.sign, att.RequestJSON)
		if code != 200 {
			t.Fatalf("attestation: %d %s", code, body)
		}
		bodies = append(bodies, string(body))
	}
	if bodies[0] != bodies[1] || bodies[1] != bodies[2] {
		t.Fatal("a repeated hedged attestation got a different signature")
	}
	_, text := r.scrape(t, "localhost")
	for _, want := range []string{
		`signing_requests_total{result="ok",type="ATTESTATION"} 3`,
		`consensus_slashingprotection_permitted_signings_total 1`,
		`signing_mldsa87_signing_duration_seconds_count{type="ATTESTATION"} 1`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("scrape lacks %s", want)
		}
	}
}

// On Linux the process is not dumpable and has no core-file limit once the
// signer has started; elsewhere hygiene is a no-op and this is skipped.
func TestHygieneAfterStartup(t *testing.T) {
	if !hygiene.Supported {
		t.Skip("process hygiene acts on Linux only")
	}
	cfg := baseConfig(t)
	cfg.Hygiene = hygiene.Config{DisableCoreDumps: true}
	r := start(t, cfg)
	r.waitReady(t)
	dumpable, core, err := hygiene.State()
	if err != nil {
		t.Fatal(err)
	}
	if dumpable || core != 0 {
		t.Fatalf("after startup: PR_GET_DUMPABLE %v, RLIMIT_CORE %d; want 0 and 0", dumpable, core)
	}
}

func selfSignedClient(t *testing.T, cn string) tls.Certificate {
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

// The signer over TLS in mode mtls with a generated certificate: a known
// client certificate is the sign credential, admin routes need the admin
// token as well, and SIGHUP withdraws a removed client's scope at once.
func TestRunMTLS(t *testing.T) {
	cfg := baseConfig(t)
	vc := selfSignedClient(t, "vc")
	known := filepath.Join(cfg.DataPath, "known-clients")
	writeKnown := func(c tls.Certificate) {
		line := fmt.Sprintf("vc %s\n", tlsconf.FingerprintOf(c.Certificate[0]))
		if err := os.WriteFile(known, []byte(line), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeKnown(vc)
	cfg.HTTP.AuthMode = auth.ModeMTLS
	cfg.TLS = tlsconf.Config{GenerateSelfSigned: true, KnownClientsFile: known}
	r := start(t, cfg)
	pemData, err := os.ReadFile(filepath.Join(cfg.SelfSignedTLSPath(), tlsconf.SelfSignedCertFile))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pemData)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{vc}}}}
	base := strings.Replace(r.base, "http://", "https://", 1)
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
		return resp.StatusCode, string(body)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if code, _ := do(http.MethodGet, "/upcheck", ""); code == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("never ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if code, body := do(http.MethodGet, "/api/v1/consensus/capabilities", ""); code != 200 {
		t.Fatalf("capabilities with the certificate: %d %s", code, body)
	}
	if code, body := do(http.MethodPost, "/reload", ""); code != 403 || !strings.Contains(body, "FORBIDDEN_SCOPE") {
		t.Fatalf("POST /reload with the certificate alone: %d %s", code, body)
	}
	if code, body := do(http.MethodPost, "/reload", r.admin); code != 202 {
		t.Fatalf("POST /reload with the certificate and the admin token: %d %s", code, body)
	}

	writeKnown(selfSignedClient(t, "replacement"))
	r.hup <- struct{}{}
	deadline = time.Now().Add(5 * time.Second)
	for {
		code, _ := do(http.MethodGet, "/api/v1/consensus/capabilities", "")
		if code == 401 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("removed client still served after SIGHUP: %d", code)
		}
		time.Sleep(10 * time.Millisecond)
	}
	fresh := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{vc}}}}
	if resp, err := fresh.Get(base + "/upcheck"); err == nil {
		_ = resp.Body.Close()
		t.Fatalf("a new connection of the removed client was accepted: %d", resp.StatusCode)
	}
}
