// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
)

const (
	signTok  = "0x1111111111111111111111111111111111111111111111111111111111111111"
	adminTok = "0x2222222222222222222222222222222222222222222222222222222222222222"
	otherTok = "0x3333333333333333333333333333333333333333333333333333333333333333"
)

func writeToken(t *testing.T, dir, name, tok string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func request(tok string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
	return r
}

func reasonOf(e *apierr.Error) apierr.Reason {
	if e == nil {
		return ""
	}
	return e.Reason
}

// The scope matrix of the token modes (docs/contract.md section 6).
func TestScopeMatrix(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		SignTokenFile:  writeToken(t, dir, "sign", signTok),
		AdminTokenFile: writeToken(t, dir, "admin", adminTok),
	}
	tests := []struct {
		mode  Mode
		scope Scope
		tok   string
		want  apierr.Reason
	}{
		{ModeToken, ScopeNone, "", ""},
		{ModeToken, ScopeSign, "", apierr.Unauthenticated},
		{ModeToken, ScopeSign, otherTok, apierr.Unauthenticated},
		{ModeToken, ScopeSign, signTok, ""},
		{ModeToken, ScopeSign, adminTok, apierr.Unauthenticated},
		{ModeToken, ScopeAdmin, "", apierr.Unauthenticated},
		{ModeToken, ScopeAdmin, otherTok, apierr.Unauthenticated},
		{ModeToken, ScopeAdmin, signTok, apierr.ForbiddenScope},
		{ModeToken, ScopeAdmin, adminTok, ""},
		{ModeNone, ScopeSign, "", ""},
		{ModeNone, ScopeSign, otherTok, ""},
		{ModeNone, ScopeAdmin, "", apierr.Unauthenticated},
		{ModeNone, ScopeAdmin, signTok, apierr.Unauthenticated}, // no sign token exists in mode none
		{ModeNone, ScopeAdmin, adminTok, ""},
	}
	for _, tt := range tests {
		name := string(tt.mode) + "/" + tt.scope.String() + "/" + strings.TrimPrefix(tt.tok, "0x")[:min(4, len(tt.tok))]
		t.Run(name, func(t *testing.T) {
			c := cfg
			c.Mode = tt.mode
			a, err := New(c)
			if err != nil {
				t.Fatal(err)
			}
			if got := reasonOf(a.Check(request(tt.tok), tt.scope)); got != tt.want {
				t.Fatalf("Check = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBearerParsing(t *testing.T) {
	dir := t.TempDir()
	a, err := New(Config{Mode: ModeToken, SignTokenFile: writeToken(t, dir, "sign", signTok)})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"bearer " + signTok, "BEARER  " + signTok + " "} {
		r := request("")
		r.Header.Set("Authorization", h)
		if e := a.Check(r, ScopeSign); e != nil {
			t.Errorf("%q: %v", h, e)
		}
	}
	for _, h := range []string{"Basic " + signTok, signTok, "Bearer", "Bearer "} {
		r := request("")
		r.Header.Set("Authorization", h)
		if e := a.Check(r, ScopeSign); reasonOf(e) != apierr.Unauthenticated {
			t.Errorf("%q: got %v, want UNAUTHENTICATED", h, e)
		}
	}
}

func TestGeneratesTokenFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	cfg := Config{
		Mode:           ModeToken,
		SignTokenFile:  filepath.Join(dir, "auth-token"),
		AdminTokenFile: filepath.Join(dir, "admin-token"),
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !a.HasAdmin() {
		t.Fatal("HasAdmin = false with an admin token file")
	}
	var toks []string
	for _, p := range []string{cfg.SignTokenFile, cfg.AdminTokenFile} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %v, want 0600", p, fi.Mode().Perm())
		}
		data, _ := os.ReadFile(p)
		tok := strings.TrimSpace(string(data))
		if !ValidToken([]byte(tok)) || len(tok) != 66 {
			t.Errorf("%s holds %q, want 0x + 64 hex", p, tok)
		}
		toks = append(toks, tok)
	}
	if toks[0] == toks[1] {
		t.Fatal("sign and admin tokens are equal")
	}
	if e := a.Check(request(toks[0]), ScopeSign); e != nil {
		t.Errorf("generated sign token refused: %v", e)
	}
	if e := a.Check(request(toks[1]), ScopeAdmin); e != nil {
		t.Errorf("generated admin token refused: %v", e)
	}

	// A second start reads the same files.
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if e := b.Check(request(toks[0]), ScopeSign); e != nil {
		t.Errorf("token changed across restarts: %v", e)
	}
}

func TestReload(t *testing.T) {
	dir := t.TempDir()
	signFile := writeToken(t, dir, "sign", signTok)
	a, err := New(Config{Mode: ModeToken, SignTokenFile: signFile})
	if err != nil {
		t.Fatal(err)
	}
	if a.HasAdmin() {
		t.Fatal("HasAdmin = true without an admin token file")
	}
	if e := a.Check(request(adminTok), ScopeAdmin); reasonOf(e) != apierr.Unauthenticated {
		t.Fatalf("admin route without admin token: %v", e)
	}

	writeToken(t, dir, "sign", otherTok)
	if err := a.Reload(); err != nil {
		t.Fatal(err)
	}
	if a.Allows(request(signTok), ScopeSign) || !a.Allows(request(otherTok), ScopeSign) {
		t.Fatal("Reload did not rotate the sign token")
	}

	// An invalid file on reload keeps the previous token.
	writeToken(t, dir, "sign", "0xshort")
	if err := a.Reload(); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Reload with a bad file = %v, want ErrInvalidToken", err)
	}
	if !a.Allows(request(otherTok), ScopeSign) {
		t.Fatal("a failed reload dropped the previous token")
	}

	// A reload that would make the admin token equal the sign token is
	// refused; the previous tokens stay in force.
	writeToken(t, dir, "sign", otherTok)
	adminFile := writeToken(t, dir, "admin", adminTok)
	b, err := New(Config{Mode: ModeToken, SignTokenFile: signFile, AdminTokenFile: adminFile})
	if err != nil {
		t.Fatal(err)
	}
	writeToken(t, dir, "admin", otherTok)
	if err := b.Reload(); !errors.Is(err, ErrSameTokens) {
		t.Fatalf("Reload with equal tokens = %v, want ErrSameTokens", err)
	}
	if !b.Allows(request(adminTok), ScopeAdmin) || b.Allows(request(otherTok), ScopeAdmin) {
		t.Fatal("a refused reload changed the admin token")
	}

	// Deleting the file and reloading generates a new one.
	if err := os.Remove(signFile); err != nil {
		t.Fatal(err)
	}
	if err := a.Reload(); err != nil {
		t.Fatal(err)
	}
	if a.Allows(request(otherTok), ScopeSign) {
		t.Fatal("old token still accepted after the file was regenerated")
	}
}

func TestNewErrors(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name string
		cfg  Config
		want error
	}{
		{"token mode without a file", Config{Mode: ModeToken}, ErrNoSignToken},
		{"invalid token", Config{Mode: ModeToken, SignTokenFile: writeToken(t, dir, "bad", "secret")}, ErrInvalidToken},
		{"invalid admin token", Config{Mode: ModeNone, AdminTokenFile: writeToken(t, dir, "bad2", "0x12")}, ErrInvalidToken},
		{"one file for both scopes", Config{Mode: ModeToken, SignTokenFile: writeToken(t, dir, "both", signTok), AdminTokenFile: filepath.Join(dir, "both")}, ErrSameTokens},
		{"same token in two files", Config{Mode: ModeToken, SignTokenFile: writeToken(t, dir, "s", signTok), AdminTokenFile: writeToken(t, dir, "a", signTok+"\n")}, ErrSameTokens},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.cfg); !errors.Is(err, tt.want) {
				t.Fatalf("New = %v, want %v", err, tt.want)
			}
		})
	}
	if _, err := New(Config{Mode: "mTLS"}); err == nil {
		t.Fatal("New accepted an unknown mode")
	}
	if _, err := New(Config{Mode: ModeMTLS}); !errors.Is(err, ErrNoVerifyClient) {
		t.Fatalf("mtls without a client check: %v", err)
	}
	if _, err := New(Config{Mode: ModeTokenMTLS, VerifyClient: acceptGood}); !errors.Is(err, ErrNoSignToken) {
		t.Fatalf("token+mtls without a sign token file: %v", err)
	}
}

// acceptGood is a client check that accepts the certificate named "good".
func acceptGood(cs *tls.ConnectionState) error {
	if len(cs.PeerCertificates) > 0 && cs.PeerCertificates[0].Subject.CommonName == "good" {
		return nil
	}
	return errors.New("unknown client")
}

// withCert adds a TLS state carrying a client certificate named cn ("" for
// a TLS connection without one; "-" for plaintext).
func withCert(r *http.Request, cn string) *http.Request {
	switch cn {
	case "-":
	case "":
		r.TLS = &tls.ConnectionState{}
	default:
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: cn}}}}
	}
	return r
}

// The scope matrix of the mTLS modes (G4 S2; DESIGN §3.10): in mtls a
// certificate is the sign credential and admin routes need the admin
// token, a certificate alone getting 403; in token+mtls each scope needs
// the certificate and its token.
func TestMTLSScopeMatrix(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		SignTokenFile:  writeToken(t, dir, "sign", signTok),
		AdminTokenFile: writeToken(t, dir, "admin", adminTok),
		VerifyClient:   acceptGood,
	}
	tests := []struct {
		mode  Mode
		scope Scope
		cert  string // "good", "bad", "" (TLS, no certificate) or "-" (plaintext)
		tok   string
		want  apierr.Reason
	}{
		{ModeMTLS, ScopeSign, "good", "", ""},
		{ModeMTLS, ScopeSign, "good", otherTok, ""},
		{ModeMTLS, ScopeSign, "good", adminTok, ""},
		{ModeMTLS, ScopeSign, "bad", "", apierr.Unauthenticated},
		{ModeMTLS, ScopeSign, "", "", apierr.Unauthenticated},
		{ModeMTLS, ScopeSign, "-", "", apierr.Unauthenticated},
		{ModeMTLS, ScopeSign, "-", signTok, apierr.Unauthenticated},
		{ModeMTLS, ScopeAdmin, "good", "", apierr.ForbiddenScope},
		{ModeMTLS, ScopeAdmin, "good", otherTok, apierr.Unauthenticated},
		{ModeMTLS, ScopeAdmin, "good", signTok, apierr.Unauthenticated}, // no sign token exists in mode mtls
		{ModeMTLS, ScopeAdmin, "good", adminTok, ""},
		{ModeMTLS, ScopeAdmin, "bad", adminTok, apierr.Unauthenticated},
		{ModeMTLS, ScopeAdmin, "-", adminTok, apierr.Unauthenticated},
		{ModeTokenMTLS, ScopeSign, "good", signTok, ""},
		{ModeTokenMTLS, ScopeSign, "good", "", apierr.Unauthenticated},
		{ModeTokenMTLS, ScopeSign, "good", adminTok, apierr.Unauthenticated},
		{ModeTokenMTLS, ScopeSign, "bad", signTok, apierr.Unauthenticated},
		{ModeTokenMTLS, ScopeSign, "", signTok, apierr.Unauthenticated},
		{ModeTokenMTLS, ScopeSign, "-", signTok, apierr.Unauthenticated},
		{ModeTokenMTLS, ScopeAdmin, "good", adminTok, ""},
		{ModeTokenMTLS, ScopeAdmin, "good", "", apierr.Unauthenticated},
		{ModeTokenMTLS, ScopeAdmin, "good", signTok, apierr.ForbiddenScope},
		{ModeTokenMTLS, ScopeAdmin, "bad", adminTok, apierr.Unauthenticated},
		{ModeTokenMTLS, ScopeAdmin, "-", adminTok, apierr.Unauthenticated},
		{ModeTokenMTLS, ScopeNone, "-", "", ""},
	}
	for _, tt := range tests {
		name := string(tt.mode) + "/" + tt.scope.String() + "/" + tt.cert + "/" + strings.TrimPrefix(tt.tok, "0x")[:min(4, len(tt.tok))]
		t.Run(name, func(t *testing.T) {
			c := cfg
			c.Mode = tt.mode
			a, err := New(c)
			if err != nil {
				t.Fatal(err)
			}
			if got := reasonOf(a.Check(withCert(request(tt.tok), tt.cert), tt.scope)); got != tt.want {
				t.Fatalf("Check = %q, want %q", got, tt.want)
			}
		})
	}
}

// The metrics scope is open without a metrics token, needs it otherwise,
// and is granted by no other credential.
func TestMetricsScope(t *testing.T) {
	dir := t.TempDir()
	open, err := New(Config{Mode: ModeToken, SignTokenFile: writeToken(t, dir, "sign", signTok)})
	if err != nil {
		t.Fatal(err)
	}
	if e := open.Check(request(""), ScopeMetrics); e != nil {
		t.Fatalf("no metrics token: %v", e)
	}
	metricsTok := "0x" + strings.Repeat("44", 32)
	a, err := New(Config{
		Mode: ModeToken, SignTokenFile: filepath.Join(dir, "sign"),
		AdminTokenFile: writeToken(t, dir, "admin", adminTok), MetricsTokenFile: writeToken(t, dir, "metrics", metricsTok),
	})
	if err != nil {
		t.Fatal(err)
	}
	for tok, want := range map[string]apierr.Reason{"": apierr.Unauthenticated, signTok: apierr.Unauthenticated,
		adminTok: apierr.Unauthenticated, metricsTok: ""} {
		if got := reasonOf(a.Check(request(tok), ScopeMetrics)); got != want {
			t.Errorf("token %.6s: %q, want %q", tok, got, want)
		}
	}
	if a.Allows(request(metricsTok), ScopeSign) || a.Allows(request(metricsTok), ScopeAdmin) {
		t.Fatal("the metrics token grants an API scope")
	}
	// A generated metrics token file is 0600.
	gen := filepath.Join(dir, "gen", "metrics-token")
	if _, err := New(Config{Mode: ModeNone, MetricsTokenFile: gen}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(gen); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("generated metrics token: %v %v", fi, err)
	}
	// The metrics token must differ from the API tokens, at start and on reload.
	for _, other := range []string{filepath.Join(dir, "sign"), filepath.Join(dir, "admin")} {
		_, err := New(Config{Mode: ModeToken, SignTokenFile: filepath.Join(dir, "sign"), AdminTokenFile: filepath.Join(dir, "admin"), MetricsTokenFile: other})
		if !errors.Is(err, ErrSameMetricsToken) {
			t.Errorf("metrics token file %s: %v", other, err)
		}
	}
	writeToken(t, dir, "metrics", adminTok)
	if err := a.Reload(); !errors.Is(err, ErrSameMetricsToken) {
		t.Fatalf("reload to the admin token: %v", err)
	}
	if !a.Allows(request(metricsTok), ScopeMetrics) {
		t.Fatal("a refused reload changed the metrics token")
	}
}

func TestValidToken(t *testing.T) {
	tests := []struct {
		tok  string
		want bool
	}{
		{signTok, true},
		{signTok + "ab", true},
		{strings.ToUpper(signTok[2:]), false},
		{"0x" + strings.Repeat("A", 64), true},
		{"0x" + strings.Repeat("a", 63), false},
		{"0x" + strings.Repeat("g", 64), false},
		{"", false},
	}
	for _, tt := range tests {
		if got := ValidToken([]byte(tt.tok)); got != tt.want {
			t.Errorf("ValidToken(%q) = %v, want %v", tt.tok, got, tt.want)
		}
	}
}
