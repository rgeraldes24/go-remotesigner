// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
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

// The scope matrix of the token modes (G4 S1, S2).
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
	if _, err := New(Config{Mode: "mtls"}); err == nil {
		t.Fatal("New accepted an unknown mode")
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
