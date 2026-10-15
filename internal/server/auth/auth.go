// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package auth authenticates API requests with scoped bearer tokens.
//
// There are two scopes, each with its own token file: `sign` (duty routes,
// publicKeys, capabilities, GET /reload, healthcheck detail) and `admin`
// (POST /reload and the other admin routes). Neither implies the other: a
// sign token on an admin route is refused with 403 FORBIDDEN_SCOPE, and an
// admin token on a sign route with 401 UNAUTHENTICATED.
//
// A token is "0x" followed by at least 64 hex characters. Token files are
// generated (mode 0600) when missing and re-read by Reload, which the
// process calls on SIGHUP. Presented tokens are compared in constant time,
// over SHA-256 digests so that the comparison does not depend on length.
//
// In auth mode none (loopback listeners only) the sign scope is open; the
// admin scope always needs the admin token.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
	"github.com/rgeraldes24/go-remotesigner/internal/logging"
)

// Scope is the credential a route requires.
type Scope uint8

// Scopes.
const (
	ScopeNone  Scope = iota // no credential
	ScopeSign               // the sign token (or nothing in mode none)
	ScopeAdmin              // the admin token, in every mode
)

// String names the scope.
func (s Scope) String() string {
	switch s {
	case ScopeNone:
		return "none"
	case ScopeSign:
		return "sign"
	case ScopeAdmin:
		return "admin"
	default:
		return fmt.Sprintf("Scope(%d)", uint8(s))
	}
}

// Mode is --http-auth-mode. Only the modes that need no TLS exist so far.
type Mode string

// Modes.
const (
	ModeToken Mode = "token"
	ModeNone  Mode = "none"
)

// MinTokenHexLength is the minimum number of hex characters after "0x".
const MinTokenHexLength = 64

// fileMode is the permission of a generated token file.
const fileMode fs.FileMode = 0o600

// Errors returned by this package.
var (
	ErrInvalidToken = errors.New("auth: token must be 0x followed by at least 64 hex characters")
	ErrNoSignToken  = errors.New("auth: token mode needs a sign token file")
)

// Config configures an Authenticator.
type Config struct {
	Mode Mode
	// SignTokenFile is the sign token's file; required in ModeToken and
	// ignored in ModeNone.
	SignTokenFile string
	// AdminTokenFile is the admin token's file. When empty there is no admin
	// token and no admin route may be registered.
	AdminTokenFile string
}

// Authenticator checks requests against the current tokens. It is safe for
// concurrent use.
type Authenticator struct {
	cfg Config

	mu    sync.RWMutex
	sign  *[sha256.Size]byte // nil in ModeNone
	admin *[sha256.Size]byte // nil without an admin token
}

// New loads (or generates) the configured token files.
func New(cfg Config) (*Authenticator, error) {
	switch cfg.Mode {
	case ModeToken:
		if cfg.SignTokenFile == "" {
			return nil, ErrNoSignToken
		}
	case ModeNone:
		cfg.SignTokenFile = ""
	default:
		return nil, fmt.Errorf("auth: unknown mode %q", cfg.Mode)
	}
	a := &Authenticator{cfg: cfg}
	if err := a.Reload(); err != nil {
		return nil, err
	}
	return a, nil
}

// HasAdmin reports whether an admin token is configured, i.e. whether admin
// routes may exist.
func (a *Authenticator) HasAdmin() bool { return a.cfg.AdminTokenFile != "" }

// Mode returns the auth mode.
func (a *Authenticator) Mode() Mode { return a.cfg.Mode }

// Reload re-reads the token files, generating any that is missing. On error
// the previous tokens stay in force.
func (a *Authenticator) Reload() error {
	var sign, admin *[sha256.Size]byte
	if a.cfg.SignTokenFile != "" {
		d, err := loadOrGenerate(a.cfg.SignTokenFile)
		if err != nil {
			return err
		}
		sign = &d
	}
	if a.cfg.AdminTokenFile != "" {
		d, err := loadOrGenerate(a.cfg.AdminTokenFile)
		if err != nil {
			return err
		}
		admin = &d
	}
	a.mu.Lock()
	a.sign, a.admin = sign, admin
	a.mu.Unlock()
	return nil
}

// Check returns nil when r carries the credential scope requires, and the
// refusal otherwise: 401 UNAUTHENTICATED for a missing or unknown token
// (including the admin token on a sign route), 403 FORBIDDEN_SCOPE for the
// sign token on an admin route.
func (a *Authenticator) Check(r *http.Request, scope Scope) *apierr.Error {
	if scope == ScopeNone {
		return nil
	}
	a.mu.RLock()
	sign, admin := a.sign, a.admin
	a.mu.RUnlock()

	if scope == ScopeSign && a.cfg.Mode == ModeNone {
		return nil
	}
	tok, ok := bearer(r)
	if !ok {
		return apierr.New(apierr.Unauthenticated, "no bearer token")
	}
	d := sha256.Sum256(tok)
	isSign, isAdmin := matches(sign, &d), matches(admin, &d)
	switch {
	case scope == ScopeSign && isSign, scope == ScopeAdmin && isAdmin:
		return nil
	case scope == ScopeAdmin && isSign:
		return apierr.New(apierr.ForbiddenScope, "sign token on an admin route")
	default:
		return apierr.New(apierr.Unauthenticated, "unknown token for the route's scope")
	}
}

// Allows reports whether r carries the credential scope requires.
func (a *Authenticator) Allows(r *http.Request, scope Scope) bool {
	return a.Check(r, scope) == nil
}

// matches compares in constant time; a nil want never matches.
func matches(want, got *[sha256.Size]byte) bool {
	if want == nil {
		return false
	}
	return subtle.ConstantTimeCompare(want[:], got[:]) == 1
}

// bearer returns the token of an "Authorization: Bearer <token>" header. The
// scheme is case-insensitive.
func bearer(r *http.Request) (logging.Secret, bool) {
	h := r.Header.Get("Authorization")
	scheme, tok, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return nil, false
	}
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return nil, false
	}
	return logging.Secret(tok), true
}

// ValidToken reports whether tok has the token format.
func ValidToken(tok []byte) bool {
	h, ok := strings.CutPrefix(string(tok), "0x")
	if !ok || len(h) < MinTokenHexLength {
		return false
	}
	for i := 0; i < len(h); i++ {
		if !isHex(h[i]) {
			return false
		}
	}
	return true
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// loadOrGenerate returns the SHA-256 of the token in path, generating a new
// token file when none exists.
func loadOrGenerate(path string) ([sha256.Size]byte, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		data, err = generate(path)
	}
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("auth: token file %s: %w", path, err)
	}
	tok := logging.Secret(strings.TrimSpace(string(data)))
	if !ValidToken(tok) {
		return [sha256.Size]byte{}, fmt.Errorf("auth: token file %s: %w", path, ErrInvalidToken)
	}
	return sha256.Sum256(tok), nil
}

// generate writes a new random token to path (mode 0600, never replacing an
// existing file) and returns the file content.
func generate(path string) ([]byte, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, err
	}
	data := []byte("0x" + hex.EncodeToString(raw[:]) + "\n")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if errors.Is(err, fs.ErrExist) {
		// Another process created it first; use that one.
		return os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return data, nil
}
