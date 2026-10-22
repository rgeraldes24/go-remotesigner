// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package auth authenticates API requests with scoped bearer tokens and,
// in the mTLS modes, client certificates.
//
// There are two API scopes, each with its own token file: `sign` (duty
// routes, publicKeys, capabilities, GET /reload, healthcheck detail) and
// `admin` (POST /reload and the other admin routes). Neither implies the
// other: a sign token on an admin route is refused with 403
// FORBIDDEN_SCOPE, and an admin token on a sign route with 401
// UNAUTHENTICATED. A third, optional token guards the metrics listener.
//
// A token is "0x" followed by at least 64 hex characters. Token files are
// generated (mode 0600) when missing and re-read by Reload, which the
// process calls on SIGHUP. They are secret files: one that its group or
// other users can read is refused or warned about by Config.Files, the
// --strict-file-permissions policy. Presented tokens are compared in constant time,
// over SHA-256 digests so that the comparison does not depend on length.
//
// The auth mode decides what grants the sign scope (docs/contract.md
// section 6): the sign token (token); a client certificate (mtls); both
// (token+mtls); nothing (none, loopback listeners only). A client
// certificate never grants the admin scope: admin routes need the admin
// token in every mode, and in token+mtls the certificate as well. The TLS
// layer verifies the certificate during the handshake; Check verifies it
// again on every API request, the credential-less routes (/upcheck,
// /healthcheck) included, against the trust in force, through
// Config.VerifyClient.
package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
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
	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secretfile"
	"github.com/rgeraldes24/go-remotesigner/internal/logging"
)

// Scope is the credential a route requires.
type Scope uint8

// Scopes.
const (
	ScopeNone    Scope = iota // no credential
	ScopeSign                 // the mode's sign credential (nothing in mode none)
	ScopeAdmin                // the admin token in every mode (and the client certificate in token+mtls)
	ScopeMetrics              // the metrics token, when one is configured
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
	case ScopeMetrics:
		return "metrics"
	default:
		return fmt.Sprintf("Scope(%d)", uint8(s))
	}
}

// Mode is --http-auth-mode.
type Mode string

// Modes.
const (
	ModeToken     Mode = "token"
	ModeMTLS      Mode = "mtls"
	ModeTokenMTLS Mode = "token+mtls"
	ModeNone      Mode = "none"
)

// ParseMode parses --http-auth-mode.
func ParseMode(s string) (Mode, error) {
	switch m := Mode(s); m {
	case ModeToken, ModeMTLS, ModeTokenMTLS, ModeNone:
		return m, nil
	}
	return "", fmt.Errorf("%q: want token, mtls, token+mtls or none", s)
}

// ClientCerts reports whether the mode authenticates with client
// certificates.
func (m Mode) ClientCerts() bool { return m == ModeMTLS || m == ModeTokenMTLS }

// SignToken reports whether the mode has a sign token.
func (m Mode) SignToken() bool { return m == ModeToken || m == ModeTokenMTLS }

// MinTokenHexLength is the minimum number of hex characters after "0x".
const MinTokenHexLength = 64

// fileMode is the permission of a generated token file.
const fileMode fs.FileMode = 0o600

// maxTokenFile bounds a token file.
const maxTokenFile = 4 << 10

// Errors returned by this package.
var (
	ErrInvalidToken     = errors.New("auth: token must be 0x followed by at least 64 hex characters")
	ErrNoSignToken      = errors.New("auth: token mode needs a sign token file")
	ErrNoVerifyClient   = errors.New("auth: the mtls modes need a client certificate check")
	ErrSameTokens       = errors.New("auth: the sign and admin tokens must differ, or the sign token would grant the admin scope")
	ErrSameMetricsToken = errors.New("auth: the metrics token must differ from the sign and admin tokens, or a scraper would hold an API credential")
)

// Config configures an Authenticator.
type Config struct {
	Mode Mode
	// SignTokenFile is the sign token's file; required in ModeToken and
	// ModeTokenMTLS, ignored otherwise.
	SignTokenFile string
	// AdminTokenFile is the admin token's file. When empty there is no admin
	// token and no admin route may be registered.
	AdminTokenFile string
	// MetricsTokenFile is the metrics token's file. When empty the metrics
	// scope is open.
	MetricsTokenFile string
	// VerifyClient checks a request's client certificate against the trust
	// in force; required in the mtls modes.
	VerifyClient func(*tls.ConnectionState) error
	// Files is the policy for token files that their group or other users
	// can read (--strict-file-permissions): refused under Strict, warned
	// about otherwise, at startup and on every Reload.
	Files secretfile.Policy
}

// Authenticator checks requests against the current tokens. It is safe for
// concurrent use.
type Authenticator struct {
	cfg Config

	mu      sync.RWMutex
	sign    *[sha256.Size]byte // nil in ModeNone and ModeMTLS
	admin   *[sha256.Size]byte // nil without an admin token
	metrics *[sha256.Size]byte // nil without a metrics token
}

// New loads (or generates) the configured token files.
func New(cfg Config) (*Authenticator, error) {
	if _, err := ParseMode(string(cfg.Mode)); err != nil {
		return nil, fmt.Errorf("auth: mode %w", err)
	}
	switch {
	case cfg.Mode.SignToken() && cfg.SignTokenFile == "":
		return nil, ErrNoSignToken
	case !cfg.Mode.SignToken():
		cfg.SignTokenFile = ""
	}
	if cfg.Mode.ClientCerts() && cfg.VerifyClient == nil {
		return nil, ErrNoVerifyClient
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

// Reload re-reads the token files, generating any that is missing. The
// tokens must all differ (ErrSameTokens, ErrSameMetricsToken). On error the
// previous tokens stay in force.
func (a *Authenticator) Reload() error {
	var digests [3]*[sha256.Size]byte
	for i, path := range []string{a.cfg.SignTokenFile, a.cfg.AdminTokenFile, a.cfg.MetricsTokenFile} {
		if path == "" {
			continue
		}
		d, err := loadOrGenerate(path, a.cfg.Files)
		if err != nil {
			return err
		}
		digests[i] = &d
	}
	sign, admin, metrics := digests[0], digests[1], digests[2]
	if same(sign, admin) {
		return ErrSameTokens
	}
	if same(metrics, sign) || same(metrics, admin) {
		return ErrSameMetricsToken
	}
	a.mu.Lock()
	a.sign, a.admin, a.metrics = sign, admin, metrics
	a.mu.Unlock()
	return nil
}

// same reports whether two configured tokens are equal.
func same(a, b *[sha256.Size]byte) bool { return a != nil && b != nil && *a == *b }

// Check returns nil when r carries the credential scope requires, and the
// refusal otherwise: 401 UNAUTHENTICATED for a missing or unknown token or
// client certificate (including the admin token on a sign route), 403
// FORBIDDEN_SCOPE for a sign credential on an admin route (the sign token,
// or in mode mtls a client certificate without the admin token). In the
// mtls modes every API scope, ScopeNone included, needs an accepted client
// certificate, so that a client removed by a reload gets 401 on every route
// of a connection it already has open; the metrics listener has no TLS, and
// ScopeMetrics never takes a certificate.
func (a *Authenticator) Check(r *http.Request, scope Scope) *apierr.Error {
	a.mu.RLock()
	sign, admin, metrics := a.sign, a.admin, a.metrics
	a.mu.RUnlock()

	switch {
	case scope == ScopeMetrics:
		if metrics == nil {
			return nil
		}
		tok, ok := bearer(r)
		if !ok {
			return apierr.New(apierr.Unauthenticated, "no bearer token")
		}
		if d := sha256.Sum256(tok); matches(metrics, &d) {
			return nil
		}
		return apierr.New(apierr.Unauthenticated, "unknown token for the route's scope")
	case a.cfg.Mode.ClientCerts() && !a.clientCert(r):
		return apierr.New(apierr.Unauthenticated, "no accepted client certificate")
	case scope == ScopeNone:
		return nil
	case scope == ScopeSign && a.cfg.Mode == ModeNone:
		return nil
	case scope == ScopeSign && a.cfg.Mode == ModeMTLS:
		return nil // the certificate is the sign credential
	}

	tok, ok := bearer(r)
	if !ok {
		if scope == ScopeAdmin && a.cfg.Mode == ModeMTLS {
			return apierr.New(apierr.ForbiddenScope, "client certificate on an admin route")
		}
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

// clientCert reports whether r came over a TLS connection with a client
// certificate that the trust in force accepts.
func (a *Authenticator) clientCert(r *http.Request) bool {
	return r.TLS != nil && len(r.TLS.PeerCertificates) > 0 && a.cfg.VerifyClient(r.TLS) == nil
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

// loadOrGenerate returns the SHA-256 of the token in path, read under the
// file policy p, generating a new token file when none exists.
func loadOrGenerate(path string, p secretfile.Policy) ([sha256.Size]byte, error) {
	data, err := secretfile.Read(path, maxTokenFile, p)
	if errors.Is(err, fs.ErrNotExist) {
		data, err = generate(path, p)
	}
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("auth: token file %s: %w", path, err)
	}
	defer mldsa87.Wipe(data)
	tok := logging.Secret(bytes.TrimSpace(data))
	if !ValidToken(tok) {
		return [sha256.Size]byte{}, fmt.Errorf("auth: token file %s: %w", path, ErrInvalidToken)
	}
	return sha256.Sum256(tok), nil
}

// generate writes a new random token to path (mode 0600, never replacing an
// existing file) and returns the file content. When another process created
// the file first, it reads that one under the file policy p.
func generate(path string, p secretfile.Policy) ([]byte, error) {
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
		return secretfile.Read(path, maxTokenFile, p)
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
