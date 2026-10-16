// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package tlsconf builds the API listener's TLS configuration
// (docs/operations/tls.md):
//
//   - TLS 1.3 only, with Go's default key exchanges, so the hybrid
//     post-quantum X25519MLKEM768 stays first;
//   - the certificate from PEM files, a PKCS#12 keystore, or a self-signed
//     ECDSA P-256 certificate generated on first start
//     (--tls-generate-self-signed), which a configured certificate
//     overrides;
//   - in the mTLS auth modes, a required client certificate, accepted when
//     its SHA-256 fingerprint is in the known-clients file or it chains to
//     a CA of --tls-client-ca-file. That pool is the only one: the system
//     roots never vouch for a client.
//
// The client check runs in tls.Config.VerifyConnection, which Go calls on
// every handshake, resumed ones included, never in VerifyPeerCertificate,
// which resumed sessions skip. Session tickets therefore stay on: a ticket
// carries the client's certificate, and resuming it re-runs the check
// against the trust in force at that moment, so a client removed by a
// reload can neither handshake nor resume. VerifyClient applies the same
// check to every request, which closes connections a removed client had
// already open.
//
// Reload (SIGHUP) re-reads every file and swaps the new configuration in
// at once. A certificate that fails to load leaves the previous one in
// force. The client trust fails closed instead: when the known-clients
// file or the CA file fails to load, every client is refused until a
// reload succeeds, so that a reload meant to revoke a client never leaves
// it trusted. On a reload, a file that lists no client (or no CA) is valid
// and accepts nobody, which is how the last client is revoked.
package tlsconf

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// Options are the settings that do not come from the TLS flags.
type Options struct {
	// SelfSignedDir holds the files of --tls-generate-self-signed
	// (<data-path>/tls).
	SelfSignedDir string
	// SelfSignedHosts are the names a generated certificate is valid for:
	// the --http-host-allowlist.
	SelfSignedHosts []string
	// RequireClientCert requires and verifies a client certificate (auth
	// modes mtls and token+mtls).
	RequireClientCert bool
	// Now is the clock for certificate validity; nil means time.Now.
	Now func() time.Time
}

// Sources of the server certificate, as Info.Source reports them.
const (
	SourcePEM        = "pem"
	SourcePKCS12     = "pkcs12"
	SourceSelfSigned = "self-signed"
)

// Client authentication, as Info.ClientAuth reports it.
const (
	ClientAuthNone           = "none"
	ClientAuthKnownClients   = "known-clients"
	ClientAuthCA             = "ca"
	ClientAuthKnownClientsCA = "known-clients+ca"
	// ClientAuthRefused: the client trust failed to reload, and every
	// client certificate is refused until a reload succeeds.
	ClientAuthRefused = "refused"
)

// Info describes the loaded configuration, for the startup and reload
// logs.
type Info struct {
	// Source is SourcePEM, SourcePKCS12 or SourceSelfSigned.
	Source string
	// Path is the certificate file, or the keystore.
	Path string
	// Generated is set when this load generated the self-signed
	// certificate.
	Generated bool
	// Fingerprint is the SHA-256 of the server certificate.
	Fingerprint Fingerprint
	NotAfter    time.Time
	// Uncovered lists the host allowlist names a self-signed certificate
	// generated earlier is not valid for.
	Uncovered []string
	// ClientAuth is one of the ClientAuth* values.
	ClientAuth string
	// KnownClients and ClientCAs count the loaded trust entries.
	KnownClients, ClientCAs int
}

// Errors of the client check.
var (
	ErrNoClientCert  = errors.New("tls: no client certificate")
	ErrUnknownClient = errors.New("tls: client certificate not accepted")
	errNoClientTrust = errors.New("tls: client certificates are not configured")
	errNoSelfSigned  = errors.New("tlsconf: --tls-generate-self-signed needs a directory (--data-path)")
	errNotEnabled    = errors.New("tlsconf: no certificate configured")
)

// ReloadError is the error of a Reload that could not load every file.
// The configuration in force afterwards keeps the previous certificate
// when Certificate is set, and refuses every client when ClientTrust is.
type ReloadError struct {
	// Certificate is why the certificate did not load.
	Certificate error
	// ClientTrust is why the known-clients file or the CA file did not
	// load.
	ClientTrust error
}

func (e *ReloadError) Error() string {
	var parts []string
	if e.Certificate != nil {
		parts = append(parts, "the certificate did not load, so the previous one stays in force: "+e.Certificate.Error())
	}
	if e.ClientTrust != nil {
		parts = append(parts, "the client trust did not load, so every client is refused: "+e.ClientTrust.Error())
	}
	return "tlsconf: reload: " + strings.Join(parts, "; ")
}

// Unwrap returns the errors that failed the reload.
func (e *ReloadError) Unwrap() []error {
	var errs []error
	for _, err := range []error{e.Certificate, e.ClientTrust} {
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// Server holds the API listener's TLS configuration. It is safe for
// concurrent use.
type Server struct {
	cfg  Config
	opts Options
	base *tls.Config
	cur  atomic.Pointer[generation]
}

// generation is one load of every file; it never changes once built.
type generation struct {
	cert   tls.Certificate
	config *tls.Config
	trust  *trust // nil when no client certificate is required
	info   Info
}

// New loads the certificate and the client trust, generating the
// self-signed certificate when that is configured and none exists yet. A
// known-clients file that lists no client, or a CA file without a
// certificate, is refused here as a mistake.
func New(cfg Config, opts Options) (*Server, error) {
	if err := cfg.Validate(opts.RequireClientCert); err != nil {
		return nil, err
	}
	switch {
	case !cfg.Enabled():
		return nil, errNotEnabled
	case !cfg.HasCertificate() && opts.SelfSignedDir == "":
		return nil, errNoSelfSigned
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	s := &Server{cfg: cfg, opts: opts}
	cert, info, err := s.loadCertificate()
	if err != nil {
		return nil, err
	}
	t, err := s.loadTrust(&info, true)
	if err != nil {
		return nil, err
	}
	s.cur.Store(s.build(cert, info, t))
	s.base = &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return s.cur.Load().config, nil
		},
	}
	return s, nil
}

// TLSConfig returns the configuration for http.Server.TLSConfig. Each
// handshake takes the generation in force when it starts. The
// configurations it hands out offer h2 and http/1.1, as net/http's
// ServeTLS serves both.
func (s *Server) TLSConfig() *tls.Config { return s.base }

// Info describes the configuration in force.
func (s *Server) Info() Info { return s.cur.Load().info }

// Reload re-reads the certificate, the known-clients file and the CA file,
// and swaps them in together. It returns the configuration now in force
// and, when a file did not load, a *ReloadError:
//
//   - a certificate that fails to load leaves the previous one in force,
//     so a broken rotation does not take the listener down;
//   - a client trust file that fails to load (missing, unreadable, a line
//     that does not parse) fails closed: every client is refused, on new
//     handshakes and through VerifyClient on open connections, until a
//     reload succeeds. Keeping the previous trust would keep a client the
//     operator meant to revoke.
//
// A known-clients file that lists no client, or a CA file without a
// certificate, is valid here and accepts nobody.
func (s *Server) Reload() (Info, error) {
	prev := s.cur.Load()
	var re ReloadError
	cert, info, err := s.loadCertificate()
	if err != nil {
		re.Certificate = err
		cert, info = prev.cert, prev.info
		info.Generated = false
	}
	t, err := s.loadTrust(&info, false)
	if err != nil {
		re.ClientTrust = err
		t = &trust{refused: err}
		info.ClientAuth, info.KnownClients, info.ClientCAs = ClientAuthRefused, 0, 0
	}
	g := s.build(cert, info, t)
	s.cur.Store(g)
	if re.Certificate != nil || re.ClientTrust != nil {
		return g.info, &re
	}
	return g.info, nil
}

// VerifyClient checks a request's TLS state against the client trust in
// force, as the handshake did: the auth layer calls it on every request,
// so that a client removed by a reload loses its open connections' scope
// too.
func (s *Server) VerifyClient(cs *tls.ConnectionState) error {
	t := s.cur.Load().trust
	switch {
	case t == nil:
		return errNoClientTrust
	case cs == nil:
		return ErrNoClientCert
	}
	return t.verify(cs.PeerCertificates)
}

// loadCertificate loads the server certificate, generating the
// self-signed one when that is configured and none exists, and fills the
// certificate fields of the Info.
func (s *Server) loadCertificate() (tls.Certificate, Info, error) {
	var (
		cert tls.Certificate
		info Info
		err  error
	)
	switch {
	case s.cfg.CertFile != "":
		info.Source, info.Path = SourcePEM, s.cfg.CertFile
		cert, err = loadPEM(s.cfg.CertFile, s.cfg.KeyFile)
	case s.cfg.KeystoreFile != "":
		info.Source, info.Path = SourcePKCS12, s.cfg.KeystoreFile
		cert, err = loadPKCS12(s.cfg.KeystoreFile, s.cfg.KeystorePasswordFile)
	default:
		info.Source, info.Path = SourceSelfSigned, filepath.Join(s.opts.SelfSignedDir, SelfSignedCertFile)
		cert, info.Generated, err = selfSigned(s.opts.SelfSignedDir, s.opts.SelfSignedHosts, s.opts.Now())
		if err == nil && !info.Generated {
			info.Uncovered = uncoveredHosts(cert.Leaf, s.opts.SelfSignedHosts)
		}
	}
	if err != nil {
		return cert, Info{}, err
	}
	info.Fingerprint = FingerprintOf(cert.Leaf.Raw)
	info.NotAfter = cert.Leaf.NotAfter
	return cert, info, nil
}

// loadTrust loads the client trust, nil when no client certificate is
// required, and fills the client fields of info. At startup a trust file
// that lists nobody is refused as a mistake; on a reload it is valid and
// accepts nobody.
func (s *Server) loadTrust(info *Info, startup bool) (*trust, error) {
	info.ClientAuth, info.KnownClients, info.ClientCAs = ClientAuthNone, 0, 0
	if !s.opts.RequireClientCert {
		return nil, nil
	}
	t := &trust{now: s.opts.Now}
	if path := s.cfg.KnownClientsFile; path != "" {
		known, err := loadKnownClients(path)
		if err != nil {
			return nil, err
		}
		if startup && len(known) == 0 {
			return nil, fmt.Errorf("--tls-known-clients-file %s lists no client", path)
		}
		t.known, info.KnownClients = known, len(known)
	}
	if path := s.cfg.ClientCAFile; path != "" {
		pool, n, err := loadClientCAs(path)
		if err != nil {
			return nil, err
		}
		if startup && n == 0 {
			return nil, fmt.Errorf("--tls-client-ca-file %s: no PEM certificate", path)
		}
		t.pool, info.ClientCAs = pool, n
	}
	switch {
	case t.known == nil:
		info.ClientAuth = ClientAuthCA
	case t.pool == nil:
		info.ClientAuth = ClientAuthKnownClients
	default:
		info.ClientAuth = ClientAuthKnownClientsCA
	}
	return t, nil
}

// build assembles a generation from a certificate and a client trust.
func (s *Server) build(cert tls.Certificate, info Info, t *trust) *generation {
	g := &generation{
		cert: cert,
		config: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
			ClientAuth:   tls.NoClientCert,
			Time:         s.opts.Now,
		},
		trust: t,
		info:  info,
	}
	if t == nil {
		return g
	}
	if t.refused == nil && t.known == nil && t.pool != nil {
		// CA mode: Go verifies the chain against the explicit pool, which
		// must never be nil (nil would mean the system roots).
		g.config.ClientAuth = tls.RequireAndVerifyClientCert
		g.config.ClientCAs = t.pool
	} else {
		// Fingerprints, both checks (either may accept the client, so the
		// chain is verified in VerifyConnection rather than by Go), or a
		// trust that refuses everyone.
		g.config.ClientAuth = tls.RequireAnyClientCert
	}
	g.config.VerifyConnection = func(cs tls.ConnectionState) error { return t.verify(cs.PeerCertificates) }
	return g
}

// trust is one generation's client trust.
type trust struct {
	known map[Fingerprint]struct{}
	pool  *x509.CertPool
	now   func() time.Time
	// refused is set when the trust failed to reload: every client is
	// refused.
	refused error
}

// verify accepts a client chain whose leaf is a known client, or that
// chains to a CA of the pool with the client-auth usage.
func (t *trust) verify(chain []*x509.Certificate) error {
	if t.refused != nil {
		return fmt.Errorf("%w: the client trust failed to reload, so every client is refused", ErrUnknownClient)
	}
	if len(chain) == 0 {
		return ErrNoClientCert
	}
	leaf := chain[0]
	fp := FingerprintOf(leaf.Raw)
	if _, ok := t.known[fp]; ok {
		return nil
	}
	if t.pool == nil {
		return fmt.Errorf("%w: SHA-256 %s is not in the known-clients file", ErrUnknownClient, fp)
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         t.pool,
		Intermediates: inter,
		CurrentTime:   t.now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return fmt.Errorf("%w: SHA-256 %s: %v", ErrUnknownClient, fp, err)
	}
	return nil
}
