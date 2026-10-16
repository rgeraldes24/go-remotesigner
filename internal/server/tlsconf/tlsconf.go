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
// Reload (SIGHUP) re-reads every file and swaps the whole configuration
// at once; on any error the previous one stays in force.
package tlsconf

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"path/filepath"
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
	config *tls.Config
	trust  *trust // nil when no client certificate is required
	info   Info
}

// New loads the certificate and the client trust, generating the
// self-signed certificate when that is configured and none exists yet.
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
	g, err := s.load()
	if err != nil {
		return nil, err
	}
	s.cur.Store(g)
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
// and swaps them in together. On error the previous configuration stays in
// force.
func (s *Server) Reload() (Info, error) {
	g, err := s.load()
	if err != nil {
		return Info{}, err
	}
	s.cur.Store(g)
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

func (s *Server) load() (*generation, error) {
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
		return nil, err
	}
	info.Fingerprint = FingerprintOf(cert.Leaf.Raw)
	info.NotAfter = cert.Leaf.NotAfter

	g := &generation{
		config: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
			ClientAuth:   tls.NoClientCert,
			Time:         s.opts.Now,
		},
		info: info,
	}
	g.info.ClientAuth = ClientAuthNone
	if !s.opts.RequireClientCert {
		return g, nil
	}
	t := &trust{now: s.opts.Now}
	if s.cfg.KnownClientsFile != "" {
		if t.known, err = loadKnownClients(s.cfg.KnownClientsFile); err != nil {
			return nil, err
		}
		g.info.KnownClients = len(t.known)
	}
	if s.cfg.ClientCAFile != "" {
		if t.pool, g.info.ClientCAs, err = loadClientCAs(s.cfg.ClientCAFile); err != nil {
			return nil, err
		}
	}
	switch {
	case t.known == nil:
		// CA mode: Go verifies the chain against the explicit pool, which
		// must never be nil (nil would mean the system roots).
		g.info.ClientAuth = ClientAuthCA
		g.config.ClientAuth = tls.RequireAndVerifyClientCert
		g.config.ClientCAs = t.pool
	case t.pool == nil:
		g.info.ClientAuth = ClientAuthKnownClients
		g.config.ClientAuth = tls.RequireAnyClientCert
	default:
		// Either check may accept the client, so the chain is verified in
		// VerifyConnection rather than by Go.
		g.info.ClientAuth = ClientAuthKnownClientsCA
		g.config.ClientAuth = tls.RequireAnyClientCert
	}
	g.config.VerifyConnection = func(cs tls.ConnectionState) error { return t.verify(cs.PeerCertificates) }
	g.trust = t
	return g, nil
}

// trust is one generation's client trust.
type trust struct {
	known map[Fingerprint]struct{}
	pool  *x509.CertPool
	now   func() time.Time
}

// verify accepts a client chain whose leaf is a known client, or that
// chains to a CA of the pool with the client-auth usage.
func (t *trust) verify(chain []*x509.Certificate) error {
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
