// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package tlsconf

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// pair is a test certificate and its key.
type pair struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// issue makes a certificate for cn signed by parent, or self-signed when
// parent is nil. A CA gets the cert-sign usage; a leaf gets usage.
func issue(t *testing.T, parent *pair, cn string, ca bool, usage x509.ExtKeyUsage, dns ...string) pair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		DNSNames:              dns,
	}
	if ca {
		tmpl.IsCA = true
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{usage}
	}
	signerCert, signerKey := tmpl, crypto.Signer(key)
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return pair{cert: c, key: key}
}

func serverPair(t *testing.T) pair {
	return issue(t, nil, "server", false, x509.ExtKeyUsageServerAuth, "localhost")
}

func clientPair(t *testing.T, parent *pair, cn string) pair {
	return issue(t, parent, cn, false, x509.ExtKeyUsageClientAuth)
}

// tlsCert is p as a tls.Certificate, followed by chain.
func (p pair) tlsCert(chain ...pair) tls.Certificate {
	c := tls.Certificate{Certificate: [][]byte{p.cert.Raw}, PrivateKey: p.key, Leaf: p.cert}
	for _, x := range chain {
		c.Certificate = append(c.Certificate, x.cert.Raw)
	}
	return c
}

func (p pair) fingerprint() Fingerprint { return FingerprintOf(p.cert.Raw) }

func writeFile(t *testing.T, path string, data []byte) string {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func certPEM(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

// writePEM writes p's certificate and key and returns their paths.
func writePEM(t *testing.T, dir, name string, p pair) (certFile, keyFile string) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(p.key)
	if err != nil {
		t.Fatal(err)
	}
	certFile = writeFile(t, filepath.Join(dir, name+".crt"), certPEM(p.cert))
	keyFile = writeFile(t, filepath.Join(dir, name+".key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	return certFile, keyFile
}

// serve accepts TLS connections with cfg until the test ends. Each
// connection completes its handshake, gets one byte and is then read until
// the client closes it, so that the client receives its session ticket.
func serve(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	l, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				if err := c.(*tls.Conn).Handshake(); err != nil {
					return
				}
				if _, err := c.Write([]byte{1}); err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return l.Addr().String()
}

// connect handshakes with the server at addr and reads its byte, which in
// TLS 1.3 is where a refused client certificate surfaces.
func connect(addr string, cfg *tls.Config) (tls.ConnectionState, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	c, err := tls.DialWithDialer(d, "tcp", addr, cfg)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	var b [1]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		return c.ConnectionState(), err
	}
	return c.ConnectionState(), nil
}

// clientConfig trusts the server certificate srv and presents client, if
// any.
func clientConfig(srv pair, client *tls.Certificate) *tls.Config {
	roots := x509.NewCertPool()
	roots.AddCert(srv.cert)
	cfg := &tls.Config{RootCAs: roots, ServerName: "localhost"}
	if client != nil {
		cfg.Certificates = []tls.Certificate{*client}
	}
	return cfg
}

// isRefused reports whether err is a handshake refusal, not a test-setup
// failure such as a refused TCP connection.
func isRefused(err error) bool {
	var op *net.OpError
	return err != nil && (!errors.As(err, &op) || op.Op != "dial")
}
