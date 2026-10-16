// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package tlsconf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The files of --tls-generate-self-signed, under Options.SelfSignedDir.
const (
	SelfSignedCertFile = "cert.pem"
	SelfSignedKeyFile  = "key.pem"
)

// SelfSignedValidity is how long a generated certificate is valid. Clients
// pin it, so it is long-lived; rotating it means deleting the files and
// pinning the new certificate.
const SelfSignedValidity = 10 * 365 * 24 * time.Hour

// selfSignedCommonName is the subject of a generated certificate. Clients
// match host names against its subject alternative names only.
const selfSignedCommonName = "remotesigner self-signed"

// ErrNoHostNames: the host allowlist names no host to put in a generated
// certificate (it is a wildcard).
var ErrNoHostNames = errors.New("--tls-generate-self-signed needs the host names clients connect with in --http-host-allowlist; a wildcard names none")

// selfSigned returns the certificate in dir that an earlier start
// generated, or generates and writes one valid for hosts: an ECDSA P-256
// key and a self-signed certificate, both files 0600 in a 0700 directory.
// The certificate file is written last, so a certificate file always has
// its key; one without it is refused rather than replaced, because clients
// may pin it.
func selfSigned(dir string, hosts []string, now time.Time) (cert tls.Certificate, generated bool, err error) {
	certPath, keyPath := filepath.Join(dir, SelfSignedCertFile), filepath.Join(dir, SelfSignedKeyFile)
	switch _, err := os.Stat(certPath); {
	case err == nil:
		if _, err := os.Stat(keyPath); errors.Is(err, fs.ErrNotExist) {
			return cert, false, fmt.Errorf("%s exists without %s: restore the key, or delete both to generate a new "+
				"certificate (and pin the new one in every client)", certPath, keyPath)
		}
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return cert, false, fmt.Errorf("the self-signed certificate in %s: %w", dir, err)
		}
		cert, err = withLeaf(cert)
		return cert, false, err
	case !errors.Is(err, fs.ErrNotExist):
		return cert, false, err
	}

	dns, ips := subjectAltNames(hosts)
	if len(dns)+len(ips) == 0 {
		return cert, false, ErrNoHostNames
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return cert, false, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return cert, false, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: selfSignedCommonName},
		NotBefore:             now.Add(-time.Hour), // tolerate client clocks a little behind
		NotAfter:              now.Add(SelfSignedValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dns,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return cert, false, fmt.Errorf("generate a self-signed certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return cert, false, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return cert, false, err
	}
	if err := writeFileAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
		return cert, false, err
	}
	if err := writeFileAtomic(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
		return cert, false, err
	}
	cert, err = withLeaf(tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key})
	return cert, true, err
}

// subjectAltNames splits the host allowlist into DNS names and IP
// addresses, leaving out the wildcard.
func subjectAltNames(hosts []string) (dns []string, ips []net.IP) {
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if len(h) >= 2 && h[0] == '[' && h[len(h)-1] == ']' {
			h = h[1 : len(h)-1]
		}
		switch {
		case h == "" || h == "*":
		case net.ParseIP(h) != nil:
			ips = append(ips, net.ParseIP(h))
		default:
			dns = append(dns, strings.ToLower(h))
		}
	}
	return dns, ips
}

// uncoveredHosts returns the allowlist names a certificate is not valid
// for.
func uncoveredHosts(leaf *x509.Certificate, hosts []string) []string {
	dns, ips := subjectAltNames(hosts)
	var out []string
	for _, ip := range ips {
		if leaf.VerifyHostname(ip.String()) != nil {
			out = append(out, ip.String())
		}
	}
	for _, d := range dns {
		if leaf.VerifyHostname(d) != nil {
			out = append(out, d)
		}
	}
	return out
}

// writeFileAtomic writes a 0600 file through a temporary file in the same
// directory, synced and renamed into place.
func writeFileAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // a no-op once renamed
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
