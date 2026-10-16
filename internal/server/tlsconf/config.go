// Copyright 2020 ConsenSys AG.
// Copyright 2026 The go-remotesigner Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//
// Modified by The go-remotesigner Authors, 2026: translated from Java to Go and adapted for QRL.
// Derived from Web3Signer
// core/src/main/java/tech/pegasys/web3signer/core/Runner.java and
// commandline/src/main/java/tech/pegasys/web3signer/commandline/config/PicoCliTlsServerOptionsValidator.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package tlsconf

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"software.sslmate.com/src/go-pkcs12"
)

// Config holds the TLS flags of the API listener.
type Config struct {
	// CertFile and KeyFile are a PEM certificate chain and its private key
	// (--tls-cert-file, --tls-key-file).
	CertFile, KeyFile string
	// KeystoreFile is a PKCS#12 keystore holding the key and its chain, and
	// KeystorePasswordFile the file whose first line is its password
	// (--tls-keystore-file, --tls-keystore-password-file).
	KeystoreFile, KeystorePasswordFile string
	// KnownClientsFile lists the SHA-256 fingerprints of the accepted client
	// certificates (--tls-known-clients-file).
	KnownClientsFile string
	// ClientCAFile is a PEM bundle of the CAs that may issue client
	// certificates (--tls-client-ca-file). It is the only trust pool for
	// client certificates: the system roots are never used.
	ClientCAFile string
	// GenerateSelfSigned writes, on first start, a self-signed certificate
	// when no certificate is configured (--tls-generate-self-signed).
	GenerateSelfSigned bool
}

// HasCertificate reports whether a certificate is configured (PEM or
// PKCS#12). A configured certificate takes precedence over
// GenerateSelfSigned.
func (c *Config) HasCertificate() bool {
	return c.CertFile != "" || c.KeyFile != "" || c.KeystoreFile != "" || c.KeystorePasswordFile != ""
}

// Enabled reports whether the API listener serves TLS.
func (c *Config) Enabled() bool { return c.HasCertificate() || c.GenerateSelfSigned }

// HasClientTrust reports whether a client-certificate trust source is
// configured.
func (c *Config) HasClientTrust() bool { return c.KnownClientsFile != "" || c.ClientCAFile != "" }

// Errors returned by Validate. Each names the flags to fix.
var (
	ErrCertWithoutKey        = errors.New("--tls-cert-file must be specified together with --tls-key-file")
	ErrKeystoreNoPassword    = errors.New("--tls-keystore-file must be specified together with --tls-keystore-password-file")
	ErrTwoCertificates       = errors.New("give the certificate either as PEM (--tls-cert-file, --tls-key-file) or as PKCS#12 (--tls-keystore-file), not both")
	ErrClientTrustWithoutTLS = errors.New("--tls-known-clients-file and --tls-client-ca-file need TLS: --tls-cert-file and --tls-key-file, --tls-keystore-file, or --tls-generate-self-signed")
	ErrClientTrustNotMTLS    = errors.New("--tls-known-clients-file and --tls-client-ca-file are used only with --http-auth-mode=mtls or token+mtls")
	ErrMTLSWithoutTLS        = errors.New("--http-auth-mode=mtls and token+mtls need TLS: --tls-cert-file and --tls-key-file, --tls-keystore-file, or --tls-generate-self-signed")
	ErrMTLSWithoutTrust      = errors.New("--http-auth-mode=mtls and token+mtls need --tls-known-clients-file or --tls-client-ca-file to verify client certificates")
)

// Validate checks that the flags combine. requireClientCert is set in the
// auth modes that authenticate with client certificates (mtls,
// token+mtls); only they take a client trust source.
func (c *Config) Validate(requireClientCert bool) error {
	switch {
	case (c.CertFile == "") != (c.KeyFile == ""):
		return ErrCertWithoutKey
	case (c.KeystoreFile == "") != (c.KeystorePasswordFile == ""):
		return ErrKeystoreNoPassword
	case c.CertFile != "" && c.KeystoreFile != "":
		return ErrTwoCertificates
	case requireClientCert && !c.Enabled():
		return ErrMTLSWithoutTLS
	case requireClientCert && !c.HasClientTrust():
		return ErrMTLSWithoutTrust
	case c.HasClientTrust() && !c.Enabled():
		return ErrClientTrustWithoutTLS
	case c.HasClientTrust() && !requireClientCert:
		return ErrClientTrustNotMTLS
	}
	return nil
}

// loadPEM loads a PEM certificate chain and its key.
func loadPEM(certFile, keyFile string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("--tls-cert-file %s and --tls-key-file %s: %w", certFile, keyFile, err)
	}
	return withLeaf(cert)
}

// loadPKCS12 loads a PKCS#12 keystore. Like Web3Signer, only the first line
// of the password file is the password.
func loadPKCS12(file, passwordFile string) (tls.Certificate, error) {
	password, err := firstLine(passwordFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("--tls-keystore-password-file %s: %w", passwordFile, err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("--tls-keystore-file: %w", err)
	}
	key, leaf, chain, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("--tls-keystore-file %s: %w", file, err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return tls.Certificate{}, fmt.Errorf("--tls-keystore-file %s: unsupported private key type %T", file, key)
	}
	if !samePublicKey(signer.Public(), leaf.PublicKey) {
		return tls.Certificate{}, fmt.Errorf("--tls-keystore-file %s: the private key does not match the certificate", file)
	}
	cert := tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}
	for _, c := range chain {
		cert.Certificate = append(cert.Certificate, c.Raw)
	}
	return cert, nil
}

// samePublicKey compares two public keys of the standard library's types.
func samePublicKey(a, b crypto.PublicKey) bool {
	k, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && k.Equal(b)
}

// firstLine returns the first line of a file, without its line ending. An
// empty file is an error.
func firstLine(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "", errors.New("empty file")
	}
	line, _, _ := bytes.Cut(data, []byte("\n"))
	return strings.TrimSuffix(string(line), "\r"), nil
}

// withLeaf parses the certificate's leaf when the loader left it unset.
func withLeaf(cert tls.Certificate) (tls.Certificate, error) {
	if cert.Leaf != nil {
		return cert, nil
	}
	if len(cert.Certificate) == 0 {
		return cert, errors.New("no certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return cert, err
	}
	cert.Leaf = leaf
	return cert, nil
}

// loadClientCAs reads a PEM bundle of client CAs into a fresh pool. The
// pool never includes the system roots.
func loadClientCAs(path string) (*x509.CertPool, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, fmt.Errorf("--tls-client-ca-file: %w", err)
	}
	pool := x509.NewCertPool()
	n := 0
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, 0, fmt.Errorf("--tls-client-ca-file %s: certificate %d: %w", path, n+1, err)
		}
		pool.AddCert(c)
		n++
	}
	if n == 0 {
		return nil, 0, fmt.Errorf("--tls-client-ca-file %s: no PEM certificate", path)
	}
	return pool, n, nil
}

// Fingerprint is the SHA-256 of a DER certificate, the identity of a
// known client.
type Fingerprint [sha256.Size]byte

// FingerprintOf returns the fingerprint of a DER certificate.
func FingerprintOf(der []byte) Fingerprint { return sha256.Sum256(der) }

// String renders the fingerprint as OpenSSL's `x509 -fingerprint -sha256`
// does: upper-case hex bytes separated by colons.
func (f Fingerprint) String() string {
	const digits = "0123456789ABCDEF"
	b := make([]byte, 0, 3*len(f)-1)
	for i, c := range f {
		if i > 0 {
			b = append(b, ':')
		}
		b = append(b, digits[c>>4], digits[c&0xf])
	}
	return string(b)
}

// ParseFingerprint reads a SHA-256 fingerprint in hex, with or without
// colons between the bytes, in either case.
func ParseFingerprint(s string) (Fingerprint, error) {
	var f Fingerprint
	h := strings.ReplaceAll(s, ":", "")
	if len(h) != 2*len(f) {
		return f, errors.New("want a SHA-256 fingerprint: 32 hex bytes, colons optional")
	}
	if _, err := hex.Decode(f[:], []byte(h)); err != nil {
		return f, errors.New("want a SHA-256 fingerprint: 32 hex bytes, colons optional")
	}
	return f, nil
}

// loadKnownClients reads a known-clients file in Web3Signer's format: one
// "<label> <fingerprint>" per line, where the label (Web3Signer writes the
// client's host, optionally with a port) is for the operator and only the
// fingerprint is matched. Blank lines and lines starting with # are
// skipped. A file that lists no client is an error.
func loadKnownClients(path string) (map[Fingerprint]struct{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("--tls-known-clients-file: %w", err)
	}
	known := map[Fingerprint]struct{}{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("--tls-known-clients-file %s line %d: want \"<label> <sha256 fingerprint>\"", path, n)
		}
		f, err := ParseFingerprint(fields[1])
		if err != nil {
			return nil, fmt.Errorf("--tls-known-clients-file %s line %d: %w", path, n, err)
		}
		known[f] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("--tls-known-clients-file %s: %w", path, err)
	}
	if len(known) == 0 {
		return nil, fmt.Errorf("--tls-known-clients-file %s lists no client", path)
	}
	return known, nil
}
