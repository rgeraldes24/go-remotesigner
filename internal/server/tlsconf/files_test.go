// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package tlsconf

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/secretfile"
)

// The TLS files that hold a private key or its password (--tls-key-file,
// --tls-keystore-file, --tls-keystore-password-file and a reused
// self-signed key) are secret files: one that its group or other users can
// read is refused under the strict policy and loaded with a warning
// otherwise. The certificate is public and is not checked.
func TestSecretFilePermissions(t *testing.T) {
	dir := t.TempDir()
	srv := serverPair(t)
	certFile, keyFile := writePEM(t, dir, "server", srv)
	p12, err := pkcs12.Modern.Encode(srv.key, srv.cert, nil, "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	keystore := writeFile(t, filepath.Join(dir, "server.p12"), p12)
	password := writeFile(t, filepath.Join(dir, "password"), []byte("s3cret\n"))
	selfDir := filepath.Join(dir, "tls")
	if _, err := New(Config{GenerateSelfSigned: true}, Options{SelfSignedDir: selfDir, SelfSignedHosts: []string{"localhost"}}); err != nil {
		t.Fatal(err)
	}
	pem := Config{CertFile: certFile, KeyFile: keyFile}
	pkcs := Config{KeystoreFile: keystore, KeystorePasswordFile: password}
	self := Config{GenerateSelfSigned: true}
	selfOpts := Options{SelfSignedDir: selfDir, SelfSignedHosts: []string{"localhost"}}

	tests := []struct {
		name  string
		cfg   Config
		opts  Options
		loose string
	}{
		{"--tls-key-file", pem, Options{}, keyFile},
		{"--tls-keystore-file", pkcs, Options{}, keystore},
		{"--tls-keystore-password-file", pkcs, Options{}, password},
		{"reused self-signed key", self, selfOpts, filepath.Join(selfDir, SelfSignedKeyFile)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strict, loose := tt.opts, tt.opts
			strict.Files = secretfile.Policy{Strict: true}
			if _, err := New(tt.cfg, strict); err != nil {
				t.Fatalf("0600, strict: %v", err)
			}
			if err := os.Chmod(tt.loose, 0o644); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(tt.loose, 0o600) })
			if _, err := New(tt.cfg, strict); !errors.Is(err, secretfile.ErrInsecure) {
				t.Fatalf("0644, strict: %v, want ErrInsecure", err)
			}
			var warned []string
			loose.Files = secretfile.Policy{Warn: func(path string, _ fs.FileMode) { warned = append(warned, path) }}
			if _, err := New(tt.cfg, loose); err != nil {
				t.Fatalf("0644, not strict: %v", err)
			}
			if len(warned) != 1 || warned[0] != tt.loose {
				t.Fatalf("0644, not strict: warned about %v, want %s", warned, tt.loose)
			}
		})
	}

	// The certificate file is not a secret: 0644 passes the strict policy.
	if err := os.Chmod(certFile, 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := New(pem, Options{Files: secretfile.Policy{Strict: true}})
	if err != nil {
		t.Fatalf("a 0644 certificate with a 0600 key, strict: %v", err)
	}

	// A key loosened after startup fails the reload's certificate, and the
	// certificate in force stays.
	if err := os.Chmod(keyFile, 0o644); err != nil {
		t.Fatal(err)
	}
	before := s.Info().Fingerprint
	info, err := s.Reload()
	var re *ReloadError
	if !errors.As(err, &re) || !errors.Is(re.Certificate, secretfile.ErrInsecure) {
		t.Fatalf("reload with a 0644 key: %v, want a certificate ReloadError of ErrInsecure", err)
	}
	if info.Fingerprint != before {
		t.Fatal("the certificate in force changed after the failed reload")
	}
}
