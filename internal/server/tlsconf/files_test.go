// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package tlsconf

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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

// The files that say whom the listener trusts (--tls-known-clients-file,
// --tls-client-ca-file) hold no secret, so anyone may read them, but one
// that its group or other users can write is refused under the strict
// policy and loaded with a warning otherwise: whoever writes it adds a
// client of their own. Loosened while the signer runs, it fails the
// reload's client trust, which then accepts nobody.
func TestTrustFilePermissions(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writePEM(t, dir, "server", serverPair(t))
	ca := issue(t, nil, "client CA", true, 0)
	known := knownClientsFile(t, filepath.Join(dir, "known"), clientPair(t, nil, "vc"))
	caFile := writeFile(t, filepath.Join(dir, "ca.pem"), certPEM(ca.cert))
	for _, tt := range []struct {
		name string
		file string
		cfg  Config
	}{
		{"--tls-known-clients-file", known, Config{CertFile: certFile, KeyFile: keyFile, KnownClientsFile: known}},
		{"--tls-client-ca-file", caFile, Config{CertFile: certFile, KeyFile: keyFile, ClientCAFile: caFile}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			strict := Options{RequireClientCert: true, Files: secretfile.Policy{Strict: true},
				TrustFiles: secretfile.Policy{Strict: true}}
			for _, mode := range []fs.FileMode{0o600, 0o644, 0o444} {
				if err := os.Chmod(tt.file, mode); err != nil {
					t.Fatal(err)
				}
				if _, err := New(tt.cfg, strict); err != nil {
					t.Fatalf("%04o, strict: %v", mode, err)
				}
			}
			s, err := New(tt.cfg, strict)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(tt.file, 0o600) })
			for _, mode := range []fs.FileMode{0o664, 0o646, 0o660} {
				if err := os.Chmod(tt.file, mode); err != nil {
					t.Fatal(err)
				}
				_, err := New(tt.cfg, strict)
				if !errors.Is(err, secretfile.ErrWritable) || !strings.Contains(err.Error(), tt.name+": "+tt.file) {
					t.Fatalf("%04o, strict: %v, want ErrWritable naming the flag and %s", mode, err, tt.file)
				}
			}

			// The reload refuses it too, and refuses every client with it.
			_, err = s.Reload()
			var re *ReloadError
			if !errors.As(err, &re) || !errors.Is(re.ClientTrust, secretfile.ErrWritable) || re.Certificate != nil {
				t.Fatalf("reload with a 0660 trust file: %v, want a client-trust ReloadError of ErrWritable", err)
			}

			var warned, secrets []string
			loose := Options{RequireClientCert: true,
				Files:      secretfile.Policy{Strict: true, Warn: func(path string, _ fs.FileMode) { secrets = append(secrets, path) }},
				TrustFiles: secretfile.Policy{Warn: func(path string, _ fs.FileMode) { warned = append(warned, path) }}}
			if _, err := New(tt.cfg, loose); err != nil {
				t.Fatalf("0660, not strict: %v", err)
			}
			if len(warned) != 1 || warned[0] != tt.file || len(secrets) != 0 {
				t.Fatalf("0660, not strict: warned about %v (and %v as secret files), want %s", warned, secrets, tt.file)
			}
		})
	}

	// A trust file must be a regular file.
	cfg := Config{CertFile: certFile, KeyFile: keyFile, KnownClientsFile: dir}
	if _, err := New(cfg, Options{RequireClientCert: true}); !errors.Is(err, secretfile.ErrNotRegular) {
		t.Fatalf("a directory as the known-clients file: %v", err)
	}
}
