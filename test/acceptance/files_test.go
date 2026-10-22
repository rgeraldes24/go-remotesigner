// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package acceptance

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The listener's own secret files follow --strict-file-permissions like the
// password and key-config files do: a token file or a TLS key that its
// group or other users can read refuses startup under the strict policy
// (the default) and is loaded with a warning without it. The case the
// audit probed first: a 0644 admin token file with the keymanager enabled.
func TestListenerSecretFilePermissions(t *testing.T) {
	data := t.TempDir()
	first := startKM(t, options{data: data})
	first.waitReady()
	first.stop()
	admin := filepath.Join(data, "admin-token")
	if err := os.Chmod(admin, 0o644); err != nil {
		t.Fatal(err)
	}

	refused := launch(t, options{data: data, keys: first.keys,
		consensus: []string{"--key-manager-api-enabled", "--network-genesis-validators-root=" + goldenGVR(t)}})
	out := func(s *signer) string { return s.output.String() }
	if code := refused.exitCode(15 * time.Second); code != 1 || !strings.Contains(out(refused), admin) ||
		!strings.Contains(out(refused), "mode 0644") {
		t.Fatalf("a 0644 admin token file: exit %d\n%s", code, out(refused))
	}

	lax := startKM(t, options{data: data, keys: first.keys, global: []string{"--strict-file-permissions=false"}})
	lax.waitReady()
	if code, _, body := lax.km("GET", ""); code != 200 {
		t.Fatalf("the keymanager with the 0644 admin token, not strict: %d %s", code, body)
	}
	lax.stop()
	if !strings.Contains(out(lax), "A token or TLS key file is readable by its group or other users") ||
		!strings.Contains(out(lax), admin) {
		t.Fatalf("no warning naming %s:\n%s", admin, out(lax))
	}

	// A sign token file loosened while the signer runs fails the SIGHUP
	// reload, and the tokens in force stay.
	if err := os.Chmod(admin, 0o600); err != nil {
		t.Fatal(err)
	}
	s := start(t, options{data: data, keys: first.keys})
	s.waitReady()
	tok := s.signToken()
	if err := os.Chmod(filepath.Join(data, "auth-token"), 0o640); err != nil {
		t.Fatal(err)
	}
	s.signal(syscall.SIGHUP)
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(out(s), "Reloading the token files failed") {
		if time.Now().After(deadline) {
			t.Fatalf("no reload failure logged:\n%s", out(s))
		}
		time.Sleep(10 * time.Millisecond)
	}
	if code, _, _ := s.do(request{path: "/api/v1/consensus/publicKeys", token: tok}); code != 200 {
		t.Fatalf("the sign token in force before the failed reload: %d", code)
	}
	s.stop()
	if err := os.Chmod(filepath.Join(data, "auth-token"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A reused self-signed TLS key that others can read refuses startup.
	tlsData := t.TempDir()
	gen := start(t, options{data: tlsData, global: []string{"--tls-generate-self-signed"}})
	gen.stop()
	key := filepath.Join(tlsData, "tls", "key.pem")
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	reuse := launch(t, options{data: tlsData, global: []string{"--tls-generate-self-signed"}})
	if code := reuse.exitCode(15 * time.Second); code != 1 || !strings.Contains(out(reuse), key) {
		t.Fatalf("a 0644 self-signed key: exit %d\n%s", code, out(reuse))
	}

	// So does a --tls-key-file that others can read.
	srv := serverCert(t, false)
	cf, kf := writePEMPair(t, t.TempDir(), "server", srv)
	if err := os.Chmod(kf, 0o644); err != nil {
		t.Fatal(err)
	}
	pemKey := launch(t, options{global: []string{"--tls-cert-file=" + cf, "--tls-key-file=" + kf}})
	if code := pemKey.exitCode(15 * time.Second); code != 1 || !strings.Contains(out(pemKey), kf) {
		t.Fatalf("a 0644 --tls-key-file: exit %d\n%s", code, out(pemKey))
	}
}
