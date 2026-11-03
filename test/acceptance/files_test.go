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
// group or other users can read or write refuses startup under the strict
// policy (the default) and is loaded with a warning without it. The cases
// the audits probed: a 0644 admin token file with the keymanager enabled,
// and a 0622 one, which others cannot read but can fill with a token of
// their choice.
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
	if err := os.Chmod(admin, 0o622); err != nil {
		t.Fatal(err)
	}
	writable := launch(t, options{data: data, keys: first.keys})
	if code := writable.exitCode(15 * time.Second); code != 1 || !strings.Contains(out(writable), admin) ||
		!strings.Contains(out(writable), "mode 0622: readable or writable by group or other users") {
		t.Fatalf("a 0622 admin token file: exit %d\n%s", code, out(writable))
	}
	if err := os.Chmod(admin, 0o644); err != nil {
		t.Fatal(err)
	}

	lax := startKM(t, options{data: data, keys: first.keys, global: []string{"--strict-file-permissions=false"}})
	lax.waitReady()
	if code, _, body := lax.km("GET", ""); code != 200 {
		t.Fatalf("the keymanager with the 0644 admin token, not strict: %d %s", code, body)
	}
	lax.stop()
	if !strings.Contains(out(lax), "A token or TLS key file is readable or writable by its group or other users") ||
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

	// A data path that others can write refuses the start that would
	// generate the token files in it, and no token file is written there;
	// without the strict policy they are generated with a warning naming it.
	open := t.TempDir()
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	openRefused := launch(t, options{data: open, keys: first.keys})
	if code := openRefused.exitCode(15 * time.Second); code != 1 ||
		!strings.Contains(out(openRefused), "directory "+open+": mode 0777: writable by group or other users") {
		t.Fatalf("a 0777 data path: exit %d\n%s", code, out(openRefused))
	}
	for _, name := range []string{"auth-token", "admin-token"} {
		if _, err := os.Stat(filepath.Join(open, name)); err == nil {
			t.Fatalf("%s was generated in the refused data path", name)
		}
	}
	openLax := start(t, options{data: open, keys: first.keys, global: []string{"--strict-file-permissions=false"}})
	openLax.waitReady()
	openLax.stop()
	if !strings.Contains(out(openLax), "A token file is generated in a directory that its group or other users can write") ||
		!strings.Contains(out(openLax), open) {
		t.Fatalf("no warning naming the 0777 data path %s:\n%s", open, out(openLax))
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
