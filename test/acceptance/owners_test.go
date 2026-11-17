// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package acceptance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Secret files must
// belong to the signer's user or to root: another user can read, replace
// or re-mode what it owns, whatever the mode says. Only root can give a
// file away, so this test runs as root only; the signer it starts runs as
// root too, which owns none of the files given to uid 1000.
func TestFilesOfAnotherUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("giving a file to another user needs root")
	}
	const uid = 1000
	give := func(path string) {
		t.Helper()
		if err := os.Chown(path, uid, uid); err != nil {
			t.Fatal(err)
		}
	}
	take := func(path string) {
		t.Helper()
		if err := os.Chown(path, 0, 0); err != nil {
			t.Fatal(err)
		}
	}
	data := t.TempDir()
	first := start(t, options{data: data})
	first.waitReady()
	first.stop()
	refusal := func(name string, o options, want string) {
		t.Helper()
		o.keys = first.keys
		s := launch(t, o)
		if code := s.exitCode(15 * time.Second); code != 1 || !strings.Contains(s.output.String(), want) ||
			!strings.Contains(s.output.String(), "owner uid 1000, signer uid 0: owned by another user") {
			t.Fatalf("%s: exit %d, want 1 and %q\n%s", name, code, want, s.output.String())
		}
	}

	token := filepath.Join(data, "auth-token")
	give(token)
	refusal("another user's token file", options{data: data}, token)
	lax := start(t, options{data: data, keys: first.keys, global: []string{"--strict-file-permissions=false"}})
	lax.waitReady()
	lax.stop()
	if out := lax.output.String(); !strings.Contains(out, "is owned by another user than the signer's and root") ||
		!strings.Contains(out, "owner-uid=1000") || !strings.Contains(out, token) {
		t.Fatalf("no warning naming %s and its owner:\n%s", token, out)
	}
	take(token)

	dir := t.TempDir()
	cf, kf := writePEMPair(t, dir, "server", serverCert(t, false))
	give(kf)
	refusal("another user's TLS key", options{data: data, global: []string{"--tls-cert-file=" + cf, "--tls-key-file=" + kf}}, kf)
}
