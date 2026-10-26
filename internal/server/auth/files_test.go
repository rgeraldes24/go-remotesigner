// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package auth

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/secretfile"
)

// A token file that its group or other users can read is refused under the
// strict policy, at startup and on Reload, and loaded with a warning
// otherwise; a generated token file is 0600 and passes.
func TestTokenFilePermissions(t *testing.T) {
	strict := secretfile.Policy{Strict: true}
	for _, scope := range []string{"sign", "admin", "metrics"} {
		for _, mode := range []fs.FileMode{0o644, 0o640, 0o604} {
			dir := t.TempDir()
			cfg := Config{Mode: ModeToken, SignTokenFile: writeToken(t, dir, "sign", signTok),
				AdminTokenFile: writeToken(t, dir, "admin", adminTok), MetricsTokenFile: writeToken(t, dir, "metrics", otherTok)}
			loose := filepath.Join(dir, scope)
			if err := os.Chmod(loose, mode); err != nil {
				t.Fatal(err)
			}
			cfg.Files = strict
			if _, err := New(cfg); !errors.Is(err, secretfile.ErrInsecure) {
				t.Errorf("%s token file mode %04o, strict: %v, want ErrInsecure", scope, mode, err)
			}
			var warned []string
			cfg.Files = secretfile.Policy{Warn: func(path string, _ fs.FileMode) { warned = append(warned, path) }}
			if _, err := New(cfg); err != nil {
				t.Errorf("%s token file mode %04o, not strict: %v", scope, mode, err)
			}
			if len(warned) != 1 || warned[0] != loose {
				t.Errorf("%s token file mode %04o, not strict: warned about %v, want %s", scope, mode, warned, loose)
			}
		}
	}

	// A generated token file passes the strict policy.
	dir := filepath.Join(t.TempDir(), "data")
	a, err := New(Config{Mode: ModeToken, SignTokenFile: filepath.Join(dir, "auth-token"),
		AdminTokenFile: filepath.Join(dir, "admin-token"), Files: strict})
	if err != nil {
		t.Fatalf("generated token files, strict: %v", err)
	}

	// A token file loosened after startup fails the reload, and the tokens
	// in force stay.
	if err := os.Chmod(filepath.Join(dir, "admin-token"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := a.Reload(); !errors.Is(err, secretfile.ErrInsecure) {
		t.Fatalf("reload with a 0644 admin token file: %v, want ErrInsecure", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "admin-token"))
	if err != nil {
		t.Fatal(err)
	}
	if e := a.Check(request(string(data[:len(data)-1])), ScopeAdmin); e != nil {
		t.Fatalf("the admin token in force before the failed reload: %v", e)
	}
}
