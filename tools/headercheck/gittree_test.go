// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGitTreeHash(t *testing.T) {
	// Expected ids were produced by `git write-tree` on the same layouts.
	tests := []struct {
		name  string
		build func(t *testing.T, dir string)
		want  string
	}{
		{
			name:  "empty directory",
			build: func(*testing.T, string) {},
			want:  emptyTree,
		},
		{
			name: "regular, executable, symlink, nested and empty dirs",
			build: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "a"), "hello\n", 0o644)
				writeFile(t, filepath.Join(dir, "sub", "b.sh"), "echo\n", 0o755)
				if err := os.MkdirAll(filepath.Join(dir, "empty"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("a", filepath.Join(dir, "link")); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			},
			want: "680fda65511c360c2c2d07b13785dfc0da8497ca",
		},
		{
			// git compares a directory as "a/", so the file "a.b" sorts first
			// although "a" < "a.b" as plain strings.
			name: "directory ordering",
			build: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "a", "x"), "x", 0o644)
				writeFile(t, filepath.Join(dir, "a.b"), "y", 0o644)
			},
			want: "f3349e4a12a1f55a286107a262e5aed8e5a4de9a",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			tt.build(t, dir)
			got, err := gitTreeHash(dir)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("gitTreeHash = %s, want %s", got, tt.want)
			}
		})
	}
}

func writeFile(t *testing.T, p, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}
