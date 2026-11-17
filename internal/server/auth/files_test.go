// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package auth

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/secretfile"
)

// A token file that its group or other users can read or write is refused
// under the strict policy, at startup and on Reload, and loaded with a
// warning otherwise; an owner-only one, such as a generated token file
// (0600), passes silently. One they can write but not read (0602, 0620,
// 0622) is refused too: they would choose the token.
func TestTokenFilePermissions(t *testing.T) {
	strict := secretfile.Policy{Strict: true}
	for _, tt := range []struct {
		mode     fs.FileMode
		insecure bool
	}{
		{0o600, false},
		{0o400, false},
		{0o602, true},
		{0o604, true},
		{0o620, true},
		{0o622, true},
		{0o640, true},
		{0o644, true},
		{0o660, true},
	} {
		for _, scope := range []string{"sign", "admin", "metrics"} {
			for _, isStrict := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s/%04o/strict=%v", scope, tt.mode, isStrict), func(t *testing.T) {
					dir := t.TempDir()
					cfg := Config{Mode: ModeToken, SignTokenFile: writeToken(t, dir, "sign", signTok),
						AdminTokenFile: writeToken(t, dir, "admin", adminTok), MetricsTokenFile: writeToken(t, dir, "metrics", otherTok)}
					loose := filepath.Join(dir, scope)
					if err := os.Chmod(loose, tt.mode); err != nil {
						t.Fatal(err)
					}
					var warned []string
					cfg.Files = secretfile.Policy{Strict: isStrict, Warn: func(path string, _ fs.FileMode) { warned = append(warned, path) }}
					_, err := New(cfg)
					switch {
					case tt.insecure && isStrict:
						if !errors.Is(err, secretfile.ErrInsecure) || !strings.Contains(err.Error(), loose) {
							t.Fatalf("New = %v, want ErrInsecure naming %s", err, loose)
						}
					case err != nil:
						t.Fatalf("New = %v", err)
					case tt.insecure && (len(warned) != 1 || warned[0] != loose):
						t.Fatalf("warned about %v, want %s", warned, loose)
					case !tt.insecure && len(warned) != 0:
						t.Fatalf("warned about %v, want no warning", warned)
					}
				})
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

	// A token file loosened after startup, here made writable by others,
	// fails the reload, and the tokens in force stay.
	if err := os.Chmod(filepath.Join(dir, "admin-token"), 0o602); err != nil {
		t.Fatal(err)
	}
	if err := a.Reload(); !errors.Is(err, secretfile.ErrInsecure) {
		t.Fatalf("reload with a 0602 admin token file: %v, want ErrInsecure", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "admin-token"))
	if err != nil {
		t.Fatal(err)
	}
	if e := a.Check(request(string(data[:len(data)-1])), ScopeAdmin); e != nil {
		t.Fatalf("the admin token in force before the failed reload: %v", e)
	}
}

// A token file is generated only in a directory that its group and other
// users cannot write: under the strict policy a writable one, such as a
// --data-path made 0770 or 0777, is refused, at startup and on the Reload
// that would generate a deleted token, and nothing is written into it;
// otherwise the token is generated with a warning naming the directory. A
// directory they can only read or enter, such as 0755, passes silently.
func TestTokenFileDirectoryPermissions(t *testing.T) {
	for _, tt := range []struct {
		mode     fs.FileMode
		insecure bool
	}{
		{0o700, false},
		{0o750, false},
		{0o755, false},
		{0o702, true},
		{0o720, true},
		{0o770, true},
		{0o775, true},
		{0o777, true},
	} {
		for _, strict := range []bool{true, false} {
			t.Run(fmt.Sprintf("%04o/strict=%v", tt.mode, strict), func(t *testing.T) {
				data := filepath.Join(t.TempDir(), "data")
				if err := os.Mkdir(data, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(data, tt.mode); err != nil { // not subject to the umask
					t.Fatal(err)
				}
				var warned []string
				pol := secretfile.Policy{Strict: strict,
					Warn: func(path string, _ fs.FileMode) { t.Errorf("Warn(%s) for a generated token file", path) },
					WarnDir: func(path string, mode fs.FileMode) {
						warned = append(warned, path)
						if mode != tt.mode {
							t.Errorf("warned with mode %04o", mode)
						}
					}}
				cfg := Config{Mode: ModeToken, SignTokenFile: filepath.Join(data, "auth-token"),
					AdminTokenFile: filepath.Join(data, "admin-token"), Files: pol}
				a, err := New(cfg)
				if tt.insecure && strict {
					if !errors.Is(err, secretfile.ErrDirInsecure) || !strings.Contains(err.Error(), data) {
						t.Fatalf("New = %v, want ErrDirInsecure naming %s", err, data)
					}
					if entries, err := os.ReadDir(data); err != nil || len(entries) != 0 {
						t.Fatalf("the refused directory holds %v (%v), want nothing", entries, err)
					}
					return
				}
				if err != nil {
					t.Fatalf("New = %v", err)
				}
				if want := map[bool]int{true: 2, false: 0}[tt.insecure]; len(warned) != want {
					t.Fatalf("warned about %v, want %d warnings", warned, want)
				}
				for _, name := range []string{"auth-token", "admin-token"} {
					if fi, err := os.Stat(filepath.Join(data, name)); err != nil || fi.Mode().Perm() != 0o600 {
						t.Fatalf("%s: %v, %v; want a 0600 file", name, fi, err)
					}
				}

				// The Reload that would generate a deleted token checks the
				// directory again, and the tokens in force stay when it fails.
				if err := os.Remove(filepath.Join(data, "admin-token")); err != nil {
					t.Fatal(err)
				}
				a.cfg.Files.Strict = true
				err = a.Reload()
				if tt.insecure {
					if !errors.Is(err, secretfile.ErrDirInsecure) {
						t.Fatalf("Reload = %v, want ErrDirInsecure", err)
					}
					if a.admin == nil {
						t.Fatal("the admin token in force was dropped")
					}
					return
				}
				if err != nil {
					t.Fatalf("Reload = %v", err)
				}
			})
		}
	}
}

// A token file that exists is loaded only from a directory that its group
// and other users cannot write, as a missing one is generated only in
// such a directory: whoever can write the directory can put a token of
// their own in the file's place, whatever the file's mode. Under the
// strict policy a writable directory is refused, at startup and on
// Reload, where the tokens in force stay; otherwise the token is loaded
// with a warning naming the directory. The sticky bit exempts nothing.
func TestExistingTokenDirectoryPermissions(t *testing.T) {
	for _, tt := range []struct {
		mode     fs.FileMode
		insecure bool
	}{
		{0o700, false},
		{0o750, false},
		{0o755, false},
		{0o720, true},
		{0o770, true},
		{0o775, true},
		{0o777, true},
		{0o777 | fs.ModeSticky, true},
		{0o770 | fs.ModeSetgid, true},
	} {
		for _, strict := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/strict=%v", secretfile.Octal(tt.mode), strict), func(t *testing.T) {
				data := filepath.Join(t.TempDir(), "data")
				if err := os.Mkdir(data, 0o700); err != nil {
					t.Fatal(err)
				}
				cfg := Config{Mode: ModeToken, SignTokenFile: writeToken(t, data, "auth-token", signTok),
					AdminTokenFile: writeToken(t, data, "admin-token", adminTok)}
				var warned []string
				cfg.Files = secretfile.Policy{Strict: strict,
					Warn:    func(path string, _ fs.FileMode) { t.Errorf("Warn(%s) for a 0600 token file", path) },
					WarnDir: func(path string, _ fs.FileMode) { warned = append(warned, path) }}

				// Loaded from the 0700 directory, then reloaded from the
				// directory as the case has it.
				a, err := New(Config{Mode: cfg.Mode, SignTokenFile: cfg.SignTokenFile, AdminTokenFile: cfg.AdminTokenFile,
					Files: secretfile.Policy{Strict: true}})
				if err != nil {
					t.Fatalf("New from a 0700 directory: %v", err)
				}
				if err := os.Chmod(data, tt.mode); err != nil { // not subject to the umask
					t.Fatal(err)
				}
				if fi, err := os.Stat(data); err != nil || fi.Mode()&fs.ModeSetgid != tt.mode&fs.ModeSetgid {
					t.Skipf("this file system does not keep the mode %s: %v, %v", secretfile.Octal(tt.mode), fi, err)
				}
				a.cfg.Files = cfg.Files
				rerr := a.Reload()
				_, nerr := New(cfg)
				for name, err := range map[string]error{"Reload": rerr, "New": nerr} {
					switch {
					case tt.insecure && strict:
						if !errors.Is(err, secretfile.ErrDirInsecure) ||
							!strings.Contains(err.Error(), "directory "+data+": mode "+secretfile.Octal(tt.mode)) {
							t.Fatalf("%s = %v, want ErrDirInsecure naming %s and its mode", name, err, data)
						}
					case err != nil:
						t.Fatalf("%s = %v", name, err)
					}
				}
				if e := a.Check(request(adminTok), ScopeAdmin); e != nil {
					t.Fatalf("the admin token in force: %v", e)
				}
				// Reload and New each warn once for each of the two files.
				if want := map[bool]int{true: 4, false: 0}[tt.insecure && !strict]; len(warned) != want {
					t.Fatalf("warned about %v, want %d warnings", warned, want)
				}
				for _, w := range warned {
					if w != data {
						t.Fatalf("warned about %s, want %s", w, data)
					}
				}
			})
		}
	}
}

// A token file reached through a symbolic link is held to the directory
// the link is in and to the one the file is in: an entry replaced in
// either changes the token that is read.
func TestSymlinkedTokenDirectoryPermissions(t *testing.T) {
	root := t.TempDir()
	conf, secrets := filepath.Join(root, "conf"), filepath.Join(root, "secrets")
	for _, d := range []string{conf, secrets} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	target := writeToken(t, secrets, "token", signTok)
	link := filepath.Join(conf, "auth-token")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Mode: ModeToken, SignTokenFile: link, Files: secretfile.Policy{Strict: true}}
	if _, err := New(cfg); err != nil {
		t.Fatalf("both directories 0700: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(secrets)
	if err != nil {
		t.Fatal(err)
	}
	for dir, named := range map[string]string{secrets: resolved, conf: conf} {
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		if _, err := New(cfg); !errors.Is(err, secretfile.ErrDirInsecure) || !strings.Contains(err.Error(), "directory "+named+":") {
			t.Fatalf("%s made 0777: %v, want ErrDirInsecure naming %s", dir, err, named)
		}
		var warned []string
		lax := cfg
		lax.Files = secretfile.Policy{WarnDir: func(path string, _ fs.FileMode) { warned = append(warned, path) }}
		if _, err := New(lax); err != nil || len(warned) != 1 || warned[0] != named {
			t.Fatalf("%s made 0777, not strict: %v, warned about %v; want %s", dir, err, warned, named)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
}

// Generated token files get a directory of their own, mode 0700, when
// the data path does not exist, and pass the strict policy on the next
// load.
func TestGeneratedTokenDirectoryMode(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	data := filepath.Join(t.TempDir(), "a", "data")
	cfg := Config{Mode: ModeToken, SignTokenFile: filepath.Join(data, "auth-token"),
		AdminTokenFile: filepath.Join(data, "admin-token"), Files: secretfile.Policy{Strict: true}}
	if _, err := New(cfg); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{data, filepath.Dir(data)} {
		if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("%s: %v, %v; want mode 0700 with a umask of 0", dir, fi, err)
		}
	}
	if _, err := New(cfg); err != nil {
		t.Fatalf("the second load: %v", err)
	}
}
