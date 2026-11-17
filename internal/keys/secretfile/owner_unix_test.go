// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package secretfile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// ownedBy is a file's info with another owner.
type ownedBy struct {
	fs.FileInfo
	uid uint32
}

func (o ownedBy) Sys() any { return &syscall.Stat_t{Uid: o.uid} }

// noOwner is a file's info that does not come from the operating system.
type noOwner struct{ fs.FileInfo }

func (noOwner) Sys() any { return nil }

// asUID makes the signer's effective uid uid for the test.
func asUID(t *testing.T, uid int) {
	t.Helper()
	old := euid
	euid = func() int { return uid }
	t.Cleanup(func() { euid = old })
}

// A secret file and a token directory must belong to the
// signer's effective uid or to root: another user's is refused under the
// strict policy, whatever its mode, and passes with a warning naming the
// owner otherwise. Info without a uid is not checked.
func TestOwnerPolicy(t *testing.T) {
	const signer, other = 65532, 1000
	asUID(t, signer)
	file := write(t, "hunter2\n", 0o600)
	fileInfo, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(file)
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name  string
		path  string
		info  fs.FileInfo
		check func(Policy, string, fs.FileInfo) error
		named string // how the refusal names the path
	}{
		{"secret file", file, fileInfo, Policy.Check, file},
		{"directory", dir, dirInfo, Policy.CheckDir, "directory " + dir},
	}
	for _, c := range checks {
		for _, tt := range []struct {
			name    string
			info    fs.FileInfo
			foreign bool
		}{
			{"the signer's", ownedBy{c.info, signer}, false},
			{"root's", ownedBy{c.info, 0}, false},
			{"another user's", ownedBy{c.info, other}, true},
			{"nobody's", ownedBy{c.info, 65534}, true},
			{"no uid", noOwner{c.info}, false},
		} {
			for _, strict := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s/%s/strict=%v", c.name, tt.name, strict), func(t *testing.T) {
					var warned []string
					pol := Policy{Strict: strict,
						Warn:    func(path string, _ fs.FileMode) { t.Errorf("Warn(%s) for an owner", path) },
						WarnDir: func(path string, _ fs.FileMode) { t.Errorf("WarnDir(%s) for an owner", path) },
						WarnOwner: func(path string, uid uint32) {
							warned = append(warned, fmt.Sprintf("%s %d", path, uid))
						}}
					err := c.check(pol, c.path, tt.info)
					if tt.foreign && strict {
						if !errors.Is(err, ErrForeignOwner) {
							t.Fatalf("got %v, want ErrForeignOwner", err)
						}
						uid := tt.info.(ownedBy).uid
						want := fmt.Sprintf("%s: owner uid %d, signer uid %d: owned by another user", c.named, uid, signer)
						if !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "--strict-file-permissions=false") {
							t.Errorf("error %q does not say %q and name the flag", err, want)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					var want []string
					if tt.foreign {
						want = []string{fmt.Sprintf("%s %d", c.path, tt.info.(ownedBy).uid)}
					}
					if fmt.Sprint(warned) != fmt.Sprint(want) {
						t.Fatalf("owner warnings %v, want %v", warned, want)
					}
				})
			}
		}
	}

	// A nil WarnOwner warns nobody, and a signer that runs as root is
	// refused another user's file too.
	if err := (Policy{}).Check(file, ownedBy{fileInfo, other}); err != nil {
		t.Errorf("not strict, no WarnOwner: %v", err)
	}
	asUID(t, 0)
	if err := (Policy{Strict: true}).Check(file, ownedBy{fileInfo, other}); !errors.Is(err, ErrForeignOwner) {
		t.Errorf("root reading another user's file: %v", err)
	}
}

// Read checks the owner of the file it opened; a file
// with both faults is refused for its mode first, and warned about for
// both without the strict policy.
func TestReadChecksOwner(t *testing.T) {
	file := write(t, "hunter2\n", 0o600)
	if _, err := Read(file, 64, Policy{Strict: true}); err != nil {
		t.Fatalf("the test's own file: %v", err)
	}
	asUID(t, os.Geteuid()+1)
	if os.Geteuid() == 0 {
		t.Skip("root owns the test's files, and root's files pass")
	}
	if got, err := Read(file, 64, Policy{Strict: true}); !errors.Is(err, ErrForeignOwner) || got != nil {
		t.Fatalf("Read = %q, %v; want ErrForeignOwner", got, err)
	}
	loose := write(t, "hunter2\n", 0o644)
	if _, err := Read(loose, 64, Policy{Strict: true}); !errors.Is(err, ErrInsecure) {
		t.Fatalf("a 0644 file of another user: %v, want ErrInsecure first", err)
	}
	var modes, owners int
	pol := Policy{Warn: func(string, fs.FileMode) { modes++ }, WarnOwner: func(string, uint32) { owners++ }}
	if got, err := Read(loose, 64, pol); err != nil || string(got) != "hunter2\n" || modes != 1 || owners != 1 {
		t.Fatalf("Read = %q, %v with %d mode and %d owner warnings; want the content and one of each", got, err, modes, owners)
	}
}

// A file that really belongs to another user is refused; only root can
// make one.
func TestForeignOwnedFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("giving a file to another user needs root")
	}
	file := write(t, "hunter2\n", 0o600)
	if err := os.Chown(file, 1000, 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(file, 64, Policy{Strict: true}); !errors.Is(err, ErrForeignOwner) {
		t.Fatalf("Read = %v, want ErrForeignOwner", err)
	}
}
