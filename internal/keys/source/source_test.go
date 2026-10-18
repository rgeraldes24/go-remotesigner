// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package source

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type info struct {
	size int64
	mod  time.Time
}

func (i info) Name() string       { return "f" }
func (i info) Size() int64        { return i.size }
func (i info) Mode() fs.FileMode  { return 0o600 }
func (i info) ModTime() time.Time { return i.mod }
func (i info) IsDir() bool        { return false }
func (i info) Sys() any           { return nil }

func keys(fis ...fs.FileInfo) []fs.FileInfo { return fis }

func TestVersion(t *testing.T) {
	start := time.Unix(1_760_000_000, 0)
	old := start.Add(-time.Hour)
	a := Version(start, keys(info{10, old}), info{3, old})
	if a == "" || a != Version(start, keys(info{10, old}), info{3, old}) {
		t.Fatalf("Version is not stable: %q", a)
	}
	for _, other := range []string{
		Version(start, keys(info{11, old}), info{3, old}),
		Version(start, keys(info{10, old.Add(time.Nanosecond)}), info{3, old}),
		Version(start, keys(info{10, old}), info{4, old}),
		Version(start, keys(info{10, old})),
	} {
		if other == a {
			t.Errorf("a changed source has the same version %q", a)
		}
	}
	// A file modified within the racy window gives no version.
	if v := Version(start, keys(info{10, old}), info{3, start.Add(-RacyWindow / 2)}); v != "" {
		t.Errorf("racy password file: version %q", v)
	}
	if v := Version(start, keys(info{10, start.Add(-RacyWindow / 2)})); v != "" {
		t.Errorf("racy key file: version %q", v)
	}
	if v := Version(start, keys(info{10, start.Add(-RacyWindow - time.Second)})); v == "" {
		t.Error("a file older than the racy window has no version")
	}
}

// stat returns the file information of path.
func stat(t *testing.T, path string) fs.FileInfo {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi
}

// A key file replaced by another of the same size and modification time,
// as renaming one extracted keystore over another leaves it, is a new
// version, and so is a key file whose mode changed. A password file is
// versioned by size and modification time only, so fixing its mode keeps
// the version.
func TestVersionFileIdentity(t *testing.T) {
	if _, ok := identity(stat(t, t.TempDir())); !ok {
		t.Skip("no file identity on this platform")
	}
	dir := t.TempDir()
	same := time.Unix(1_760_000_000, 0)
	write := func(name, content string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, same, same); err != nil {
			t.Fatal(err)
		}
		return p
	}
	a, b, pw := write("a.json", "key a"), write("b.json", "key b"), write("pw.txt", "secret")
	start := time.Now()
	before := Version(start, keys(stat(t, a)), stat(t, pw))
	if before == "" {
		t.Fatal("no version")
	}
	if err := os.Rename(b, a); err != nil {
		t.Fatal(err)
	}
	fi := stat(t, a)
	if fi.Size() != 5 || !fi.ModTime().Equal(same) {
		t.Fatalf("the replacement has size %d and time %v", fi.Size(), fi.ModTime())
	}
	replaced := Version(start, keys(fi), stat(t, pw))
	if replaced == before {
		t.Fatalf("a key file renamed over another keeps the version %q", before)
	}

	if err := os.Chmod(pw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(pw, 0o600); err != nil {
		t.Fatal(err)
	}
	if v := Version(start, keys(stat(t, a)), stat(t, pw)); v != replaced {
		t.Errorf("a chmod of the password file changed the version: %q, then %q", replaced, v)
	}
	time.Sleep(10 * time.Millisecond) // past the status-change time's granularity
	if err := os.Chmod(a, 0o400); err != nil {
		t.Fatal(err)
	}
	if v := Version(start, keys(stat(t, a)), stat(t, pw)); v == replaced {
		t.Error("a chmod of the key file kept the version")
	}
}

func TestEach(t *testing.T) {
	var running, peak atomic.Int64
	var mu sync.Mutex
	seen := map[int]int{}
	Each(context.Background(), 50, 3, func(i int) {
		n := running.Add(1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		time.Sleep(time.Millisecond)
		running.Add(-1)
		mu.Lock()
		seen[i]++
		mu.Unlock()
	}, nil)
	if len(seen) != 50 || peak.Load() > 3 {
		t.Fatalf("%d indexes, peak %d", len(seen), peak.Load())
	}
	for i, n := range seen {
		if n != 1 {
			t.Errorf("index %d ran %d times", i, n)
		}
	}
	Each(context.Background(), 0, 4, func(int) { t.Error("called with n = 0") }, nil)
}
