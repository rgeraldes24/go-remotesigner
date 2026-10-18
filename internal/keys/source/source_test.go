// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package source

import (
	"context"
	"io/fs"
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

func TestVersion(t *testing.T) {
	start := time.Unix(1_760_000_000, 0)
	old := start.Add(-time.Hour)
	a := Version(start, info{10, old}, info{3, old})
	if a == "" || a != Version(start, info{10, old}, info{3, old}) {
		t.Fatalf("Version is not stable: %q", a)
	}
	for _, other := range []string{
		Version(start, info{11, old}, info{3, old}),
		Version(start, info{10, old.Add(time.Nanosecond)}, info{3, old}),
		Version(start, info{10, old}),
	} {
		if other == a {
			t.Errorf("a changed source has the same version %q", a)
		}
	}
	// A file modified within the racy window gives no version.
	if v := Version(start, info{10, old}, info{3, start.Add(-RacyWindow / 2)}); v != "" {
		t.Errorf("racy file: version %q", v)
	}
	if v := Version(start, info{10, start.Add(-RacyWindow - time.Second)}); v == "" {
		t.Error("a file older than the racy window has no version")
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
