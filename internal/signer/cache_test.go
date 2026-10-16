// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"io"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/consensus/signingroot"
	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
)

// clock is a settable time source.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func cachingSigner(t *testing.T, size int, ttl time.Duration) (*Signer, *keyset, *clock) {
	t.Helper()
	ks := &keyset{keys: map[ID]Key{}}
	l := logrus.New()
	l.SetOutput(io.Discard)
	c := &clock{now: time.Unix(1760000000, 0)}
	s := New(Config{Lookup: ks.get, SelectionProofMode: mldsa87.Deterministic, Log: l, CacheTTL: ttl, CacheSize: size, Now: c.Now})
	return s, ks, c
}

func TestCacheTTL(t *testing.T) {
	if got := CacheTTL(60, 128); got != 4*time.Hour+16*time.Minute {
		t.Fatalf("mainnet: %v", got)
	}
	if got := CacheTTL(10, 6); got != 2*time.Minute {
		t.Fatalf("end-to-end: %v", got)
	}
}

// G4 S16: with the cache on, a repeated hedged request gets the bytes
// released the first time; another type, root or key does not; an entry
// lasts the TTL.
func TestCacheRepeats(t *testing.T) {
	s, ks, c := cachingSigner(t, DefaultCacheSize, 2*time.Minute)
	k, other := newKey(t, 1), newKey(t, 2)
	ks.set(k.ID(), k)
	ks.set(other.ID(), other)
	root := [32]byte{9}
	if _, ok := s.Cached(k.ID(), signingroot.Attestation, root); ok {
		t.Fatal("hit on an empty cache")
	}
	first, err := s.Sign(k.ID(), k, signingroot.Attestation, root)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s.Cached(k.ID(), signingroot.Attestation, root)
	if !ok || got != first {
		t.Fatal("a repeated hedged request did not get the released bytes")
	}
	for name, miss := range map[string]func() bool{
		"other type": func() bool { _, ok := s.Cached(k.ID(), signingroot.BlockV2, root); return ok },
		"other root": func() bool { _, ok := s.Cached(k.ID(), signingroot.Attestation, [32]byte{8}); return ok },
		"other key":  func() bool { _, ok := s.Cached(other.ID(), signingroot.Attestation, root); return ok },
	} {
		if miss() {
			t.Errorf("%s: hit", name)
		}
	}
	c.advance(2*time.Minute - time.Second)
	if _, ok := s.Cached(k.ID(), signingroot.Attestation, root); !ok {
		t.Fatal("entry gone before its TTL")
	}
	c.advance(time.Second)
	if _, ok := s.Cached(k.ID(), signingroot.Attestation, root); ok {
		t.Fatal("entry served after its TTL")
	}
	if s.cache.len() != 0 {
		t.Fatal("expired entry kept")
	}
	// After expiry a new signature is made and cached in turn.
	second, err := s.Sign(k.ID(), k, signingroot.Attestation, root)
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatal("hedged signature repeated after expiry")
	}
	if got, ok := s.Cached(k.ID(), signingroot.Attestation, root); !ok || got != second {
		t.Fatal("the new signature was not cached")
	}
}

// The cache holds at most its size, evicting the least recently used.
func TestCacheBound(t *testing.T) {
	s, ks, _ := cachingSigner(t, 3, time.Hour)
	k := newKey(t, 1)
	ks.set(k.ID(), k)
	sign := func(b byte) {
		t.Helper()
		if _, err := s.Sign(k.ID(), k, signingroot.SyncCommitteeMessage, [32]byte{b}); err != nil {
			t.Fatal(err)
		}
	}
	hit := func(b byte) bool {
		_, ok := s.Cached(k.ID(), signingroot.SyncCommitteeMessage, [32]byte{b})
		return ok
	}
	sign(1)
	sign(2)
	sign(3)
	if !hit(1) { // 1 becomes the most recently used
		t.Fatal("entry 1 missing")
	}
	sign(4)
	if s.cache.len() != 3 || hit(2) || !hit(1) || !hit(3) || !hit(4) {
		t.Fatalf("after the 4th entry: %d entries, 1 %v 2 %v 3 %v 4 %v", s.cache.len(), hit(1), hit(2), hit(3), hit(4))
	}
}

// The default bound is 4,096 entries, about 19 MB of signatures.
func TestCacheDefaultSize(t *testing.T) {
	s, _, _ := cachingSigner(t, 0, time.Hour)
	if s.cache.size != 4096 {
		t.Fatalf("size %d", s.cache.size)
	}
	if bytes := s.cache.size * mldsa87.SignatureSize; bytes > 19<<20 {
		t.Fatalf("%d bytes of signatures", bytes)
	}
	off, _, _ := cachingSigner(t, 0, 0)
	if off.cache != nil {
		t.Fatal("a zero TTL left the cache on")
	}
	if _, ok := off.Cached(ID{}, signingroot.Attestation, [32]byte{}); ok {
		t.Fatal("hit with the cache off")
	}
}

// A key load that removes a key drops its cached responses.
func TestCacheDropsRemovedKeys(t *testing.T) {
	s, ks, _ := cachingSigner(t, DefaultCacheSize, time.Hour)
	k, kept := newKey(t, 1), newKey(t, 2)
	ks.set(k.ID(), k)
	ks.set(kept.ID(), kept)
	root := [32]byte{5}
	for _, key := range []*mldsa87.Key{k, kept} {
		if _, err := s.Sign(key.ID(), key, signingroot.Attestation, root); err != nil {
			t.Fatal(err)
		}
	}
	ks.mu.Lock()
	delete(ks.keys, k.ID())
	ks.mu.Unlock()
	s.Release()
	if _, ok := s.Cached(k.ID(), signingroot.Attestation, root); ok {
		t.Fatal("a removed key's response is still cached")
	}
	if _, ok := s.Cached(kept.ID(), signingroot.Attestation, root); !ok {
		t.Fatal("a loaded key's response was dropped")
	}
}

// Concurrent identical requests that all missed the cache get one
// signature once the first has been cached.
func TestCacheConcurrentRepeats(t *testing.T) {
	s, ks, _ := cachingSigner(t, DefaultCacheSize, time.Hour)
	k := newKey(t, 1)
	ks.set(k.ID(), k)
	root := [32]byte{3}
	sigs := make([]Signature, 8)
	var wg sync.WaitGroup
	for i := range sigs {
		wg.Go(func() {
			sig, err := s.Sign(k.ID(), k, signingroot.Attestation, root)
			if err != nil {
				t.Error(err)
			}
			sigs[i] = sig
		})
	}
	wg.Wait()
	cached, _ := s.Cached(k.ID(), signingroot.Attestation, root)
	for i, sig := range sigs {
		if sig != cached {
			t.Fatalf("request %d got a signature other than the cached one", i)
		}
	}
}
