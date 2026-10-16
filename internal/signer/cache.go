// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"container/list"
	"sync"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/consensus/signingroot"
)

// The response cache (docs/contract.md section 15) keeps the signatures it
// released, keyed by key, artifact type and signing root, so that a repeat
// of a request gets the same bytes instead of a fresh signature:
//
//   - hedged signing gives a different signature on every call, so without
//     the cache a client retry would not be idempotent;
//   - a repeat costs no new signing computation, which bounds how many
//     signatures of one message a client can collect (the raw material of a
//     fault attack on deterministic signing).
//
// Both bounds are the contract's (contract §15): 4,096 entries of about
// 4.7 KB (about 19 MB), each kept for two epochs, longer than any client
// retries a duty.
const (
	// DefaultCacheSize is the response cache's capacity.
	DefaultCacheSize = 4096
	// CacheEpochs is how many epochs an entry is served.
	CacheEpochs = 2
)

// CacheTTL returns the response cache's entry lifetime on a network:
// CacheEpochs epochs.
func CacheTTL(secondsPerSlot, slotsPerEpoch uint64) time.Duration {
	return time.Duration(CacheEpochs*slotsPerEpoch*secondsPerSlot) * time.Second
}

type cacheKey struct {
	id   ID
	typ  signingroot.ArtifactType
	root [32]byte
}

type cacheEntry struct {
	key     cacheKey
	sig     Signature
	expires time.Time
}

// responseCache is a bounded LRU of released signatures whose entries
// expire after ttl. It is safe for concurrent use.
type responseCache struct {
	size int
	ttl  time.Duration
	now  func() time.Time

	mu    sync.Mutex
	order *list.List // of *cacheEntry, most recently used first
	byKey map[cacheKey]*list.Element
}

func newResponseCache(size int, ttl time.Duration, now func() time.Time) *responseCache {
	return &responseCache{size: size, ttl: ttl, now: now, order: list.New(), byKey: map[cacheKey]*list.Element{}}
}

// get returns the live entry for k and marks it recently used; an expired
// entry is dropped.
func (c *responseCache) get(k cacheKey) (Signature, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.byKey[k]
	if !ok {
		return Signature{}, false
	}
	e := el.Value.(*cacheEntry)
	if !c.now().Before(e.expires) {
		c.remove(el)
		return Signature{}, false
	}
	c.order.MoveToFront(el)
	return e.sig, true
}

// put stores sig for k, evicting the least recently used entry beyond the
// capacity, and returns the signature to release. A live entry keeps its
// bytes, which put returns: of concurrent identical requests that all
// missed the cache, every one that finishes after the first gets the
// first's signature.
func (c *responseCache) put(k cacheKey, sig *Signature) Signature {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.byKey[k]; ok {
		e := el.Value.(*cacheEntry)
		if c.now().Before(e.expires) {
			c.order.MoveToFront(el)
			return e.sig
		}
		c.remove(el)
	}
	c.byKey[k] = c.order.PushFront(&cacheEntry{key: k, sig: *sig, expires: c.now().Add(c.ttl)})
	for c.order.Len() > c.size {
		c.remove(c.order.Back())
	}
	return *sig
}

// retain drops the entries of every key keep rejects.
func (c *responseCache) retain(keep func(ID) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for el := c.order.Front(); el != nil; {
		next := el.Next()
		if !keep(el.Value.(*cacheEntry).key.id) {
			c.remove(el)
		}
		el = next
	}
}

func (c *responseCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

// remove needs c.mu.
func (c *responseCache) remove(el *list.Element) {
	delete(c.byKey, el.Value.(*cacheEntry).key)
	c.order.Remove(el)
}
