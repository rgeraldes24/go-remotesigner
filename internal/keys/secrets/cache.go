// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"crypto/sha256"
	"sync"
)

// Cache holds up to Max store clients, by the connection settings they
// were built from, so that the documents of one store share one client
// across loads, as Web3Signer's client caches do. When it is full, the
// least recently used client is closed and dropped.
type Cache[K comparable, V any] struct {
	// Max is the number of clients kept; at least one is.
	Max int
	// Close releases a dropped client; nil releases nothing.
	Close func(V)

	mu      sync.Mutex
	entries map[K]*cacheEntry[V]
	tick    uint64
}

type cacheEntry[V any] struct {
	v    V
	used uint64
}

// Get returns the client of k, building it with build when the cache has
// none. A build error is returned and nothing is cached.
func (c *Cache[K, V]) Get(k K, build func() (V, error)) (V, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tick++
	if e, ok := c.entries[k]; ok {
		e.used = c.tick
		return e.v, nil
	}
	v, err := build()
	if err != nil {
		return v, err
	}
	if c.entries == nil {
		c.entries = map[K]*cacheEntry[V]{}
	}
	for len(c.entries) >= max(1, c.Max) {
		var oldest K
		first := true
		for key, e := range c.entries {
			if first || e.used < c.entries[oldest].used {
				oldest, first = key, false
			}
		}
		c.drop(oldest)
	}
	c.entries[k] = &cacheEntry[V]{v: v, used: c.tick}
	return v, nil
}

// Len returns the number of cached clients.
func (c *Cache[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// Purge closes and drops every client.
func (c *Cache[K, V]) Purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.entries {
		c.drop(k)
	}
}

func (c *Cache[K, V]) drop(k K) {
	if c.Close != nil {
		c.Close(c.entries[k].v)
	}
	delete(c.entries, k)
}

// Digest is SHA-256 of a credential, for a cache key that must tell two
// credentials apart without holding either.
func Digest(b []byte) [sha256.Size]byte { return sha256.Sum256(b) }
