// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"crypto/sha256"
	"sync"
)

// Cache holds up to Max store clients, by the connection settings they
// were built from, so that the documents of one store share one client.
// When it is full, the least recently used client is dropped, and closed
// once no fetch uses it.
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
	v       V
	used    uint64
	refs    int  // fetches using v
	dropped bool // no longer in the cache: closed when refs reaches 0
}

// Get returns the client of k, building it with build when the cache has
// none, and the function to call when the fetch is done with it, which
// closes a client dropped meanwhile. A build error is returned and nothing
// is cached.
func (c *Cache[K, V]) Get(k K, build func() (V, error)) (V, func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tick++
	e, ok := c.entries[k]
	if !ok {
		v, err := build()
		if err != nil {
			return v, nil, err
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
		e = &cacheEntry[V]{v: v}
		c.entries[k] = e
	}
	e.used = c.tick
	e.refs++
	return e.v, sync.OnceFunc(func() { c.release(e) }), nil
}

// Len returns the number of cached clients.
func (c *Cache[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// Purge drops every client, closing each once no fetch uses it. The cache
// stays usable: the next Get builds a new client.
func (c *Cache[K, V]) Purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.entries {
		c.drop(k)
	}
}

func (c *Cache[K, V]) drop(k K) {
	e := c.entries[k]
	delete(c.entries, k)
	e.dropped = true
	if e.refs == 0 {
		c.close(e.v)
	}
}

func (c *Cache[K, V]) release(e *cacheEntry[V]) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e.refs--
	if e.dropped && e.refs == 0 {
		c.close(e.v)
	}
}

func (c *Cache[K, V]) close(v V) {
	if c.Close != nil {
		c.Close(v)
	}
}

// Digest is SHA-256 of a credential, for a cache key that must tell two
// credentials apart without holding either.
func Digest(b []byte) [sha256.Size]byte { return sha256.Sum256(b) }
