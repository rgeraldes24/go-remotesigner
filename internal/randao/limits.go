// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package randao

import (
	"container/list"
	"math/bits"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// bucket is a key's new-layer token bucket. Its level is kept as credit
// time: every token is worth one refill period, the bucket holds at most
// burst periods, and credit accrues with wall-clock time. A zero period
// turns the bucket off. The zero value is a full bucket.
type bucket struct {
	used   time.Duration // credit missing from a full bucket
	at     time.Time     // when used was last brought up to date
	primed bool
}

// refill brings the bucket up to now.
func (b *bucket) refill(now time.Time) {
	if b.primed {
		if d := now.Sub(b.at); d > 0 {
			b.used = max(b.used-d, 0)
		}
	}
	b.at, b.primed = now, true
}

// ready reports whether the bucket holds a token at now.
func (b *bucket) ready(now time.Time, period time.Duration, burst uint64) bool {
	if period <= 0 {
		return true
	}
	b.refill(now)
	return capacity(period, burst)-b.used >= period
}

// take removes one token. Call it only after ready.
func (b *bucket) take(now time.Time, period time.Duration) {
	if period <= 0 {
		return
	}
	b.refill(now)
	b.used += period
}

// capacity is burst periods, saturating.
func capacity(period time.Duration, burst uint64) time.Duration {
	hi, lo := bits.Mul64(uint64(period), burst)
	if hi != 0 || lo > uint64(1<<63-1) {
		return 1<<63 - 1
	}
	return time.Duration(lo)
}

// negativeCache remembers (key, commitment) pairs that a full scan did not
// find, so that repeating an unknown commitment costs no further scan. It
// evicts the least recently used entry beyond its size. It is not safe for
// concurrent use.
type negativeCache struct {
	size  int
	order *list.List // of negKey, most recent first
	items map[negKey]*list.Element
}

type negKey struct {
	id         slashing.KeyID
	commitment [32]byte
}

func newNegativeCache(size int) *negativeCache {
	return &negativeCache{size: size, order: list.New(), items: map[negKey]*list.Element{}}
}

func (c *negativeCache) contains(k negKey) bool {
	e, ok := c.items[k]
	if ok {
		c.order.MoveToFront(e)
	}
	return ok
}

func (c *negativeCache) add(k negKey) {
	if e, ok := c.items[k]; ok {
		c.order.MoveToFront(e)
		return
	}
	c.items[k] = c.order.PushFront(k)
	for c.order.Len() > c.size {
		last := c.order.Back()
		c.order.Remove(last)
		delete(c.items, last.Value.(negKey))
	}
}

// window reports whether slot lies in [now_slot - 1, now_slot + skew], with
// now_slot = floor((now - genesis) / secondsPerSlot), which is negative
// before genesis. It never overflows.
func window(now time.Time, genesis, secondsPerSlot, skew, slot uint64) bool {
	t := uint64(max(now.Unix(), 0))
	if t >= genesis {
		ns := (t - genesis) / secondsPerSlot
		if ns >= 1 && slot < ns-1 {
			return false
		}
		hi, carry := bits.Add64(ns, skew, 0)
		return carry != 0 || slot <= hi
	}
	d := genesis - t
	back := d/secondsPerSlot + min(d%secondsPerSlot, 1) // now_slot = -back
	return skew >= back && slot <= skew-back
}
