// Copyright 2020 ConsenSys AG.
// Copyright 2026 The go-remotesigner Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//
// Modified by The go-remotesigner Authors, 2026: translated from Java to Go and adapted for QRL.
// Derived from Web3Signer
// signing/src/main/java/tech/pegasys/web3signer/signing/config/DefaultArtifactSignerProvider.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

// Package provider holds the loaded keys as an immutable snapshot behind an
// atomic pointer: lookups are lock-free, and a load builds a new snapshot
// copy-on-write and swaps it in, so readers see the old or the new key set,
// never a mix.
//
// A load never turns a failure into a removal. Keys come in batches, one per
// source (a key-config file); a batch that failed to load keeps the keys it
// had. Keys absent from a successful load are evicted from memory and
// zeroized, but nothing about them is written anywhere: in particular their
// slashing-protection rows are untouched. A key that is already loaded keeps
// its in-memory object across loads, so in-flight users of it are not
// disturbed.
package provider

import (
	"bytes"
	"errors"
	"iter"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
)

// ID is a key id: SHA-256 of the public key.
type ID = [mldsa87.IDSize]byte

// Entry is a loaded key and the source it came from.
type Entry struct {
	Key    *mldsa87.Key
	PK     mldsa87.PublicKey
	Source string
}

// Batch is the outcome of loading one source: its keys, or the error that
// made it fail.
type Batch struct {
	Source string
	Keys   []*mldsa87.Key
	Err    error
}

// Delta summarises an Apply.
type Delta struct {
	Added, Removed, Kept int
	// Errors counts the batches that failed.
	Errors int
}

// ErrClosed is returned by Apply after Close.
var ErrClosed = errors.New("provider: closed")

// snapshot is an immutable key set.
type snapshot struct {
	byID     map[ID]*Entry
	sorted   []*Entry // by public key bytes, i.e. by canonical identifier
	bySource map[string][]*Entry
}

var empty = &snapshot{byID: map[ID]*Entry{}, bySource: map[string][]*Entry{}}

// Provider is the loaded key set. Reads are safe for concurrent use; Apply
// and Close are serialised.
type Provider struct {
	log   logrus.FieldLogger
	state atomic.Pointer[snapshot]

	mu     sync.Mutex // serialises writers
	closed bool
}

// New returns an empty provider.
func New(log logrus.FieldLogger) *Provider {
	p := &Provider{log: log}
	p.state.Store(empty)
	return p
}

// Get returns the key with id.
func (p *Provider) Get(id ID) (*mldsa87.Key, bool) {
	e, ok := p.state.Load().byID[id]
	if !ok {
		return nil, false
	}
	return e.Key, true
}

// Len returns the number of loaded keys.
func (p *Provider) Len() int { return len(p.state.Load().byID) }

// PublicKeys yields the public keys of one snapshot, sorted by their bytes
// (the order of their canonical identifiers).
func (p *Provider) PublicKeys() iter.Seq[*mldsa87.PublicKey] {
	s := p.state.Load()
	return func(yield func(*mldsa87.PublicKey) bool) {
		for _, e := range s.sorted {
			if !yield(&e.PK) {
				return
			}
		}
	}
}

// Apply builds the next key set from batches and swaps it in:
//
//   - a failed batch keeps the keys its source had in the current set;
//   - a key already loaded keeps its current object, and the duplicate just
//     derived is zeroized;
//   - of two batches with the same key, the first wins, with a warning;
//   - sources absent from batches are dropped.
//
// Before the swap, register is called with the public keys that are new to
// the set (it registers them in slashing protection); if it fails, nothing
// changes, the new keys are zeroized and its error is returned. After the
// swap, keys no longer in the set are zeroized. Apply takes ownership of
// every key in batches.
func (p *Provider) Apply(batches []Batch, register func(pubkeys [][]byte) error) (Delta, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		for _, b := range batches {
			zeroize(b.Keys)
		}
		return Delta{}, ErrClosed
	}
	cur := p.state.Load()
	next := &snapshot{byID: map[ID]*Entry{}, bySource: map[string][]*Entry{}}
	var (
		d       Delta
		added   [][]byte
		fresh   []*mldsa87.Key // keys of this load that entered the set
		discard []*mldsa87.Key // keys of this load that did not
	)
	put := func(e *Entry) bool {
		id := e.Key.ID()
		if _, dup := next.byID[id]; dup {
			p.log.WithField("key", e.PK.LogID()).Warn("Duplicate key while loading; keeping the first")
			return false
		}
		next.byID[id] = e
		next.bySource[e.Source] = append(next.bySource[e.Source], e)
		return true
	}
	for _, b := range batches {
		if b.Err != nil {
			d.Errors++
			discard = append(discard, b.Keys...)
			for _, e := range cur.bySource[b.Source] {
				if put(e) {
					d.Kept++
				}
			}
			continue
		}
		for _, k := range b.Keys {
			if old, ok := cur.byID[k.ID()]; ok {
				discard = append(discard, k)
				put(&Entry{Key: old.Key, PK: old.PK, Source: b.Source})
				continue
			}
			if !put(&Entry{Key: k, PK: k.PublicKey(), Source: b.Source}) {
				discard = append(discard, k)
				continue
			}
			fresh = append(fresh, k)
			pk := k.PublicKey()
			added = append(added, pk[:])
		}
	}
	if len(added) > 0 && register != nil {
		if err := register(added); err != nil {
			zeroize(discard)
			zeroize(fresh)
			return Delta{Errors: d.Errors}, err
		}
	}
	d.Added = len(added)

	next.sorted = make([]*Entry, 0, len(next.byID))
	for _, e := range next.byID {
		next.sorted = append(next.sorted, e)
	}
	slices.SortFunc(next.sorted, func(a, b *Entry) int { return bytes.Compare(a.PK[:], b.PK[:]) })
	p.state.Store(next)

	zeroize(discard)
	for id, e := range cur.byID {
		if _, ok := next.byID[id]; !ok {
			e.Key.Zeroize()
			d.Removed++
		}
	}
	return d, nil
}

// Close empties the set and zeroizes every key. Later Apply calls fail.
func (p *Provider) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	cur := p.state.Swap(empty)
	for _, e := range cur.byID {
		e.Key.Zeroize()
	}
}

func zeroize(keys []*mldsa87.Key) {
	for _, k := range keys {
		k.Zeroize()
	}
}
