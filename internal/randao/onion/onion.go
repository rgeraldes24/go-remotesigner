// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package onion computes layers of the QRL RANDAO hash onion.
//
// It is written from docs/spec/randao-onion.md and its vectors only. In the
// note's terms, layer 0 is derived from the validator's 48-byte seed, every
// further layer is the SHA-256 of the one below it, the on-chain commitment is
// layer L, and a proposal for commitment layer j reveals layer j-1. A reveal r
// is valid for a commitment c exactly when Step(r) == c.
//
// The package is stateless: it holds no seed and caches nothing. The reveal
// service decides which layer may be released.
package onion

import (
	"crypto/sha256"
)

// Size is the length in bytes of every onion layer, commitment and reveal.
const Size = sha256.Size

// DefaultLayers is the default onion length L = 2^20. Interop genesis uses it.
const DefaultLayers uint64 = 1 << 20

// domainTag separates onion derivation from every other use of the seed.
const domainTag = "qrl-randao-onion-v1"

// Base returns layer 0, SHA-256(tag ‖ seed). The signer always passes the
// validator's 48-byte wallet seed; the derivation itself accepts any length.
func Base(seed []byte) [Size]byte {
	buf := make([]byte, 0, len(domainTag)+len(seed))
	buf = append(buf, domainTag...)
	buf = append(buf, seed...)
	x := sha256.Sum256(buf)
	clear(buf)
	return x
}

// Step returns the layer above x, SHA-256(x).
func Step(x [Size]byte) [Size]byte {
	return sha256.Sum256(x[:])
}

// Advance returns the layer k steps above x. Advance(x, 0) is x.
func Advance(x [Size]byte, k uint64) [Size]byte {
	for ; k > 0; k-- {
		x = sha256.Sum256(x[:])
	}
	return x
}

// Top returns layer `layers` of the onion of seed: the commitment of an onion
// of that length. It costs `layers` hashes.
func Top(seed []byte, layers uint64) [Size]byte {
	return Advance(Base(seed), layers)
}

// Find locates c in the onion of seed by stepping up from layer 0, looking at
// layers 0 through maxDepth. It costs at most maxDepth hashes.
//
// When c is layer j, Find returns j, the reveal for c (layer j-1) and true.
// For j == 0 there is no reveal inside the onion: the returned reveal is the
// zero value and the caller must treat the onion as exhausted. When c is not
// among those layers, Find returns false.
func Find(seed []byte, c [Size]byte, maxDepth uint64) (index uint64, reveal [Size]byte, ok bool) {
	x := Base(seed)
	if x == c {
		return 0, [Size]byte{}, true
	}
	for j := uint64(1); j <= maxDepth; j++ {
		next := sha256.Sum256(x[:])
		if next == c {
			return j, x, true
		}
		x = next
		if j == ^uint64(0) {
			break
		}
	}
	return 0, [Size]byte{}, false
}
