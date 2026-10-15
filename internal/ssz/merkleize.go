// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package ssz computes SSZ hash-tree-roots.
//
// It implements the merkleization half of the SSZ specification (Ethereum
// consensus specs v1.5.0, ssz/simple-serialize.md, CC0-1.0): pack, merkleize
// with an optional limit, mix_in_length, and the roots of the basic and
// collection types the signer hashes. The signer never serialises or
// deserialises SSZ, so there is no codec here.
//
// Padding to a power of two is virtual: missing subtrees are filled from a
// table of precomputed zero-subtree roots, so a List[Vector[byte,4627],128]
// with two elements hashes two elements, not 128.
package ssz

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
)

// BytesPerChunk is the size of a Merkle leaf.
const BytesPerChunk = 32

// maxDepth is the depth of a tree with 2^64 leaves, the most a uint64 limit
// can ask for.
const maxDepth = 64

// ErrLimit is returned when an input has more chunks or elements than its
// type allows.
var ErrLimit = errors.New("ssz: input exceeds limit")

// zeroHashes[d] is the root of a complete tree of depth d whose leaves are
// all zero chunks.
var zeroHashes = func() (z [maxDepth + 1][32]byte) {
	for d := 1; d <= maxDepth; d++ {
		z[d] = hashPair(z[d-1], z[d-1])
	}
	return z
}()

// ZeroHash returns the root of a complete tree of the given depth (0 to 64)
// whose leaves are all zero chunks.
func ZeroHash(depth int) [32]byte {
	return zeroHashes[depth]
}

func hashPair(a, b [32]byte) [32]byte {
	var buf [64]byte
	copy(buf[:32], a[:])
	copy(buf[32:], b[:])
	return sha256.Sum256(buf[:])
}

// Pack splits b into 32-byte chunks, right-padding the last one with zeros.
// An empty input gives no chunks.
func Pack(b []byte) [][32]byte {
	chunks := make([][32]byte, (len(b)+BytesPerChunk-1)/BytesPerChunk)
	for i := range chunks {
		copy(chunks[i][:], b[i*BytesPerChunk:])
	}
	return chunks
}

// Merkleize returns the root of chunks padded with zero chunks to the next
// power of two of their count (merkleize without a limit). No chunks give the
// zero chunk.
func Merkleize(chunks [][32]byte) [32]byte {
	return merkleize(chunks, depthFor(uint64(len(chunks))))
}

// MerkleizeWithLimit returns the root of chunks padded with zero chunks to
// the next power of two of limit. It fails with ErrLimit if there are more
// chunks than limit.
func MerkleizeWithLimit(chunks [][32]byte, limit uint64) ([32]byte, error) {
	if uint64(len(chunks)) > limit {
		return [32]byte{}, fmt.Errorf("%w: %d chunks, limit %d", ErrLimit, len(chunks), limit)
	}
	return merkleize(chunks, depthFor(limit)), nil
}

// MixInLength returns sha256(root ‖ uint256_le(length)).
func MixInLength(root [32]byte, length uint64) [32]byte {
	var l [32]byte
	binary.LittleEndian.PutUint64(l[:8], length)
	return hashPair(root, l)
}

// ContainerRoot returns the root of a container from the roots of its fields
// in declaration order.
func ContainerRoot(fieldRoots ...[32]byte) [32]byte {
	return Merkleize(fieldRoots)
}

// depthFor returns log2(next_pow_of_two(n)), with 0 and 1 both giving 0.
func depthFor(n uint64) int {
	if n <= 1 {
		return 0
	}
	return bits.Len64(n - 1)
}

// merkleize hashes chunks into a tree of the given depth. Pairs whose right
// sibling is past the end of the input use the zero-subtree root of that
// level, which is the virtual padding the specification allows. chunks is
// never modified.
func merkleize(chunks [][32]byte, depth int) [32]byte {
	if len(chunks) == 0 {
		return zeroHashes[depth]
	}
	if depth == 0 {
		return chunks[0]
	}
	layer := make([][32]byte, (len(chunks)+1)/2)
	n := pairUp(layer, chunks, 0)
	for d := 1; d < depth; d++ {
		// pairUp writes element i after reading elements 2i and 2i+1, so
		// the layer can be reduced in place.
		n = pairUp(layer[:n], layer[:n], d)
	}
	return layer[0]
}

// pairUp writes the parents of src (a layer at the given level) into dst and
// returns their count.
func pairUp(dst, src [][32]byte, level int) int {
	n := (len(src) + 1) / 2
	for i := 0; i < n; i++ {
		right := zeroHashes[level]
		if 2*i+1 < len(src) {
			right = src[2*i+1]
		}
		dst[i] = hashPair(src[2*i], right)
	}
	return n
}
