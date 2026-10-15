// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package ssz

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
)

var (
	// ErrEmptyVector is returned for a zero-length vector or bitvector, which
	// the specification declares illegal.
	ErrEmptyVector = errors.New("ssz: vector length must be positive")
	// ErrBitvectorLength is returned when a bitvector's byte length does not
	// match its bit length.
	ErrBitvectorLength = errors.New("ssz: bitvector has the wrong byte length")
	// ErrBitvectorPadding is returned when the unused high bits of a
	// bitvector's last byte are not zero.
	ErrBitvectorPadding = errors.New("ssz: bitvector has non-zero padding bits")
	// ErrBitlistDelimiter is returned for a bitlist without its length
	// delimiter: an empty input, or a last byte of zero.
	ErrBitlistDelimiter = errors.New("ssz: bitlist has no delimiter bit")
)

// Uint64Root returns the hash-tree-root of a uint64: its 8 little-endian
// bytes, right-padded to a chunk.
func Uint64Root(v uint64) [32]byte {
	var c [32]byte
	binary.LittleEndian.PutUint64(c[:8], v)
	return c
}

// ByteVectorRoot returns the hash-tree-root of a Vector[byte, len(b)]:
// merkleize(pack(b)) with no limit and no length mix-in. A Vector[byte, 4627]
// is 145 chunks, padded to 256 leaves.
func ByteVectorRoot(b []byte) ([32]byte, error) {
	if len(b) == 0 {
		return [32]byte{}, ErrEmptyVector
	}
	return Merkleize(Pack(b)), nil
}

// BitvectorRoot returns the hash-tree-root of a Bitvector[n] given its
// serialized bytes: merkleize(pack_bits(bits), limit=(n+255)/256). The byte
// length must be (n+7)/8 and the bits past n must be zero.
func BitvectorRoot(b []byte, n uint64) ([32]byte, error) {
	if n == 0 {
		return [32]byte{}, ErrEmptyVector
	}
	// n/8 + min(n%8, 1) is (n+7)/8 without wrapping for n near 2^64.
	if uint64(len(b)) != n/8+min(n%8, 1) {
		return [32]byte{}, fmt.Errorf("%w: %d bytes for %d bits", ErrBitvectorLength, len(b), n)
	}
	if rem := n % 8; rem != 0 && b[len(b)-1]>>rem != 0 {
		return [32]byte{}, ErrBitvectorPadding
	}
	return MerkleizeWithLimit(Pack(b), chunkLimitForBits(n))
}

// BitlistRoot returns the hash-tree-root of a Bitlist[limit] given its
// serialized bytes, which end with the delimiter bit:
// mix_in_length(merkleize(pack_bits(bits), limit=(limit+255)/256), bit length).
// The delimiter is excluded from the packed bits. Bitlist[32] therefore has a
// chunk limit of 1: its root is sha256(bits ‖ uint256_le(bit length)).
func BitlistRoot(b []byte, limit uint64) ([32]byte, error) {
	if len(b) == 0 || b[len(b)-1] == 0 {
		return [32]byte{}, ErrBitlistDelimiter
	}
	last := b[len(b)-1]
	delimiter := bits.Len8(last) - 1
	bitLen := uint64(len(b)-1)*8 + uint64(delimiter)
	if bitLen > limit {
		return [32]byte{}, fmt.Errorf("%w: bitlist of %d bits, limit %d", ErrLimit, bitLen, limit)
	}
	// pack_bits: the bit bytes without the delimiter, ceil(bitLen/8) of them.
	packed := make([]byte, (bitLen+7)/8)
	copy(packed, b)
	if delimiter != 0 {
		packed[len(packed)-1] = last &^ (1 << delimiter)
	}
	root, err := MerkleizeWithLimit(Pack(packed), chunkLimitForBits(limit))
	if err != nil {
		return [32]byte{}, err
	}
	return MixInLength(root, bitLen), nil
}

// ListRoot returns the hash-tree-root of a List[C, limit] of composite
// elements from their roots: mix_in_length(merkleize(roots, limit), len).
// The limit counts elements, not bytes.
func ListRoot(elementRoots [][32]byte, limit uint64) ([32]byte, error) {
	root, err := MerkleizeWithLimit(elementRoots, limit)
	if err != nil {
		return [32]byte{}, err
	}
	return MixInLength(root, uint64(len(elementRoots))), nil
}

// chunkLimitForBits is chunk_count for Bitvector[n] and Bitlist[n],
// (n+255)/256, written so that it cannot overflow.
func chunkLimitForBits(n uint64) uint64 {
	return n/256 + min(n%256, 1)
}
