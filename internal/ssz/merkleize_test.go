// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package ssz

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func mustRoot(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad root literal %q", s)
	}
	return [32]byte(b)
}

// chunkOf returns a chunk whose bytes are all v.
func chunkOf(v byte) (c [32]byte) {
	for i := range c {
		c[i] = v
	}
	return c
}

// explicitMerkleize is the specification's merkleize with the padding done
// for real: append zero chunks up to width (a power of two), then hash pairs
// until one root is left. It is the reference for the virtual padding.
func explicitMerkleize(chunks [][32]byte, width int) [32]byte {
	layer := append([][32]byte(nil), chunks...)
	for len(layer) < width {
		layer = append(layer, [32]byte{})
	}
	for len(layer) > 1 {
		next := make([][32]byte, len(layer)/2)
		for i := range next {
			next[i] = sha256.Sum256(append(layer[2*i][:], layer[2*i+1][:]...))
		}
		layer = next
	}
	return layer[0]
}

func nextPowOfTwo(n int) int {
	p := 1
	for p < n {
		p *= 2
	}
	return p
}

func TestZeroHashes(t *testing.T) {
	// The zero-subtree roots used across Ethereum and QRL alike.
	tests := []struct {
		depth int
		want  string
	}{
		{0, "0000000000000000000000000000000000000000000000000000000000000000"},
		{1, "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"},
		{5, "9efde052aa15429fae05bad4d0b1d7c64da64d03d7a1854a588c2cb8430c0d30"},
		{7, "87eb0ddba57e35f6d286673802a4af5975e22506c7cf4c64bb6be5ee11527f2c"},
		{8, "26846476fd5fc54a5d43385167c95144f2643f533cc85bb9d16b782f8d7db193"},
	}
	for _, tt := range tests {
		if got := ZeroHash(tt.depth); got != mustRoot(t, tt.want) {
			t.Errorf("ZeroHash(%d) = %x, want %s", tt.depth, got, tt.want)
		}
		if got := explicitMerkleize(nil, 1<<tt.depth); got != ZeroHash(tt.depth) {
			t.Errorf("explicit zero tree of depth %d = %x, want %x", tt.depth, got, ZeroHash(tt.depth))
		}
	}
}

func TestDepthFor(t *testing.T) {
	tests := []struct {
		n    uint64
		want int
	}{
		{0, 0}, {1, 0}, {2, 1}, {3, 2}, {4, 2}, {5, 3}, {32, 5}, {33, 6}, {128, 7}, {145, 8}, {256, 8},
		{1 << 63, 63}, {1<<63 + 1, 64}, {^uint64(0), 64},
	}
	for _, tt := range tests {
		if got := depthFor(tt.n); got != tt.want {
			t.Errorf("depthFor(%d) = %d, want %d", tt.n, got, tt.want)
		}
	}
}

func TestPack(t *testing.T) {
	tests := []struct {
		name   string
		in     []byte
		chunks int
	}{
		{"empty", nil, 0},
		{"one byte", []byte{7}, 1},
		{"one chunk", make([]byte, 32), 1},
		{"chunk plus one", make([]byte, 33), 2},
		{"address", make([]byte, 64), 2},
		{"pubkey", make([]byte, 2592), 81},
		{"signature", make([]byte, 4627), 145},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := len(Pack(tt.in)); got != tt.chunks {
				t.Fatalf("len(Pack) = %d, want %d", got, tt.chunks)
			}
		})
	}
	got := Pack([]byte{1, 2, 3})
	want := [32]byte{1, 2, 3}
	if got[0] != want {
		t.Fatalf("Pack right-pads with zeros: got %x", got[0])
	}
}

func TestMerkleizeMatchesExplicitPadding(t *testing.T) {
	for n := 0; n <= 70; n++ {
		chunks := make([][32]byte, n)
		for i := range chunks {
			chunks[i] = chunkOf(byte(i + 1))
		}
		saved := append([][32]byte(nil), chunks...)

		if got, want := Merkleize(chunks), explicitMerkleize(chunks, nextPowOfTwo(n)); got != want {
			t.Errorf("Merkleize(%d chunks) = %x, want %x", n, got, want)
		}
		for _, limit := range []int{n, n + 1, 2 * n, 128, 300} {
			if limit < n {
				continue
			}
			got, err := MerkleizeWithLimit(chunks, uint64(limit))
			if err != nil {
				t.Fatalf("MerkleizeWithLimit(%d chunks, %d): %v", n, limit, err)
			}
			if want := explicitMerkleize(chunks, nextPowOfTwo(limit)); got != want {
				t.Errorf("MerkleizeWithLimit(%d chunks, %d) = %x, want %x", n, limit, got, want)
			}
		}
		for i := range chunks {
			if chunks[i] != saved[i] {
				t.Fatalf("Merkleize modified its input at %d", i)
			}
		}
	}
}

func TestMerkleizeWithLimitRejectsOverflow(t *testing.T) {
	chunks := make([][32]byte, 33)
	if _, err := MerkleizeWithLimit(chunks, 32); !errors.Is(err, ErrLimit) {
		t.Fatalf("33 chunks with limit 32: err = %v, want ErrLimit", err)
	}
	if _, err := MerkleizeWithLimit(chunks[:1], 0); !errors.Is(err, ErrLimit) {
		t.Fatalf("1 chunk with limit 0: err = %v, want ErrLimit", err)
	}
	// Limit 0 is legal for no chunks and pads to a single zero chunk.
	if got, err := MerkleizeWithLimit(nil, 0); err != nil || got != ([32]byte{}) {
		t.Fatalf("no chunks with limit 0 = %x, %v; want the zero chunk", got, err)
	}
	// The largest limit gives a depth-64 tree without overflowing.
	got, err := MerkleizeWithLimit(nil, ^uint64(0))
	if err != nil || got != ZeroHash(64) {
		t.Fatalf("no chunks with limit 2^64-1 = %x, %v; want ZeroHash(64)", got, err)
	}
}

func TestMixInLength(t *testing.T) {
	// mix_in_length(Z0, 0) is sha256 of 64 zero bytes, which is Z1.
	if got := MixInLength([32]byte{}, 0); got != ZeroHash(1) {
		t.Fatalf("MixInLength(zero, 0) = %x, want %x", got, ZeroHash(1))
	}
	root := chunkOf(0xaa)
	var length [32]byte
	length[0], length[1] = 0x34, 0x12 // 0x1234, uint256 little-endian
	want := sha256.Sum256(append(root[:], length[:]...))
	if got := MixInLength(root, 0x1234); got != want {
		t.Fatalf("MixInLength = %x, want %x", got, want)
	}
}

func TestContainerRoot(t *testing.T) {
	a, b, c := chunkOf(1), chunkOf(2), chunkOf(3)
	h := func(x, y [32]byte) [32]byte { return sha256.Sum256(append(x[:], y[:]...)) }
	tests := []struct {
		name   string
		fields [][32]byte
		want   [32]byte
	}{
		{"one field is the field itself", [][32]byte{a}, a},
		{"two fields", [][32]byte{a, b}, h(a, b)},
		{"three fields pad to four", [][32]byte{a, b, c}, h(h(a, b), h(c, [32]byte{}))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ContainerRoot(tt.fields...); got != tt.want {
				t.Fatalf("ContainerRoot = %x, want %x", got, tt.want)
			}
		})
	}
}
