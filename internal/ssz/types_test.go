// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package ssz

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
)

const (
	pubkeyLen    = 2592 // ML-DSA-87 public key
	signatureLen = 4627 // ML-DSA-87 signature
)

func mustByteVectorRoot(t *testing.T, b []byte) [32]byte {
	t.Helper()
	r, err := ByteVectorRoot(b)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestAnchors pins the values every implementation of the QRL signing
// containers has to reproduce. They were also computed by
// internal/consensus/testdata/gen_fixtures.py, an independent implementation.
func TestAnchors(t *testing.T) {
	zeroSig := mustByteVectorRoot(t, make([]byte, signatureLen))
	tests := []struct {
		name string
		root func() ([32]byte, error)
		want string
	}{
		{"zero Vector[byte,2592] = Z7", func() ([32]byte, error) { return ByteVectorRoot(make([]byte, pubkeyLen)) },
			"87eb0ddba57e35f6d286673802a4af5975e22506c7cf4c64bb6be5ee11527f2c"},
		{"zero Vector[byte,4627] = Z8", func() ([32]byte, error) { return ByteVectorRoot(make([]byte, signatureLen)) },
			"26846476fd5fc54a5d43385167c95144f2643f533cc85bb9d16b782f8d7db193"},
		{"empty List[signature,32]", func() ([32]byte, error) { return ListRoot(nil, 32) },
			"52e2647abc3d0c9d3be0387f3f0d925422c7a4e98cf4489066f0f43281a899f3"},
		{"empty List[signature,128]", func() ([32]byte, error) { return ListRoot(nil, 128) },
			"96559674a79656e540871e1f39c9b91e152aa8cddb71493e754827c4cc809d57"},
		{"empty List[signature,16]", func() ([32]byte, error) { return ListRoot(nil, 16) },
			"792930bbd5baac43bcc798ee49aa8185ef76bb3b44ba62b91d86ae569e4bb535"},
		{"[zero signature] in List[signature,32]", func() ([32]byte, error) { return ListRoot([][32]byte{zeroSig}, 32) },
			"34037bca7b0d04fde7c26d17fbb52a5be433c0015e87c7acf672180578e65e36"},
		{"[zero signature] in List[signature,128]", func() ([32]byte, error) { return ListRoot([][32]byte{zeroSig}, 128) },
			"56c2e976eff8df1702d8483b48db6c7b385d7ae4a4d01af55571af6d15906923"},
		{"[zero signature] in List[signature,16]", func() ([32]byte, error) { return ListRoot([][32]byte{zeroSig}, 16) },
			"c431634702b0dd00314f91113ace0803b220fb0f59503076eece946fafbc54d4"},
		{"empty Bitlist[32] 0x01 = Z1", func() ([32]byte, error) { return BitlistRoot([]byte{0x01}, 32) },
			"f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"},
		{"Bitlist[32] 0x14 (4 bits, bit 2 set)", func() ([32]byte, error) { return BitlistRoot([]byte{0x14}, 32) },
			"3c27186a030991e3d008114becb58b249cf038d500d1323185bc899e500a9a60"},
		{"Bitlist[32] 0xffffffff01 (32 bits, 5 bytes)", func() ([32]byte, error) {
			return BitlistRoot([]byte{0xff, 0xff, 0xff, 0xff, 0x01}, 32)
		}, "85297ab0b2f486660b993498387f40c2e81c41f68a38fd9c69816d954249c3c4"},
		{"Bitvector[16] 0x0500", func() ([32]byte, error) { return BitvectorRoot([]byte{0x05, 0x00}, 16) },
			"0500000000000000000000000000000000000000000000000000000000000000"},
		{"Bitvector[128] 0x0500…00", func() ([32]byte, error) {
			b := make([]byte, 16)
			b[0] = 0x05
			return BitvectorRoot(b, 128)
		}, "0500000000000000000000000000000000000000000000000000000000000000"},
		{"uint64 1234", func() ([32]byte, error) { return Uint64Root(1234), nil },
			"d204000000000000000000000000000000000000000000000000000000000000"},
		{"uint64 max", func() ([32]byte, error) { return Uint64Root(^uint64(0)), nil },
			"ffffffffffffffff000000000000000000000000000000000000000000000000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.root()
			if err != nil {
				t.Fatal(err)
			}
			if got != mustRoot(t, tt.want) {
				t.Fatalf("root = %x, want %s", got, tt.want)
			}
		})
	}
}

// A Vector[byte,4627] is 145 chunks (the last holds 19 data bytes and 13 zero
// bytes), padded to 256 leaves, with no length mix-in.
func TestByteVector4627Chunking(t *testing.T) {
	sig := make([]byte, signatureLen)
	for i := range sig {
		sig[i] = byte(i*7 + 1)
	}
	chunks := Pack(sig)
	if len(chunks) != 145 {
		t.Fatalf("Pack gave %d chunks, want 145", len(chunks))
	}
	last := chunks[144]
	if !bytes.Equal(last[:19], sig[4608:]) || !bytes.Equal(last[19:], make([]byte, 13)) {
		t.Fatalf("last chunk = %x, want 19 data bytes and 13 zero bytes", last)
	}

	got := mustByteVectorRoot(t, sig)
	if want := explicitMerkleize(chunks, 256); got != want {
		t.Fatalf("root = %x, want the 256-leaf tree %x", got, want)
	}
	// The usual mistakes give different roots.
	mistakes := map[string][32]byte{
		"512 leaves":         explicitMerkleize(chunks, 512),
		"length mixed in":    MixInLength(explicitMerkleize(chunks, 256), signatureLen),
		"list limit 4627":    explicitMerkleize(chunks, 8192),
		"last chunk dropped": explicitMerkleize(chunks[:144], 256),
	}
	for name, wrong := range mistakes {
		if got == wrong {
			t.Errorf("root equals the %s variant", name)
		}
	}
}

func TestByteVectorRootRejectsEmpty(t *testing.T) {
	if _, err := ByteVectorRoot(nil); !errors.Is(err, ErrEmptyVector) {
		t.Fatalf("err = %v, want ErrEmptyVector", err)
	}
}

// Bitlist[32] has a chunk limit of (32+255)/256 = 1, so every valid value
// hashes as sha256(chunk ‖ uint256_le(bit length)) with no tree above the
// chunk.
func TestBitlist32ChunkLimit(t *testing.T) {
	for n := 0; n <= 32; n++ {
		// n set bits followed by the delimiter at bit n.
		ser := make([]byte, n/8+1)
		for i := 0; i < n; i++ {
			ser[i/8] |= 1 << (i % 8)
		}
		ser[n/8] |= 1 << (n % 8)

		var chunk [32]byte
		for i := 0; i < n; i++ {
			chunk[i/8] |= 1 << (i % 8)
		}
		var length [32]byte
		binary.LittleEndian.PutUint64(length[:8], uint64(n))
		want := sha256.Sum256(append(chunk[:], length[:]...))

		got, err := BitlistRoot(ser, 32)
		if err != nil {
			t.Fatalf("%d bits: %v", n, err)
		}
		if got != want {
			t.Fatalf("%d bits (%x): root = %x, want %x", n, ser, got, want)
		}
	}

	// A larger limit with the same bits changes the tree: Bitlist[257] has
	// two chunks of capacity, so one extra level.
	ser := []byte{0xff, 0x01}
	r32, _ := BitlistRoot(ser, 32)
	r256, _ := BitlistRoot(ser, 256)
	r257, _ := BitlistRoot(ser, 257)
	if r32 != r256 {
		t.Errorf("Bitlist[32] and Bitlist[256] roots differ for the same bits")
	}
	if r32 == r257 {
		t.Errorf("Bitlist[257] root equals Bitlist[32] root; want an extra tree level")
	}
}

func TestBitlistRootRejects(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty input", nil, ErrBitlistDelimiter},
		{"last byte zero", []byte{0xff, 0x00}, ErrBitlistDelimiter},
		{"single zero byte", []byte{0x00}, ErrBitlistDelimiter},
		{"33 bits", []byte{0xff, 0xff, 0xff, 0xff, 0x03}, ErrLimit},
		{"6 bytes", []byte{0, 0, 0, 0, 0, 0x01}, ErrLimit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := BitlistRoot(tt.in, 32); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestBitlistRootIgnoresTrailingZeroBits(t *testing.T) {
	// 0x0100 is not a valid bitlist; 0x0001 is 8 zero bits. Its root is the
	// zero chunk mixed with length 8, not with 0.
	got, err := BitlistRoot([]byte{0x00, 0x01}, 32)
	if err != nil {
		t.Fatal(err)
	}
	if want := MixInLength([32]byte{}, 8); got != want {
		t.Fatalf("root = %x, want %x", got, want)
	}
}

func TestBitvectorRoot(t *testing.T) {
	// Bitvector[12]: two bytes, the top four bits of the second must be zero.
	if _, err := BitvectorRoot([]byte{0xff, 0x0f}, 12); err != nil {
		t.Fatalf("valid Bitvector[12]: %v", err)
	}
	// Bitvector[512] spans two chunks.
	b := bytes.Repeat([]byte{0xab}, 64)
	got, err := BitvectorRoot(b, 512)
	if err != nil {
		t.Fatal(err)
	}
	if want := explicitMerkleize(Pack(b), 2); got != want {
		t.Fatalf("Bitvector[512] root = %x, want %x", got, want)
	}

	tests := []struct {
		name string
		in   []byte
		n    uint64
		want error
	}{
		{"zero length", nil, 0, ErrEmptyVector},
		{"one byte short", []byte{0x05}, 16, ErrBitvectorLength},
		{"one byte long", []byte{0x05, 0, 0}, 16, ErrBitvectorLength},
		{"mainnet length for minimal", make([]byte, 16), 16, ErrBitvectorLength},
		{"padding bit set", []byte{0xff, 0x1f}, 12, ErrBitvectorPadding},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := BitvectorRoot(tt.in, tt.n); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestListRoot(t *testing.T) {
	sig := make([]byte, signatureLen)
	sig[0] = 1
	el := mustByteVectorRoot(t, sig)

	roots := make([][32]byte, 3)
	for i := range roots {
		roots[i] = el
	}
	got, err := ListRoot(roots, 32)
	if err != nil {
		t.Fatal(err)
	}
	if want := MixInLength(explicitMerkleize(roots, 32), 3); got != want {
		t.Fatalf("ListRoot = %x, want %x", got, want)
	}

	if _, err := ListRoot(make([][32]byte, 33), 32); !errors.Is(err, ErrLimit) {
		t.Fatalf("33 elements, limit 32: err = %v, want ErrLimit", err)
	}
	if _, err := ListRoot(make([][32]byte, 129), 128); !errors.Is(err, ErrLimit) {
		t.Fatalf("129 elements, limit 128: err = %v, want ErrLimit", err)
	}
}

func TestChunkLimitForBits(t *testing.T) {
	tests := []struct{ n, want uint64 }{
		{0, 0}, {1, 1}, {16, 1}, {32, 1}, {128, 1}, {256, 1}, {257, 2}, {2048, 8},
		{^uint64(0), ^uint64(0)/256 + 1},
	}
	for _, tt := range tests {
		if got := chunkLimitForBits(tt.n); got != tt.want {
			t.Errorf("chunkLimitForBits(%d) = %d, want %d", tt.n, got, tt.want)
		}
	}
}

func FuzzBitlistRoot(f *testing.F) {
	for _, seed := range [][]byte{{0x01}, {0x14}, {0xff, 0xff, 0xff, 0xff, 0x01}, {0x00}, {}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := BitlistRoot(b, 32)
		if err != nil {
			return
		}
		// Reference: unpack every bit, drop the delimiter, repack.
		bits := make([]bool, 0, len(b)*8)
		for i := 0; i < len(b)*8; i++ {
			bits = append(bits, b[i/8]>>(i%8)&1 == 1)
		}
		for len(bits) > 0 && !bits[len(bits)-1] {
			bits = bits[:len(bits)-1]
		}
		bits = bits[:len(bits)-1]
		var chunk [32]byte
		for i, set := range bits {
			if set {
				chunk[i/8] |= 1 << (i % 8)
			}
		}
		if want := MixInLength(chunk, uint64(len(bits))); got != want {
			t.Fatalf("BitlistRoot(%x) = %x, want %x", b, got, want)
		}
	})
}

func FuzzMerkleize(f *testing.F) {
	f.Add([]byte{}, uint16(0))
	f.Add(bytes.Repeat([]byte{1}, 100), uint16(4))
	f.Fuzz(func(t *testing.T, data []byte, extra uint16) {
		if len(data) > 1<<12 {
			return
		}
		chunks := Pack(data)
		limit := len(chunks) + int(extra%300)
		got, err := MerkleizeWithLimit(chunks, uint64(limit))
		if err != nil {
			t.Fatal(err)
		}
		if want := explicitMerkleize(chunks, nextPowOfTwo(limit)); got != want {
			t.Fatalf("MerkleizeWithLimit(%d chunks, %d) = %x, want %x", len(chunks), limit, got, want)
		}
	})
}
