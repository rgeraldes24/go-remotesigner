// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/binary"
)

// streamTag prefixes every block of the seed stream. testdata/vectors/README.md
// ("Seed expansion") specifies the stream, so the signer's tests can rebuild
// the random containers from their seeds without sharing code with this tool.
const streamTag = "qrl-remotesigner-vectors-v1"

// stream is the byte stream of one seed:
//
//	SHA-256(tag ‖ le64(seed) ‖ le64(0)) ‖ SHA-256(tag ‖ le64(seed) ‖ le64(1)) ‖ …
type stream struct {
	seed    uint64
	counter uint64
	buf     []byte
}

func newStream(seed uint64) *stream { return &stream{seed: seed} }

func (s *stream) refill() {
	var in [len(streamTag) + 16]byte
	copy(in[:], streamTag)
	binary.LittleEndian.PutUint64(in[len(streamTag):], s.seed)
	binary.LittleEndian.PutUint64(in[len(streamTag)+8:], s.counter)
	s.counter++
	h := sha256.Sum256(in[:])
	s.buf = append(s.buf, h[:]...)
}

// bytes returns the next n bytes.
func (s *stream) bytes(n int) []byte {
	for len(s.buf) < n {
		s.refill()
	}
	out := make([]byte, n)
	copy(out, s.buf)
	s.buf = s.buf[n:]
	return out
}

// u64 returns the next 8 bytes as a little-endian uint64.
func (s *stream) u64() uint64 { return binary.LittleEndian.Uint64(s.bytes(8)) }

// byte1 returns the next byte.
func (s *stream) byte1() byte { return s.bytes(1)[0] }

// bit returns the low bit of the next byte.
func (s *stream) bit() bool { return s.byte1()&1 == 1 }

// bitlist32 draws an SSZ Bitlist[32]: a length n = byte mod 33, then n bits,
// serialized with the delimiter bit at position n.
func (s *stream) bitlist32() []byte {
	n := int(s.byte1()) % 33
	out := make([]byte, n/8+1)
	for i := range n {
		if s.bit() {
			out[i/8] |= 1 << (i % 8)
		}
	}
	out[n/8] |= 1 << (n % 8)
	return out
}

// bitvector draws an SSZ Bitvector of n bits (n a multiple of 8), one stream
// byte per bit.
func (s *stream) bitvector(n int) []byte {
	out := make([]byte, n/8)
	for i := range n {
		if s.bit() {
			out[i/8] |= 1 << (i % 8)
		}
	}
	return out
}

// fill returns n deterministic filler bytes named by label, for the byte
// fields of the curated cases (signatures inside aggregates, roots). The
// values are data in the fixtures; consumers never recompute them.
func fill(label string, n int) []byte {
	out := make([]byte, 0, n+sha256.Size)
	for i := uint64(0); len(out) < n; i++ {
		var ctr [8]byte
		binary.LittleEndian.PutUint64(ctr[:], i)
		h := sha256.Sum256(append([]byte("qrl-remotesigner-fill:"+label+":"), ctr[:]...))
		out = append(out, h[:]...)
	}
	return out[:n]
}

// fill32 is fill for a 32-byte root.
func fill32(label string) []byte { return fill(label, 32) }

// popcount counts the set bits of b.
func popcount(b []byte) int {
	n := 0
	for _, c := range b {
		for ; c != 0; c &= c - 1 {
			n++
		}
	}
	return n
}
