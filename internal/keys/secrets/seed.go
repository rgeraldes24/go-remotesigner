// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
)

// Mode is the signer mode a seed is for. The two modes take different
// formats, so that a key of one mode can never be configured in the other
// (consensus and execution share a signing context).
type Mode uint8

const (
	// Consensus takes the validator's 48-byte wallet seed.
	Consensus Mode = iota
	// Execution takes the 51-byte extended seed: the descriptor 01 00 00
	// followed by the 48-byte seed.
	Execution
)

// Seed sizes.
const (
	SeedSize         = mldsa87.SeedSize // 48
	ExtendedSeedSize = 3 + SeedSize     // 51: descriptor ‖ seed
	xiSize           = 32               // FIPS 204 ξ, or a BLS key
	expandedKeySize  = 4896             // an expanded ML-DSA-87 secret key
)

// descriptor is the only valid descriptor of an extended seed: ML-DSA-87.
var descriptor = [3]byte{0x01, 0x00, 0x00}

// ErrSeed is the error of a value that is not a seed of the mode. Its
// messages never quote the value.
var ErrSeed = errors.New("invalid seed")

// ParseSeed decodes one seed written as hex, with or without 0x, and with
// surrounding ASCII whitespace (a trailing line feed, for one) ignored. It
// returns a new buffer of SeedSize bytes for Consensus and ExtendedSeedSize
// bytes for Execution, which the caller wipes with mldsa87.Wipe. A value of
// another mode's length, a 32-byte ξ or BLS key and a 4,896-byte expanded
// secret key are refused with a hint; an extended seed must carry the
// ML-DSA-87 descriptor 01 00 00.
func ParseSeed(value []byte, mode Mode) ([]byte, error) {
	h := bytes.TrimSpace(value)
	h = bytes.TrimPrefix(h, []byte("0x"))
	want := SeedSize
	if mode == Execution {
		want = ExtendedSeedSize
	}
	if len(h) != 2*want {
		return nil, lengthError(len(h), mode)
	}
	out := make([]byte, want)
	if _, err := hex.Decode(out, h); err != nil {
		mldsa87.Wipe(out)
		return nil, fmt.Errorf("%w: not hex", ErrSeed)
	}
	if mode == Execution && [3]byte(out[:3]) != descriptor {
		mldsa87.Wipe(out)
		return nil, fmt.Errorf("%w: the descriptor (first 3 bytes) of an extended seed must be 01 00 00 (ML-DSA-87)",
			ErrSeed)
	}
	return out, nil
}

// lengthError explains a value of n hex characters that is not a seed of
// mode.
func lengthError(n int, mode Mode) error {
	switch {
	case n == 2*xiSize:
		return fmt.Errorf("%w: 32 bytes; a QRL key is configured as the validator's 48-byte wallet seed%s", ErrSeed,
			executionSuffix(mode))
	case n == 2*ExtendedSeedSize && mode == Consensus:
		return fmt.Errorf("%w: a 51-byte extended seed belongs to execution mode; consensus keys are the 48-byte "+
			"wallet seed", ErrSeed)
	case n == 2*SeedSize && mode == Execution:
		return fmt.Errorf("%w: a 48-byte seed belongs to consensus mode; execution keys are the 51-byte extended "+
			"seed (descriptor 01 00 00, then the seed)", ErrSeed)
	case n == 2*expandedKeySize:
		return fmt.Errorf("%w: a 4,896-byte ML-DSA-87 secret key is not accepted; configure the seed it was derived "+
			"from", ErrSeed)
	case mode == Execution:
		return fmt.Errorf("%w: want a 51-byte extended seed, 0x + 102 hex characters", ErrSeed)
	default:
		return fmt.Errorf("%w: want a 48-byte seed, 0x + 96 hex characters", ErrSeed)
	}
}

func executionSuffix(mode Mode) string {
	if mode == Execution {
		return " (with the descriptor 01 00 00 in front in execution mode)"
	}
	return ""
}

// ConsensusSeed decodes one consensus seed (see ParseSeed). The caller
// wipes the result.
func ConsensusSeed(value []byte) (*[SeedSize]byte, error) {
	b, err := ParseSeed(value, Consensus)
	if err != nil {
		return nil, err
	}
	return (*[SeedSize]byte)(b), nil
}

// ParseSeeds decodes a secret that holds one seed per line, the bulk
// loaders' format: lines end in \n or \r\n, and blank lines are skipped. A
// secret with no seed fails, and so does one bad line, which the error
// names by its 1-based number. The caller wipes every result.
func ParseSeeds(value []byte, mode Mode) ([][]byte, error) {
	var out [][]byte
	for i, line := range bytes.Split(value, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		s, err := ParseSeed(line, mode)
		if err != nil {
			WipeAll(out)
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: the secret holds no seed", ErrSeed)
	}
	return out, nil
}

// WipeAll wipes every buffer of bs.
func WipeAll(bs [][]byte) {
	for _, b := range bs {
		mldsa87.Wipe(b)
	}
}

// Keys derives the consensus keys of a secret's value: one seed when one
// is set, else one seed per line. It wipes the seeds it decoded, but not
// value. Either every key is built or none is.
func Keys(value []byte, one bool) ([]*mldsa87.Key, error) {
	var seeds [][]byte
	if one {
		s, err := ParseSeed(value, Consensus)
		if err != nil {
			return nil, err
		}
		seeds = [][]byte{s}
	} else {
		var err error
		if seeds, err = ParseSeeds(value, Consensus); err != nil {
			return nil, err
		}
	}
	defer WipeAll(seeds)
	keys := make([]*mldsa87.Key, 0, len(seeds))
	for i, s := range seeds {
		k, err := mldsa87.FromSeed48((*[SeedSize]byte)(s))
		if err != nil {
			for _, k := range keys {
				k.Zeroize()
			}
			if one {
				return nil, fmt.Errorf("%w: %v", ErrSeed, err)
			}
			return nil, fmt.Errorf("seed %d: %w: %v", i+1, ErrSeed, err)
		}
		keys = append(keys, k)
	}
	return keys, nil
}
