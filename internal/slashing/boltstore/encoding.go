// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package boltstore

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// File layout (schema version 1). Integers are big-endian, so that bbolt's byte order is numeric order.
//
//	meta/
//	  schema_version           uint32
//	  genesis_validators_root  [32]byte, absent until pinned
//	  high_watermark           flags(1) epoch(8) slot(8), absent when none is set
//	v/<sha256(pk)>/
//	  pk                       [2592]byte
//	  enabled                  0 disabled on purpose, 1 enabled, 2 disabled by an import
//	  wm                       flags(1) slot(8) source(8) target(8), absent when none is set
//	  randao                   m(8) R(32) last(8), absent when no frontier is stored
//	  blocks/  slot(8)   → root
//	  atts/    target(8) → source(8) root
//
// A root is encoded as 0 (unknown root) or 1 followed by its 32 bytes.
var (
	bucketMeta       = []byte("meta")
	bucketValidators = []byte("v")
	bucketBlocks     = []byte("blocks")
	bucketAtts       = []byte("atts")

	keySchemaVersion = []byte("schema_version")
	keyGVR           = []byte("genesis_validators_root")
	keyHighWatermark = []byte("high_watermark")
	keyPublicKey     = []byte("pk")
	keyEnabled       = []byte("enabled")
	keyLowWatermark  = []byte("wm")
	keyRandao        = []byte("randao")
)

// ErrCorrupt reports a value in the file that this build cannot decode.
var ErrCorrupt = errors.New("boltstore: corrupt slashing-protection store")

func corrupt(what string, v []byte) error {
	return fmt.Errorf("%w: %s has %d bytes", ErrCorrupt, what, len(v))
}

func u64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }

func encodeVersion(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

func decodeVersion(b []byte) (uint32, error) {
	if len(b) != 4 {
		return 0, corrupt("schema_version", b)
	}
	return binary.BigEndian.Uint32(b), nil
}

func decodeU64(what string, b []byte) (uint64, error) {
	if len(b) != 8 {
		return 0, corrupt(what, b)
	}
	return binary.BigEndian.Uint64(b), nil
}

func decodeRoot32(what string, b []byte) (slashing.Root, error) {
	var r slashing.Root
	if len(b) != len(r) {
		return r, corrupt(what, b)
	}
	copy(r[:], b)
	return r, nil
}

func appendRoot(dst []byte, r *slashing.Root) []byte {
	if r == nil {
		return append(dst, 0)
	}
	return append(append(dst, 1), r[:]...)
}

func decodeRoot(what string, b []byte) (*slashing.Root, error) {
	switch {
	case len(b) == 1 && b[0] == 0:
		return nil, nil
	case len(b) == 33 && b[0] == 1:
		var r slashing.Root
		copy(r[:], b[1:])
		return &r, nil
	}
	return nil, corrupt(what, b)
}

// The values of a validator's enabled key.
const (
	stateDisabled byte = iota // disabled on purpose: keymanager DELETE, disable-validator
	stateEnabled
	stateDisabledByImport // registered by an import before its history, or its element failed to import
)

func encodeState(state byte) []byte { return []byte{state} }

func encodeEnabled(enabled bool) []byte {
	if enabled {
		return encodeState(stateEnabled)
	}
	return encodeState(stateDisabled)
}

func decodeState(b []byte) (byte, error) {
	if len(b) != 1 || b[0] > stateDisabledByImport {
		return 0, corrupt("enabled", b)
	}
	return b[0], nil
}

func encodeAttestation(a slashing.SignedAttestation) []byte {
	return appendRoot(u64(a.SourceEpoch), a.SigningRoot)
}

func decodeAttestation(k, v []byte) (slashing.SignedAttestation, error) {
	target, err := decodeU64("attestation target", k)
	if err != nil {
		return slashing.SignedAttestation{}, err
	}
	if len(v) < 8 {
		return slashing.SignedAttestation{}, corrupt("attestation", v)
	}
	root, err := decodeRoot("attestation root", v[8:])
	if err != nil {
		return slashing.SignedAttestation{}, err
	}
	return slashing.SignedAttestation{SourceEpoch: binary.BigEndian.Uint64(v), TargetEpoch: target, SigningRoot: root}, nil
}

// Flags of the watermark records: which optional fields are set.
const (
	flagLowSlot    = 1 << 0
	flagLowEpochs  = 1 << 1
	flagHighEpoch  = 1 << 0
	flagHighSlot   = 1 << 1
	knownFlagsMask = 1<<0 | 1<<1
)

// field returns the uint64 at off when flag is set in flags, and nil otherwise.
func field(b []byte, flags, flag byte, off int) *uint64 {
	if flags&flag == 0 {
		return nil
	}
	v := binary.BigEndian.Uint64(b[off:])
	return &v
}

func encodeLowWatermark(w slashing.LowWatermark) []byte {
	var (
		flags                byte
		slot, source, target uint64
	)
	if w.Slot != nil {
		flags |= flagLowSlot
		slot = *w.Slot
	}
	if w.SourceEpoch != nil && w.TargetEpoch != nil {
		flags |= flagLowEpochs
		source, target = *w.SourceEpoch, *w.TargetEpoch
	}
	b := append(make([]byte, 0, 25), flags)
	b = binary.BigEndian.AppendUint64(b, slot)
	b = binary.BigEndian.AppendUint64(b, source)
	return binary.BigEndian.AppendUint64(b, target)
}

func decodeLowWatermark(b []byte) (slashing.LowWatermark, error) {
	if b == nil {
		return slashing.LowWatermark{}, nil
	}
	if len(b) != 25 || b[0]&^knownFlagsMask != 0 {
		return slashing.LowWatermark{}, corrupt("low watermark", b)
	}
	return slashing.LowWatermark{
		Slot:        field(b, b[0], flagLowSlot, 1),
		SourceEpoch: field(b, b[0], flagLowEpochs, 9),
		TargetEpoch: field(b, b[0], flagLowEpochs, 17),
	}, nil
}

func encodeHighWatermark(h slashing.HighWatermark) []byte {
	var (
		flags       byte
		epoch, slot uint64
	)
	if h.Epoch != nil {
		flags |= flagHighEpoch
		epoch = *h.Epoch
	}
	if h.Slot != nil {
		flags |= flagHighSlot
		slot = *h.Slot
	}
	b := append(make([]byte, 0, 17), flags)
	b = binary.BigEndian.AppendUint64(b, epoch)
	return binary.BigEndian.AppendUint64(b, slot)
}

func decodeHighWatermark(b []byte) (slashing.HighWatermark, error) {
	if b == nil {
		return slashing.HighWatermark{}, nil
	}
	if len(b) != 17 || b[0]&^knownFlagsMask != 0 {
		return slashing.HighWatermark{}, corrupt("high watermark", b)
	}
	h := slashing.HighWatermark{Epoch: field(b, b[0], flagHighEpoch, 1), Slot: field(b, b[0], flagHighSlot, 9)}
	if err := h.Validate(); err != nil {
		return slashing.HighWatermark{}, fmt.Errorf("%w: high watermark: %w", ErrCorrupt, err)
	}
	return h, nil
}

func encodeRandao(s slashing.RandaoState) []byte {
	b := make([]byte, 0, 48)
	b = binary.BigEndian.AppendUint64(b, s.Index)
	b = append(b, s.Reveal[:]...)
	return binary.BigEndian.AppendUint64(b, s.LastSlot)
}

func decodeRandao(b []byte) (slashing.RandaoState, error) {
	if len(b) != 48 {
		return slashing.RandaoState{}, corrupt("randao state", b)
	}
	s := slashing.RandaoState{Index: binary.BigEndian.Uint64(b), LastSlot: binary.BigEndian.Uint64(b[40:])}
	copy(s.Reveal[:], b[8:40])
	return s, nil
}
