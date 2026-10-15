// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package boltstore

import (
	"bytes"

	bolt "go.etcd.io/bbolt"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// validatorTx is one validator's view of a read-write bbolt transaction. Values read from bbolt are only valid
// inside the transaction, so every decoder copies them out.
type validatorTx struct {
	tx *bolt.Tx
	b  *bolt.Bucket
}

func (t *validatorTx) Enabled() (bool, error) { return decodeBool("enabled", t.b.Get(keyEnabled)) }

func (t *validatorTx) HighWatermark() (slashing.HighWatermark, error) { return highWatermark(t.tx) }

func (t *validatorTx) LowWatermark() (slashing.LowWatermark, error) {
	return decodeLowWatermark(t.b.Get(keyLowWatermark))
}

func (t *validatorTx) putLowWatermark(w slashing.LowWatermark) error {
	return t.b.Put(keyLowWatermark, encodeLowWatermark(w))
}

type blockTx struct{ validatorTx }

var _ slashing.BlockTx = (*blockTx)(nil)

func (t *blockTx) blocks() *bolt.Bucket { return t.b.Bucket(bucketBlocks) }

func (t *blockTx) BlockAt(slot uint64) (slashing.SignedBlock, bool, error) {
	v := t.blocks().Get(u64(slot))
	if v == nil {
		return slashing.SignedBlock{}, false, nil
	}
	root, err := decodeRoot("block root", v)
	if err != nil {
		return slashing.SignedBlock{}, false, err
	}
	return slashing.SignedBlock{Slot: slot, SigningRoot: root}, true, nil
}

func (t *blockTx) InsertBlock(b slashing.SignedBlock) error {
	k := u64(b.Slot)
	if t.blocks().Get(k) != nil {
		return slashing.ErrDuplicateRecord
	}
	return t.blocks().Put(k, appendRoot(nil, b.SigningRoot))
}

func (t *blockTx) RaiseSlotLowWatermark(slot uint64) error {
	high, err := t.HighWatermark()
	if err != nil {
		return err
	}
	if high.Slot != nil && slot > *high.Slot {
		return slashing.ErrWatermarkConflict
	}
	low, err := t.LowWatermark()
	if err != nil {
		return err
	}
	if low.Slot != nil && slot < *low.Slot {
		return nil
	}
	low.Slot = &slot
	return t.putLowWatermark(low)
}

type attestationTx struct{ validatorTx }

var _ slashing.AttestationTx = (*attestationTx)(nil)

func (t *attestationTx) atts() *bolt.Bucket { return t.b.Bucket(bucketAtts) }

func (t *attestationTx) AttestationAt(target uint64) (slashing.SignedAttestation, bool, error) {
	k := u64(target)
	v := t.atts().Get(k)
	if v == nil {
		return slashing.SignedAttestation{}, false, nil
	}
	a, err := decodeAttestation(k, v)
	return a, err == nil, err
}

// SurroundingAttestation walks the targets above target from the highest down, so the first match has the highest
// target epoch.
func (t *attestationTx) SurroundingAttestation(source, target uint64) (slashing.SignedAttestation, bool, error) {
	bound := u64(target)
	c := t.atts().Cursor()
	for k, v := c.Last(); k != nil && bytes.Compare(k, bound) > 0; k, v = c.Prev() {
		a, err := decodeAttestation(k, v)
		if err != nil {
			return slashing.SignedAttestation{}, false, err
		}
		if a.SourceEpoch < source {
			return a, true, nil
		}
	}
	return slashing.SignedAttestation{}, false, nil
}

// SurroundedAttestation walks the targets below target from the highest down, so the first match has the highest
// target epoch.
func (t *attestationTx) SurroundedAttestation(source, target uint64) (slashing.SignedAttestation, bool, error) {
	c := t.atts().Cursor()
	var k, v []byte
	if first, _ := c.Seek(u64(target)); first == nil { // no target at or above target
		k, v = c.Last()
	} else {
		k, v = c.Prev()
	}
	for ; k != nil; k, v = c.Prev() {
		a, err := decodeAttestation(k, v)
		if err != nil {
			return slashing.SignedAttestation{}, false, err
		}
		if a.SourceEpoch > source {
			return a, true, nil
		}
	}
	return slashing.SignedAttestation{}, false, nil
}

func (t *attestationTx) InsertAttestation(a slashing.SignedAttestation) error {
	k := u64(a.TargetEpoch)
	if t.atts().Get(k) != nil {
		return slashing.ErrDuplicateRecord
	}
	return t.atts().Put(k, encodeAttestation(a))
}

func (t *attestationTx) RaiseEpochLowWatermarks(source, target uint64) error {
	high, err := t.HighWatermark()
	if err != nil {
		return err
	}
	if high.Epoch != nil && (source > *high.Epoch || target > *high.Epoch) {
		return slashing.ErrWatermarkConflict
	}
	low, err := t.LowWatermark()
	if err != nil {
		return err
	}
	if low.SourceEpoch != nil && (source < *low.SourceEpoch || target < *low.TargetEpoch) {
		return nil
	}
	low.SourceEpoch, low.TargetEpoch = &source, &target
	return t.putLowWatermark(low)
}
