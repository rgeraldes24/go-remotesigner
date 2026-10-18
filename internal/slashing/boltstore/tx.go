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

func (t *blockTx) LastBlock() (slashing.SignedBlock, bool, error) {
	k, v := t.blocks().Cursor().Last()
	return decodeBlockEntry(k, v)
}

func (t *blockTx) NearestBlock(slot uint64) (slashing.SignedBlock, bool, error) {
	k, v := t.blocks().Cursor().Seek(u64(slot))
	return decodeBlockEntry(k, v)
}

func (t *blockTx) PruneBlocks() (int, error) {
	low, err := t.LowWatermark()
	if err != nil || low.Slot == nil {
		return 0, err
	}
	return deleteBelow(t.blocks(), u64(*low.Slot))
}

// decodeBlockEntry decodes a cursor position of the blocks bucket; a nil key means no block.
func decodeBlockEntry(k, v []byte) (slashing.SignedBlock, bool, error) {
	if k == nil {
		return slashing.SignedBlock{}, false, nil
	}
	slot, err := decodeU64("block slot", k)
	if err != nil {
		return slashing.SignedBlock{}, false, err
	}
	root, err := decodeRoot("block root", v)
	if err != nil {
		return slashing.SignedBlock{}, false, err
	}
	return slashing.SignedBlock{Slot: slot, SigningRoot: root}, true, nil
}

// deleteBelow deletes the keys of b that sort below bound. The keys are collected first: deleting under a
// cursor that keeps moving can skip entries.
func deleteBelow(b *bolt.Bucket, bound []byte) (int, error) {
	var keys [][]byte
	c := b.Cursor()
	for k, _ := c.First(); k != nil && bytes.Compare(k, bound) < 0; k, _ = c.Next() {
		keys = append(keys, bytes.Clone(k))
	}
	for _, k := range keys {
		if err := b.Delete(k); err != nil {
			return 0, err
		}
	}
	return len(keys), nil
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

func (t *attestationTx) LastAttestation() (slashing.SignedAttestation, bool, error) {
	k, v := t.atts().Cursor().Last()
	return decodeAttestationEntry(k, v)
}

func (t *attestationTx) NearestAttestation(target uint64) (slashing.SignedAttestation, bool, error) {
	k, v := t.atts().Cursor().Seek(u64(target))
	return decodeAttestationEntry(k, v)
}

func (t *attestationTx) PruneAttestations() (int, error) {
	low, err := t.LowWatermark()
	if err != nil || low.TargetEpoch == nil {
		return 0, err
	}
	return deleteBelow(t.atts(), u64(*low.TargetEpoch))
}

// decodeAttestationEntry decodes a cursor position of the attestations bucket; a nil key means no attestation.
func decodeAttestationEntry(k, v []byte) (slashing.SignedAttestation, bool, error) {
	if k == nil {
		return slashing.SignedAttestation{}, false, nil
	}
	a, err := decodeAttestation(k, v)
	return a, err == nil, err
}

// historyTx is one validator's block and attestation view of a read-write transaction of UpdateHistory.
type historyTx struct {
	*blockTx
	*attestationTx
}

var _ slashing.HistoryTx = historyTx{}

func newHistoryTx(tx *bolt.Tx, b *bolt.Bucket) historyTx {
	v := validatorTx{tx: tx, b: b}
	return historyTx{&blockTx{v}, &attestationTx{v}}
}

func (t historyTx) Enabled() (bool, error) { return t.blockTx.Enabled() }

func (t historyTx) HighWatermark() (slashing.HighWatermark, error) { return t.blockTx.HighWatermark() }

func (t historyTx) LowWatermark() (slashing.LowWatermark, error) { return t.blockTx.LowWatermark() }

func (t historyTx) SetEnabled(enabled bool) error {
	return t.blockTx.b.Put(keyEnabled, encodeBool(enabled))
}
