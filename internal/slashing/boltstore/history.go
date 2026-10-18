// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package boltstore

import (
	"bytes"
	"context"
	"slices"

	bolt "go.etcd.io/bbolt"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// UpdateHistory runs fn for each of ids in one bbolt transaction, so a batch of validators costs one fsync. It
// holds the block and attestation locks of every validator in ids, in KeyID order.
func (s *Store) UpdateHistory(ctx context.Context, ids []slashing.KeyID, fn func(slashing.KeyID, slashing.HistoryTx) error) error {
	unlock := s.lockHistories(ids)
	defer unlock()
	return s.update(ctx, func(tx *bolt.Tx) error {
		buckets := make([]*bolt.Bucket, len(ids))
		for i, id := range ids {
			b, err := validatorBucket(tx, id)
			if err != nil {
				return err
			}
			buckets[i] = b
		}
		for i, id := range ids {
			if err := fn(id, newHistoryTx(tx, buckets[i])); err != nil {
				return err
			}
		}
		return nil
	})
}

// lockHistories takes the block and attestation locks of each distinct validator in ids, in KeyID order, and
// returns the function that releases them.
func (s *Store) lockHistories(ids []slashing.KeyID) func() {
	sorted := slices.Clone(ids)
	slices.SortFunc(sorted, func(a, b slashing.KeyID) int { return bytes.Compare(a[:], b[:]) })
	sorted = slices.Compact(sorted)
	locks := make([]*validatorLocks, len(sorted))
	for i, id := range sorted {
		locks[i] = s.lockFor(id)
		locks[i].block.Lock()
		locks[i].attestation.Lock()
	}
	return func() {
		for _, l := range slices.Backward(locks) {
			l.attestation.Unlock()
			l.block.Unlock()
		}
	}
}

// ViewHistory runs fn in one read-only bbolt transaction: a consistent snapshot that no writer blocks.
func (s *Store) ViewHistory(ctx context.Context, fn func(slashing.HistoryView) error) error {
	return s.view(ctx, func(tx *bolt.Tx) error { return fn(historyView{tx}) })
}

// historyView reads a read-only transaction. Every value it hands out is copied out of the transaction.
type historyView struct{ tx *bolt.Tx }

var _ slashing.HistoryView = historyView{}

func (v historyView) GenesisValidatorsRoot() (slashing.Root, bool, error) {
	return genesisValidatorsRoot(v.tx)
}

func (v historyView) Validators(fn func(slashing.KeyID, []byte) error) error {
	vs := v.tx.Bucket(bucketValidators)
	return vs.ForEachBucket(func(k []byte) error {
		if len(k) != len(slashing.KeyID{}) {
			return corrupt("validator id", k)
		}
		pk := vs.Bucket(k).Get(keyPublicKey)
		if len(pk) != slashing.PublicKeyLength {
			return corrupt("public key", pk)
		}
		return fn(slashing.KeyID(k), bytes.Clone(pk))
	})
}

func (v historyView) LowWatermark(id slashing.KeyID) (slashing.LowWatermark, error) {
	b, err := validatorBucket(v.tx, id)
	if err != nil {
		return slashing.LowWatermark{}, err
	}
	return decodeLowWatermark(b.Get(keyLowWatermark))
}

func (v historyView) Blocks(id slashing.KeyID, fn func(slashing.SignedBlock) error) error {
	b, err := validatorBucket(v.tx, id)
	if err != nil {
		return err
	}
	return b.Bucket(bucketBlocks).ForEach(func(k, val []byte) error {
		blk, _, err := decodeBlockEntry(k, val)
		if err != nil {
			return err
		}
		return fn(blk)
	})
}

func (v historyView) Attestations(id slashing.KeyID, fn func(slashing.SignedAttestation) error) error {
	b, err := validatorBucket(v.tx, id)
	if err != nil {
		return err
	}
	return b.Bucket(bucketAtts).ForEach(func(k, val []byte) error {
		a, err := decodeAttestation(k, val)
		if err != nil {
			return err
		}
		return fn(a)
	})
}
