// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package slashingtest is the backend-agnostic conformance suite for slashing.Store implementations. Every
// backend's tests call Run with a factory for empty stores:
//
//	func TestConformance(t *testing.T) {
//		slashingtest.Run(t, func(t *testing.T) slashing.Store { return memstore.New() })
//	}
//
// RunEIP3076 and RunStress drive the stores through slashing.Engine with 2,592-byte keys, so they check the rule
// engine and the store together. RunStoreContract and RunRandao call the Store and transaction methods directly and
// pin down the contract a backend must meet on its own. A new backend needs only a Factory: every call must return an
// independent, empty store, and the suite never runs two tests at once.
package slashingtest

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strconv"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// Factory returns an empty, open store. The suite closes it when the test ends.
type Factory func(t *testing.T) slashing.Store

// Run runs the whole conformance suite against stores from newStore.
func Run(t *testing.T, newStore Factory) {
	t.Run("EIP3076", func(t *testing.T) { RunEIP3076(t, newStore) })
	t.Run("StoreContract", func(t *testing.T) { RunStoreContract(t, newStore) })
	t.Run("Randao", func(t *testing.T) { RunRandao(t, newStore) })
	t.Run("Schema", func(t *testing.T) { RunSchema(t, newStore) })
	t.Run("Stress", func(t *testing.T) { RunStress(t, newStore) })
}

// RunSchema checks that a new store reports the current schema version.
func RunSchema(t *testing.T, newStore Factory) {
	s := open(t, newStore)
	if err := slashing.CheckSchema(context.Background(), s); err != nil {
		t.Fatalf("CheckSchema on a new store: %v", err)
	}
}

// GVR is the genesis validators root the suite signs under.
var GVR = slashing.Root(sha256.Sum256([]byte("go-remotesigner slashingtest genesis validators root")))

// Key returns the i-th deterministic test public key: PublicKeyLength bytes of SHA-256 in counter mode. The
// stores treat keys as opaque bytes, so the keys need not be valid ML-DSA-87 keys.
func Key(i int) []byte {
	key := make([]byte, 0, slashing.PublicKeyLength+sha256.Size)
	var block [16]byte
	binary.BigEndian.PutUint64(block[:8], uint64(i))
	for ctr := uint64(0); len(key) < slashing.PublicKeyLength; ctr++ {
		binary.BigEndian.PutUint64(block[8:], ctr)
		sum := sha256.Sum256(append([]byte("go-remotesigner slashingtest key"), block[:]...))
		key = append(key, sum[:]...)
	}
	return key[:slashing.PublicKeyLength]
}

// RootOf returns a signing root whose last eight bytes hold n, big-endian, with a non-zero first byte so that no
// root equals the zero root.
func RootOf(n uint64) slashing.Root {
	var r slashing.Root
	r[0] = 0xa5
	binary.BigEndian.PutUint64(r[24:], n)
	return r
}

// U64 returns a pointer to v.
func U64(v uint64) *uint64 { return &v }

// RootPtr returns a pointer to RootOf(n).
func RootPtr(n uint64) *slashing.Root {
	r := RootOf(n)
	return &r
}

// open returns a store from newStore that is closed when the test ends.
func open(t *testing.T, newStore Factory) slashing.Store {
	t.Helper()
	s := newStore(t)
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

// openWithKeys returns a store with keys 0..n-1 registered.
func openWithKeys(t *testing.T, newStore Factory, n int) slashing.Store {
	t.Helper()
	s := open(t, newStore)
	register(t, s, n)
	return s
}

func register(t *testing.T, s slashing.Store, n int) {
	t.Helper()
	keys := make([][]byte, n)
	for i := range keys {
		keys[i] = Key(i)
	}
	must(t, s.RegisterValidators(context.Background(), keys))
}

// id returns the KeyID of Key(i).
func id(i int) slashing.KeyID { return slashing.KeyIDOf(Key(i)) }

// ImportBlocks writes blocks to a validator's history and raises its low-watermark slot to their minimum slot,
// which is what an EIP-3076 import does.
func ImportBlocks(ctx context.Context, s slashing.Store, key slashing.KeyID, blocks ...slashing.SignedBlock) error {
	return s.UpdateBlocks(ctx, key, func(tx slashing.BlockTx) error {
		if len(blocks) == 0 {
			return nil
		}
		minSlot := blocks[0].Slot
		for _, b := range blocks {
			if err := tx.InsertBlock(b); err != nil {
				return err
			}
			minSlot = min(minSlot, b.Slot)
		}
		return tx.RaiseSlotLowWatermark(minSlot)
	})
}

// ImportAttestations writes attestations to a validator's history and raises each low-watermark epoch independently
// to the larger of its current value and the imported minimum, which is what an EIP-3076 import does.
func ImportAttestations(ctx context.Context, s slashing.Store, key slashing.KeyID, atts ...slashing.SignedAttestation) error {
	return s.UpdateAttestations(ctx, key, func(tx slashing.AttestationTx) error {
		if len(atts) == 0 {
			return nil
		}
		minSource, minTarget := atts[0].SourceEpoch, atts[0].TargetEpoch
		for _, a := range atts {
			if err := tx.InsertAttestation(a); err != nil {
				return err
			}
			minSource, minTarget = min(minSource, a.SourceEpoch), min(minTarget, a.TargetEpoch)
		}
		low, err := tx.LowWatermark()
		if err != nil {
			return err
		}
		if low.SourceEpoch != nil {
			minSource, minTarget = max(minSource, *low.SourceEpoch), max(minTarget, *low.TargetEpoch)
		}
		return tx.RaiseEpochLowWatermarks(minSource, minTarget)
	})
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func fmtLow(w slashing.LowWatermark) string {
	return fmt.Sprintf("{slot %s, source %s, target %s}", fmtU64(w.Slot), fmtU64(w.SourceEpoch), fmtU64(w.TargetEpoch))
}

func fmtHigh(h slashing.HighWatermark) string {
	return fmt.Sprintf("{epoch %s, slot %s}", fmtU64(h.Epoch), fmtU64(h.Slot))
}

func fmtU64(p *uint64) string {
	if p == nil {
		return "unset"
	}
	return strconv.FormatUint(*p, 10)
}
