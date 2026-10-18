// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package memstore is a process-lifetime slashing.Store. The signer uses it only when slashing protection is
// disabled, which is allowed only when every listener is loopback; the RANDAO frontier rule then runs on it for the
// life of the process. It also serves as the reference backend of the conformance suite.
package memstore

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"slices"
	"sync"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// ErrClosed is returned by every method after Close.
var ErrClosed = errors.New("memstore: store is closed")

// Store is an in-memory slashing.Store, safe for concurrent use.
//
// Lock order: Store.mu, then validator.mu. Every per-validator operation holds Store.mu for reading for its whole
// duration, so SetHighWatermark, which holds it for writing, sees every low watermark at rest.
type Store struct {
	mu         sync.RWMutex
	closed     bool
	gvr        *slashing.Root
	high       slashing.HighWatermark
	validators map[slashing.KeyID]*validator
}

type validator struct {
	mu      sync.Mutex
	pubkey  []byte
	enabled bool
	blocks  map[uint64]*slashing.Root
	atts    map[uint64]slashing.SignedAttestation
	low     slashing.LowWatermark
	randao  *slashing.RandaoState
}

var _ slashing.Store = (*Store)(nil)

// New returns an empty store.
func New() *Store {
	return &Store{validators: make(map[slashing.KeyID]*validator)}
}

// SchemaVersion returns slashing.SchemaVersion: a memory store is always current.
func (s *Store) SchemaVersion(ctx context.Context) (uint32, error) {
	if err := s.read(ctx); err != nil {
		return 0, err
	}
	defer s.mu.RUnlock()
	return slashing.SchemaVersion, nil
}

// GenesisValidatorsRoot returns the pinned root, if any.
func (s *Store) GenesisValidatorsRoot(ctx context.Context) (slashing.Root, bool, error) {
	if err := s.read(ctx); err != nil {
		return slashing.Root{}, false, err
	}
	defer s.mu.RUnlock()
	if s.gvr == nil {
		return slashing.Root{}, false, nil
	}
	return *s.gvr, true, nil
}

// PinGenesisValidatorsRoot pins gvr unless a root is already pinned, and returns the pinned root.
func (s *Store) PinGenesisValidatorsRoot(ctx context.Context, gvr slashing.Root) (slashing.Root, error) {
	if err := s.write(ctx); err != nil {
		return slashing.Root{}, err
	}
	defer s.mu.Unlock()
	if s.gvr == nil {
		s.gvr = &gvr
	}
	return *s.gvr, nil
}

// HighWatermark returns the global high watermark.
func (s *Store) HighWatermark(ctx context.Context) (slashing.HighWatermark, error) {
	if err := s.read(ctx); err != nil {
		return slashing.HighWatermark{}, err
	}
	defer s.mu.RUnlock()
	return copyHigh(s.high), nil
}

// SetHighWatermark replaces the global high watermark after checking it against every low watermark.
func (s *Store) SetHighWatermark(ctx context.Context, h slashing.HighWatermark) error {
	if err := s.write(ctx); err != nil {
		return err
	}
	defer s.mu.Unlock()
	if h.IsSet() && s.gvr == nil {
		return slashing.ErrNoGenesisValidatorsRoot
	}
	for _, v := range s.validators {
		if h.Slot != nil && v.low.Slot != nil && *h.Slot <= *v.low.Slot {
			return slashing.ErrWatermarkConflict
		}
		if h.Epoch != nil && v.low.SourceEpoch != nil &&
			(*h.Epoch <= *v.low.SourceEpoch || *h.Epoch <= *v.low.TargetEpoch) {
			return slashing.ErrWatermarkConflict
		}
	}
	s.high = copyHigh(h)
	return nil
}

// RegisterValidators registers new keys as enabled and leaves known keys unchanged.
func (s *Store) RegisterValidators(ctx context.Context, pubkeys [][]byte) error {
	return s.register(ctx, pubkeys, true)
}

// RegisterValidatorsDisabled registers new keys as disabled and leaves known keys unchanged.
func (s *Store) RegisterValidatorsDisabled(ctx context.Context, pubkeys [][]byte) error {
	return s.register(ctx, pubkeys, false)
}

func (s *Store) register(ctx context.Context, pubkeys [][]byte, enabled bool) error {
	for _, pk := range pubkeys {
		if err := slashing.CheckPublicKey(pk); err != nil {
			return err
		}
	}
	if err := s.write(ctx); err != nil {
		return err
	}
	defer s.mu.Unlock()
	for _, pk := range pubkeys {
		id := slashing.KeyIDOf(pk)
		if _, ok := s.validators[id]; !ok {
			s.validators[id] = &validator{
				pubkey:  slices.Clone(pk),
				enabled: enabled,
				blocks:  make(map[uint64]*slashing.Root),
				atts:    make(map[uint64]slashing.SignedAttestation),
			}
		}
	}
	return nil
}

// ValidatorStatus returns a key's registration state.
func (s *Store) ValidatorStatus(ctx context.Context, id slashing.KeyID) (slashing.ValidatorStatus, error) {
	var st slashing.ValidatorStatus
	err := s.withValidator(ctx, id, func(v *validator) error {
		st = slashing.ValidatorStatus{Registered: true, Enabled: v.enabled}
		return nil
	})
	if errors.Is(err, slashing.ErrValidatorNotRegistered) {
		return slashing.ValidatorStatus{}, nil
	}
	return st, err
}

// SetValidatorEnabled sets a registered key's enabled flag.
func (s *Store) SetValidatorEnabled(ctx context.Context, id slashing.KeyID, enabled bool) error {
	return s.withValidator(ctx, id, func(v *validator) error {
		v.enabled = enabled
		return nil
	})
}

// UpdateBlocks runs fn in a block transaction for one validator.
func (s *Store) UpdateBlocks(ctx context.Context, id slashing.KeyID, fn func(slashing.BlockTx) error) error {
	return s.withValidator(ctx, id, func(v *validator) error {
		return runTx(&tx{s: s, v: v, j: &journal{}}, func(t *tx) error { return fn(t) })
	})
}

// UpdateAttestations runs fn in an attestation transaction for one validator.
func (s *Store) UpdateAttestations(ctx context.Context, id slashing.KeyID, fn func(slashing.AttestationTx) error) error {
	return s.withValidator(ctx, id, func(v *validator) error {
		return runTx(&tx{s: s, v: v, j: &journal{}}, func(t *tx) error { return fn(t) })
	})
}

// UpdateHistory runs fn for each of ids with one undo journal, so that an error undoes every validator's writes.
// It holds the mutex of each distinct validator, taken in KeyID order.
func (s *Store) UpdateHistory(ctx context.Context, ids []slashing.KeyID, fn func(slashing.KeyID, slashing.HistoryTx) error) error {
	if err := s.read(ctx); err != nil {
		return err
	}
	defer s.mu.RUnlock()
	vs := make([]*validator, len(ids))
	for i, id := range ids {
		v, ok := s.validators[id]
		if !ok {
			return slashing.ErrValidatorNotRegistered
		}
		vs[i] = v
	}
	for _, id := range sortedIDs(ids) {
		v := s.validators[id]
		v.mu.Lock()
		defer v.mu.Unlock()
	}
	j := &journal{}
	for i, id := range ids {
		if err := fn(id, &tx{s: s, v: vs[i], j: j}); err != nil {
			j.rollback()
			return err
		}
	}
	return nil
}

// ViewHistory runs fn with s.mu held for writing, so that no validator changes while fn reads.
func (s *Store) ViewHistory(ctx context.Context, fn func(slashing.HistoryView) error) error {
	if err := s.write(ctx); err != nil {
		return err
	}
	defer s.mu.Unlock()
	return fn(view{s})
}

// RandaoState returns the validator's RANDAO frontier, if one is stored.
func (s *Store) RandaoState(ctx context.Context, id slashing.KeyID) (slashing.RandaoState, bool, error) {
	var (
		st slashing.RandaoState
		ok bool
	)
	err := s.withValidator(ctx, id, func(v *validator) error {
		if v.randao != nil {
			st, ok = *v.randao, true
		}
		return nil
	})
	return st, ok, err
}

// CompareAndSwapRandaoState stores next if the stored frontier equals old (nil: none stored).
func (s *Store) CompareAndSwapRandaoState(ctx context.Context, id slashing.KeyID, old *slashing.RandaoState, next slashing.RandaoState) (bool, error) {
	var swapped bool
	err := s.withValidator(ctx, id, func(v *validator) error {
		if (old == nil) != (v.randao == nil) || (old != nil && *old != *v.randao) {
			return nil
		}
		v.randao = &next
		swapped = true
		return nil
	})
	return swapped, err
}

// DeleteRandaoState removes the validator's RANDAO frontier.
func (s *Store) DeleteRandaoState(ctx context.Context, id slashing.KeyID) error {
	return s.withValidator(ctx, id, func(v *validator) error {
		v.randao = nil
		return nil
	})
}

// Close discards the store's contents.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.validators = nil
	return nil
}

// read takes s.mu for reading; the caller releases it.
func (s *Store) read(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return ErrClosed
	}
	return nil
}

// write takes s.mu for writing; the caller releases it.
func (s *Store) write(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	return nil
}

// withValidator runs fn with s.mu held for reading and the validator's mutex held.
func (s *Store) withValidator(ctx context.Context, id slashing.KeyID, fn func(*validator) error) error {
	if err := s.read(ctx); err != nil {
		return err
	}
	defer s.mu.RUnlock()
	v, ok := s.validators[id]
	if !ok {
		return slashing.ErrValidatorNotRegistered
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return fn(v)
}

// tx applies writes in place and records how to undo them in its journal, so that a failed transaction leaves no
// trace. Its methods run with s.mu held for reading and v.mu held.
type tx struct {
	s *Store
	v *validator
	j *journal
}

// journal is the undo log of one transaction, which may span several validators.
type journal struct{ undo []func() }

func (j *journal) add(u func()) { j.undo = append(j.undo, u) }

func (j *journal) rollback() {
	for _, u := range slices.Backward(j.undo) {
		u()
	}
}

func runTx(t *tx, fn func(*tx) error) error {
	if err := fn(t); err != nil {
		t.j.rollback()
		return err
	}
	return nil
}

func (t *tx) Enabled() (bool, error) { return t.v.enabled, nil }

func (t *tx) HighWatermark() (slashing.HighWatermark, error) { return copyHigh(t.s.high), nil }

func (t *tx) LowWatermark() (slashing.LowWatermark, error) {
	return slashing.LowWatermark{
		Slot:        clone(t.v.low.Slot),
		SourceEpoch: clone(t.v.low.SourceEpoch),
		TargetEpoch: clone(t.v.low.TargetEpoch),
	}, nil
}

func (t *tx) BlockAt(slot uint64) (slashing.SignedBlock, bool, error) {
	root, ok := t.v.blocks[slot]
	if !ok {
		return slashing.SignedBlock{}, false, nil
	}
	return slashing.SignedBlock{Slot: slot, SigningRoot: clone(root)}, true, nil
}

func (t *tx) InsertBlock(b slashing.SignedBlock) error {
	if _, ok := t.v.blocks[b.Slot]; ok {
		return slashing.ErrDuplicateRecord
	}
	t.v.blocks[b.Slot] = clone(b.SigningRoot)
	t.j.add(func() { delete(t.v.blocks, b.Slot) })
	return nil
}

func (t *tx) RaiseSlotLowWatermark(slot uint64) error {
	if h := t.s.high.Slot; h != nil && slot > *h {
		return slashing.ErrWatermarkConflict
	}
	if cur := t.v.low.Slot; cur == nil || slot >= *cur {
		t.v.low.Slot = &slot
		t.j.add(func() { t.v.low.Slot = cur })
	}
	return nil
}

func (t *tx) AttestationAt(target uint64) (slashing.SignedAttestation, bool, error) {
	a, ok := t.v.atts[target]
	if !ok {
		return slashing.SignedAttestation{}, false, nil
	}
	a.SigningRoot = clone(a.SigningRoot)
	return a, true, nil
}

func (t *tx) SurroundingAttestation(source, target uint64) (slashing.SignedAttestation, bool, error) {
	return t.highestTarget(func(a slashing.SignedAttestation) bool {
		return a.SourceEpoch < source && a.TargetEpoch > target
	})
}

func (t *tx) SurroundedAttestation(source, target uint64) (slashing.SignedAttestation, bool, error) {
	return t.highestTarget(func(a slashing.SignedAttestation) bool {
		return a.SourceEpoch > source && a.TargetEpoch < target
	})
}

// highestTarget returns the recorded attestation with the highest target epoch among those that match.
func (t *tx) highestTarget(match func(slashing.SignedAttestation) bool) (slashing.SignedAttestation, bool, error) {
	var (
		best  slashing.SignedAttestation
		found bool
	)
	for _, a := range t.v.atts {
		if match(a) && (!found || a.TargetEpoch > best.TargetEpoch) {
			best, found = a, true
		}
	}
	best.SigningRoot = clone(best.SigningRoot)
	return best, found, nil
}

func (t *tx) InsertAttestation(a slashing.SignedAttestation) error {
	if _, ok := t.v.atts[a.TargetEpoch]; ok {
		return slashing.ErrDuplicateRecord
	}
	a.SigningRoot = clone(a.SigningRoot)
	t.v.atts[a.TargetEpoch] = a
	t.j.add(func() { delete(t.v.atts, a.TargetEpoch) })
	return nil
}

func (t *tx) RaiseEpochLowWatermarks(source, target uint64) error {
	if h := t.s.high.Epoch; h != nil && (source > *h || target > *h) {
		return slashing.ErrWatermarkConflict
	}
	curSource, curTarget := t.v.low.SourceEpoch, t.v.low.TargetEpoch
	if curSource == nil || (source >= *curSource && target >= *curTarget) {
		t.v.low.SourceEpoch, t.v.low.TargetEpoch = &source, &target
		t.j.add(func() { t.v.low.SourceEpoch, t.v.low.TargetEpoch = curSource, curTarget })
	}
	return nil
}

func (t *tx) LastBlock() (slashing.SignedBlock, bool, error) {
	return t.block(func(slot, best uint64) bool { return slot > best }, func(uint64) bool { return true })
}

func (t *tx) NearestBlock(slot uint64) (slashing.SignedBlock, bool, error) {
	return t.block(func(s, best uint64) bool { return s < best }, func(s uint64) bool { return s >= slot })
}

// block returns the recorded block that match accepts and that is better than every other accepted one.
func (t *tx) block(better func(slot, best uint64) bool, match func(slot uint64) bool) (slashing.SignedBlock, bool, error) {
	var (
		best  slashing.SignedBlock
		found bool
	)
	for slot, root := range t.v.blocks {
		if match(slot) && (!found || better(slot, best.Slot)) {
			best, found = slashing.SignedBlock{Slot: slot, SigningRoot: root}, true
		}
	}
	best.SigningRoot = clone(best.SigningRoot)
	return best, found, nil
}

func (t *tx) PruneBlocks() (int, error) {
	low := t.v.low.Slot
	if low == nil {
		return 0, nil
	}
	n := 0
	for slot, root := range t.v.blocks {
		if slot < *low {
			delete(t.v.blocks, slot)
			t.j.add(func() { t.v.blocks[slot] = root })
			n++
		}
	}
	return n, nil
}

func (t *tx) LastAttestation() (slashing.SignedAttestation, bool, error) {
	return t.highestTarget(func(slashing.SignedAttestation) bool { return true })
}

func (t *tx) NearestAttestation(target uint64) (slashing.SignedAttestation, bool, error) {
	var (
		best  slashing.SignedAttestation
		found bool
	)
	for _, a := range t.v.atts {
		if a.TargetEpoch >= target && (!found || a.TargetEpoch < best.TargetEpoch) {
			best, found = a, true
		}
	}
	best.SigningRoot = clone(best.SigningRoot)
	return best, found, nil
}

func (t *tx) PruneAttestations() (int, error) {
	low := t.v.low.TargetEpoch
	if low == nil {
		return 0, nil
	}
	n := 0
	for target, a := range t.v.atts {
		if target < *low {
			delete(t.v.atts, target)
			t.j.add(func() { t.v.atts[target] = a })
			n++
		}
	}
	return n, nil
}

func (t *tx) SetEnabled(enabled bool) error {
	cur := t.v.enabled
	t.v.enabled = enabled
	t.j.add(func() { t.v.enabled = cur })
	return nil
}

// view reads the store for ViewHistory, with s.mu held for writing.
type view struct{ s *Store }

func (v view) GenesisValidatorsRoot() (slashing.Root, bool, error) {
	if v.s.gvr == nil {
		return slashing.Root{}, false, nil
	}
	return *v.s.gvr, true, nil
}

func (v view) Validators(fn func(slashing.KeyID, []byte) error) error {
	ids := make([]slashing.KeyID, 0, len(v.s.validators))
	for id := range v.s.validators {
		ids = append(ids, id)
	}
	for _, id := range sortedIDs(ids) {
		if err := fn(id, slices.Clone(v.s.validators[id].pubkey)); err != nil {
			return err
		}
	}
	return nil
}

func (v view) validator(id slashing.KeyID) (*validator, error) {
	val, ok := v.s.validators[id]
	if !ok {
		return nil, slashing.ErrValidatorNotRegistered
	}
	return val, nil
}

func (v view) LowWatermark(id slashing.KeyID) (slashing.LowWatermark, error) {
	val, err := v.validator(id)
	if err != nil {
		return slashing.LowWatermark{}, err
	}
	return (&tx{v: val}).LowWatermark()
}

func (v view) Blocks(id slashing.KeyID, fn func(slashing.SignedBlock) error) error {
	val, err := v.validator(id)
	if err != nil {
		return err
	}
	for _, slot := range slices.Sorted(maps.Keys(val.blocks)) {
		if err := fn(slashing.SignedBlock{Slot: slot, SigningRoot: clone(val.blocks[slot])}); err != nil {
			return err
		}
	}
	return nil
}

func (v view) Attestations(id slashing.KeyID, fn func(slashing.SignedAttestation) error) error {
	val, err := v.validator(id)
	if err != nil {
		return err
	}
	for _, target := range slices.Sorted(maps.Keys(val.atts)) {
		a := val.atts[target]
		a.SigningRoot = clone(a.SigningRoot)
		if err := fn(a); err != nil {
			return err
		}
	}
	return nil
}

// sortedIDs returns the distinct ids in KeyID order.
func sortedIDs(ids []slashing.KeyID) []slashing.KeyID {
	sorted := slices.Clone(ids)
	slices.SortFunc(sorted, func(a, b slashing.KeyID) int { return bytes.Compare(a[:], b[:]) })
	return slices.Compact(sorted)
}

func copyHigh(h slashing.HighWatermark) slashing.HighWatermark {
	return slashing.HighWatermark{Epoch: clone(h.Epoch), Slot: clone(h.Slot)}
}

// clone returns a copy of *p, or nil, so that callers never alias the store's state.
func clone[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
