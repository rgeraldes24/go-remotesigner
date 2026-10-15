// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package memstore is a process-lifetime slashing.Store. The signer uses it only when slashing protection is
// disabled, which is allowed only when every listener is loopback; the RANDAO frontier rule then runs on it for the
// life of the process. It also serves as the reference backend of the conformance suite.
package memstore

import (
	"context"
	"errors"
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
				enabled: true,
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
		return runTx(&tx{s: s, v: v}, func(t *tx) error { return fn(t) })
	})
}

// UpdateAttestations runs fn in an attestation transaction for one validator.
func (s *Store) UpdateAttestations(ctx context.Context, id slashing.KeyID, fn func(slashing.AttestationTx) error) error {
	return s.withValidator(ctx, id, func(v *validator) error {
		return runTx(&tx{s: s, v: v}, func(t *tx) error { return fn(t) })
	})
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

// tx applies writes in place and keeps an undo log, so that a failed transaction leaves no trace. Its methods
// run with s.mu held for reading and v.mu held.
type tx struct {
	s    *Store
	v    *validator
	undo []func()
}

func runTx(t *tx, fn func(*tx) error) error {
	if err := fn(t); err != nil {
		for _, u := range slices.Backward(t.undo) {
			u()
		}
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
	t.undo = append(t.undo, func() { delete(t.v.blocks, b.Slot) })
	return nil
}

func (t *tx) RaiseSlotLowWatermark(slot uint64) error {
	if h := t.s.high.Slot; h != nil && slot > *h {
		return slashing.ErrWatermarkConflict
	}
	if cur := t.v.low.Slot; cur == nil || slot >= *cur {
		t.v.low.Slot = &slot
		t.undo = append(t.undo, func() { t.v.low.Slot = cur })
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
	t.undo = append(t.undo, func() { delete(t.v.atts, a.TargetEpoch) })
	return nil
}

func (t *tx) RaiseEpochLowWatermarks(source, target uint64) error {
	if h := t.s.high.Epoch; h != nil && (source > *h || target > *h) {
		return slashing.ErrWatermarkConflict
	}
	curSource, curTarget := t.v.low.SourceEpoch, t.v.low.TargetEpoch
	if curSource == nil || (source >= *curSource && target >= *curTarget) {
		t.v.low.SourceEpoch, t.v.low.TargetEpoch = &source, &target
		t.undo = append(t.undo, func() { t.v.low.SourceEpoch, t.v.low.TargetEpoch = curSource, curTarget })
	}
	return nil
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
