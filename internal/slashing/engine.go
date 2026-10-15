// Copyright 2020 ConsenSys AG.
// Copyright 2026 The go-remotesigner Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//
// Modified by The go-remotesigner Authors, 2026: translated from Java to Go and adapted for QRL.
// Derived from Web3Signer
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/DbSlashingProtection.java,
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/validator/BlockValidator.java and
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/validator/AttestationValidator.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package slashing

import (
	"context"
	"sync"
	"sync/atomic"
)

// Engine is the backend-agnostic EIP-3076 rule engine. It implements Protector over any Store.
//
// The low-watermark conditions are the literal EIP-3076 ones: a block at the low-watermark slot, or an attestation
// at the low-watermark target epoch, is refused unless it repeats a recorded message. Web3Signer refuses only below
// the watermark and relies on its double-vote check at it, which differs after a watermark repair (deviation X8).
type Engine struct {
	store Store
	gvr   atomic.Pointer[Root] // the store's pinned root, cached after the first read

	mu         sync.RWMutex
	registered map[KeyID]struct{}
}

var _ Protector = (*Engine)(nil)

// NewEngine returns an engine over store.
func NewEngine(store Store) *Engine {
	return &Engine{store: store, registered: make(map[KeyID]struct{})}
}

// RegisterValidators registers keys in the store and makes them known to the engine. Requests for keys not
// registered through the engine fail with ErrValidatorNotRegistered.
func (e *Engine) RegisterValidators(ctx context.Context, pubkeys [][]byte) error {
	for _, pk := range pubkeys {
		if err := CheckPublicKey(pk); err != nil {
			return err
		}
	}
	if err := e.store.RegisterValidators(ctx, pubkeys); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, pk := range pubkeys {
		e.registered[KeyIDOf(pk)] = struct{}{}
	}
	return nil
}

// ValidatorEnabled reports whether a registered key is enabled.
func (e *Engine) ValidatorEnabled(ctx context.Context, pubkey []byte) (bool, error) {
	id, err := e.lookup(pubkey)
	if err != nil {
		return false, err
	}
	st, err := e.store.ValidatorStatus(ctx, id)
	if err != nil {
		return false, err
	}
	return st.Enabled, nil
}

// SetValidatorEnabled enables or disables a registered key.
func (e *Engine) SetValidatorEnabled(ctx context.Context, pubkey []byte, enabled bool) error {
	id, err := e.lookup(pubkey)
	if err != nil {
		return err
	}
	return e.store.SetValidatorEnabled(ctx, id, enabled)
}

// HighWatermark returns the global high watermark.
func (e *Engine) HighWatermark(ctx context.Context) (HighWatermark, error) {
	return e.store.HighWatermark(ctx)
}

// CheckAndRecordBlock applies the block rules in one store transaction and records an allowed, non-repeated block.
func (e *Engine) CheckAndRecordBlock(ctx context.Context, req BlockRequest) (Decision, error) {
	id, err := e.lookup(req.PublicKey)
	if err != nil {
		return Decision{}, err
	}
	if d, err := e.checkGenesisValidatorsRoot(ctx, req.GenesisValidatorsRoot); err != nil || !d.Allowed {
		return d, err
	}
	var d Decision
	err = e.store.UpdateBlocks(ctx, id, func(tx BlockTx) error {
		var err error
		d, err = checkBlock(tx, req.Slot, req.SigningRoot)
		return err
	})
	if err != nil {
		return Decision{}, err
	}
	return d, nil
}

// CheckAndRecordAttestation applies the attestation rules in one store transaction and records an allowed,
// non-repeated attestation.
func (e *Engine) CheckAndRecordAttestation(ctx context.Context, req AttestationRequest) (Decision, error) {
	id, err := e.lookup(req.PublicKey)
	if err != nil {
		return Decision{}, err
	}
	if d, err := e.checkGenesisValidatorsRoot(ctx, req.GenesisValidatorsRoot); err != nil || !d.Allowed {
		return d, err
	}
	var d Decision
	err = e.store.UpdateAttestations(ctx, id, func(tx AttestationTx) error {
		var err error
		d, err = checkAttestation(tx, req.SourceEpoch, req.TargetEpoch, req.SigningRoot)
		return err
	})
	if err != nil {
		return Decision{}, err
	}
	return d, nil
}

func (e *Engine) lookup(pubkey []byte) (KeyID, error) {
	if err := CheckPublicKey(pubkey); err != nil {
		return KeyID{}, err
	}
	id := KeyIDOf(pubkey)
	e.mu.RLock()
	_, ok := e.registered[id]
	e.mu.RUnlock()
	if !ok {
		return KeyID{}, ErrValidatorNotRegistered
	}
	return id, nil
}

// checkGenesisValidatorsRoot compares gvr with the store's root, pinning gvr when the store has none yet.
func (e *Engine) checkGenesisValidatorsRoot(ctx context.Context, gvr Root) (Decision, error) {
	pinned := e.gvr.Load()
	if pinned == nil {
		root, err := e.store.PinGenesisValidatorsRoot(ctx, gvr)
		if err != nil {
			return Decision{}, err
		}
		pinned = &root
		e.gvr.Store(pinned)
	}
	if *pinned != gvr {
		return refuse(ReasonGenesisValidatorsRootMismatch), nil
	}
	return allow(), nil
}

// checkBlock applies, in order: the enabled flag, the high watermark, the low watermark, the recorded block at the
// slot (double proposal or repeat), and the literal EIP-3076 condition at the low-watermark slot. An allowed block
// is recorded, and the first one sets the low-watermark slot.
func checkBlock(tx BlockTx, slot uint64, root Root) (Decision, error) {
	if d, err := checkEnabled(tx); err != nil || !d.Allowed {
		return d, err
	}
	high, err := tx.HighWatermark()
	if err != nil {
		return Decision{}, err
	}
	if high.Slot != nil && slot >= *high.Slot {
		return refuse(ReasonAboveHighWatermark), nil
	}
	low, err := tx.LowWatermark()
	if err != nil {
		return Decision{}, err
	}
	if low.Slot != nil && slot < *low.Slot {
		return refuse(ReasonBelowWatermark), nil
	}
	existing, found, err := tx.BlockAt(slot)
	if err != nil {
		return Decision{}, err
	}
	if found {
		if sameRoot(existing.SigningRoot, root) {
			return Decision{Allowed: true, Repeat: true}, nil
		}
		return refuse(ReasonDoubleProposal), nil
	}
	if low.Slot != nil && slot == *low.Slot {
		return refuse(ReasonBelowWatermark), nil
	}
	if err := tx.InsertBlock(SignedBlock{Slot: slot, SigningRoot: &root}); err != nil {
		return Decision{}, err
	}
	if low.Slot == nil {
		if err := tx.RaiseSlotLowWatermark(slot); err != nil {
			return Decision{}, err
		}
	}
	return allow(), nil
}

// checkAttestation applies, in order: the enabled flag, source ≤ target, the high watermark, the low watermarks,
// the recorded attestation at the target (double vote), surround votes in both directions, repeat signing, and the
// literal EIP-3076 condition at the low-watermark target. A repeat that a recorded attestation surrounds, or that
// surrounds one, is refused: that is only possible with imported history. An allowed attestation is recorded, and
// the first one sets the low-watermark epochs.
func checkAttestation(tx AttestationTx, source, target uint64, root Root) (Decision, error) {
	if d, err := checkEnabled(tx); err != nil || !d.Allowed {
		return d, err
	}
	if source > target {
		return refuse(ReasonSourceAfterTarget), nil
	}
	high, err := tx.HighWatermark()
	if err != nil {
		return Decision{}, err
	}
	if high.Epoch != nil && (source >= *high.Epoch || target >= *high.Epoch) {
		return refuse(ReasonAboveHighWatermark), nil
	}
	low, err := tx.LowWatermark()
	if err != nil {
		return Decision{}, err
	}
	if (low.SourceEpoch != nil && source < *low.SourceEpoch) || (low.TargetEpoch != nil && target < *low.TargetEpoch) {
		return refuse(ReasonBelowWatermark), nil
	}
	existing, found, err := tx.AttestationAt(target)
	if err != nil {
		return Decision{}, err
	}
	repeat := found && sameRoot(existing.SigningRoot, root)
	if found && !repeat {
		return refuse(ReasonDoubleVote), nil
	}
	_, surrounding, err := tx.SurroundingAttestation(source, target)
	if err != nil {
		return Decision{}, err
	}
	if surrounding {
		return refuse(ReasonSurroundingVote), nil
	}
	_, surrounded, err := tx.SurroundedAttestation(source, target)
	if err != nil {
		return Decision{}, err
	}
	if surrounded {
		return refuse(ReasonSurroundedVote), nil
	}
	if repeat {
		return Decision{Allowed: true, Repeat: true}, nil
	}
	if low.TargetEpoch != nil && target == *low.TargetEpoch {
		return refuse(ReasonBelowWatermark), nil
	}
	if err := tx.InsertAttestation(SignedAttestation{SourceEpoch: source, TargetEpoch: target, SigningRoot: &root}); err != nil {
		return Decision{}, err
	}
	if low.SourceEpoch == nil && low.TargetEpoch == nil {
		if err := tx.RaiseEpochLowWatermarks(source, target); err != nil {
			return Decision{}, err
		}
	}
	return allow(), nil
}

func checkEnabled(tx ValidatorTx) (Decision, error) {
	enabled, err := tx.Enabled()
	if err != nil {
		return Decision{}, err
	}
	if !enabled {
		return refuse(ReasonValidatorDisabled), nil
	}
	return allow(), nil
}

// sameRoot reports whether a recorded root is known and equals root. An unknown root never matches.
func sameRoot(recorded *Root, root Root) bool { return recorded != nil && *recorded == root }

func allow() Decision          { return Decision{Allowed: true} }
func refuse(r Reason) Decision { return Decision{Reason: r} }
