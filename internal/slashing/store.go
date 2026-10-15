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
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/dao/SignedBlocksDao.java,
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/dao/SignedAttestationsDao.java,
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/dao/LowWatermarkDao.java,
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/dao/MetadataDao.java,
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/dao/ValidatorsDao.java and
// slashing-protection/src/main/resources/migrations/postgresql/V00012__add_highwatermark_metadata.sql
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package slashing

import "context"

// SignedBlock is a recorded block proposal. A nil SigningRoot means the root is unknown (an imported record
// without one); such a record conflicts with every request at its slot.
type SignedBlock struct {
	Slot        uint64
	SigningRoot *Root
}

// SignedAttestation is a recorded attestation. A nil SigningRoot means the root is unknown; such a record
// conflicts with every request at its target epoch.
type SignedAttestation struct {
	SourceEpoch uint64
	TargetEpoch uint64
	SigningRoot *Root
}

// LowWatermark is a validator's low watermark. The slot is independent of the epochs; SourceEpoch and TargetEpoch
// are either both set or both nil. A low watermark only moves up.
type LowWatermark struct {
	Slot        *uint64
	SourceEpoch *uint64
	TargetEpoch *uint64
}

// HighWatermark is the global high watermark, a fence used before migrations. Either field may be nil; the zero
// value means no high watermark.
type HighWatermark struct {
	Epoch *uint64
	Slot  *uint64
}

// IsSet reports whether any part of the high watermark is set.
func (h HighWatermark) IsSet() bool { return h.Epoch != nil || h.Slot != nil }

// ValidatorStatus is a key's registration state.
type ValidatorStatus struct {
	Registered bool
	Enabled    bool
}

// Store is a slashing-protection backend. A store holds the history of one network: its genesis validators root
// is pinned once and never changes.
//
// UpdateBlocks and UpdateAttestations run their function in one transaction that is serialised against every
// other update of the same kind for the same validator, across processes where the backend is shared. When the
// function returns an error, nothing it wrote is kept; otherwise everything is durable before the call returns.
// Both return ErrValidatorNotRegistered, without calling the function, for an unregistered key.
//
// The conformance suite in package slashingtest pins down the contract; every backend must pass it.
type Store interface {
	// SchemaVersion returns the schema version the store was written with (see CheckSchema).
	SchemaVersion(ctx context.Context) (uint32, error)

	// GenesisValidatorsRoot returns the pinned genesis validators root, if any.
	GenesisValidatorsRoot(ctx context.Context) (Root, bool, error)
	// PinGenesisValidatorsRoot pins gvr if no root is pinned yet, and returns the root that is pinned afterwards.
	// Concurrent first calls agree on one root.
	PinGenesisValidatorsRoot(ctx context.Context, gvr Root) (Root, error)

	// HighWatermark returns the global high watermark; the zero value means none is set.
	HighWatermark(ctx context.Context) (HighWatermark, error)
	// SetHighWatermark replaces the global high watermark; the zero value removes it. Setting one returns
	// ErrNoGenesisValidatorsRoot before a root is pinned, and ErrWatermarkConflict unless the slot is greater than
	// every validator's low-watermark slot and the epoch is greater than every low-watermark source and target
	// epoch.
	SetHighWatermark(ctx context.Context, h HighWatermark) error

	// RegisterValidators registers keys of PublicKeyLength bytes. New keys are enabled; registering a known key
	// again leaves its enabled flag unchanged.
	RegisterValidators(ctx context.Context, pubkeys [][]byte) error
	// ValidatorStatus returns a key's registration state; an unknown key is neither registered nor enabled.
	ValidatorStatus(ctx context.Context, id KeyID) (ValidatorStatus, error)
	// SetValidatorEnabled sets a registered key's enabled flag. It is serialised with UpdateBlocks and
	// UpdateAttestations for the same validator: it takes the validator's block lock and then its attestation lock
	// (the fixed order block, attestation, RANDAO that every multi-lock operation uses), so a check-and-record that
	// read the old flag has committed before it returns, and one that starts afterwards reads the new flag.
	SetValidatorEnabled(ctx context.Context, id KeyID, enabled bool) error

	// UpdateBlocks runs fn in a block transaction for one validator.
	UpdateBlocks(ctx context.Context, id KeyID, fn func(BlockTx) error) error
	// UpdateAttestations runs fn in an attestation transaction for one validator.
	UpdateAttestations(ctx context.Context, id KeyID, fn func(AttestationTx) error) error

	RandaoStore

	// Close releases the store.
	Close() error
}

// ValidatorTx is the part of a transaction shared by blocks and attestations.
type ValidatorTx interface {
	// Enabled reports the validator's enabled flag.
	Enabled() (bool, error)
	// HighWatermark returns the global high watermark.
	HighWatermark() (HighWatermark, error)
	// LowWatermark returns the validator's low watermark; the zero value means none is set.
	LowWatermark() (LowWatermark, error)
}

// BlockTx reads and writes one validator's block history.
type BlockTx interface {
	ValidatorTx
	// BlockAt returns the block recorded at slot. There is at most one.
	BlockAt(slot uint64) (SignedBlock, bool, error)
	// InsertBlock records b. It returns ErrDuplicateRecord when a block is already recorded at b.Slot.
	InsertBlock(b SignedBlock) error
	// RaiseSlotLowWatermark sets the low-watermark slot when none is set or when slot is at or above it, and
	// leaves it unchanged otherwise. It returns ErrWatermarkConflict when slot is above the high-watermark slot.
	RaiseSlotLowWatermark(slot uint64) error
}

// AttestationTx reads and writes one validator's attestation history.
type AttestationTx interface {
	ValidatorTx
	// AttestationAt returns the attestation recorded at target epoch target. There is at most one.
	AttestationAt(target uint64) (SignedAttestation, bool, error)
	// SurroundingAttestation returns a recorded attestation a with a.SourceEpoch < source and
	// a.TargetEpoch > target: one that surrounds (source, target). Of several, it returns the one with the highest
	// target epoch.
	SurroundingAttestation(source, target uint64) (SignedAttestation, bool, error)
	// SurroundedAttestation returns a recorded attestation a with a.SourceEpoch > source and
	// a.TargetEpoch < target: one that (source, target) surrounds. Of several, it returns the one with the highest
	// target epoch.
	SurroundedAttestation(source, target uint64) (SignedAttestation, bool, error)
	// InsertAttestation records a. It returns ErrDuplicateRecord when an attestation is already recorded at
	// a.TargetEpoch.
	InsertAttestation(a SignedAttestation) error
	// RaiseEpochLowWatermarks sets both low-watermark epochs when none are set or when source and target are both
	// at or above them, and leaves them unchanged otherwise. It returns ErrWatermarkConflict when either epoch is
	// above the high-watermark epoch.
	RaiseEpochLowWatermarks(source, target uint64) error
}
