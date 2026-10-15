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
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/SlashingProtection.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

// Package slashing is the backend-agnostic slashing-protection core: the EIP-3076 rule engine, the Protector
// interface the signing path calls, and the Store interface that the bbolt, Postgres and in-memory backends
// implement.
//
// A refusal is reported as a Decision with Allowed false and a Reason (HTTP 412 at the API). A request that the
// server should have rejected as malformed is reported as ErrGenesisValidatorsRootMismatch or ErrSourceAfterTarget
// (HTTP 400); any other error is an infrastructure failure (HTTP 500). Only BLOCK_V2 and ATTESTATION requests are
// subject to these rules.
package slashing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// PublicKeyLength is the size of an ML-DSA-87 public key in bytes.
const PublicKeyLength = 2592

// Root is a 32-byte signing root or genesis validators root.
type Root [32]byte

// KeyID identifies a validator in a store: the SHA-256 of its public key. Stores key their records by KeyID because
// a 2,592-byte key is too large for an efficient index.
type KeyID [32]byte

// KeyIDOf returns the KeyID of a public key.
func KeyIDOf(pubkey []byte) KeyID { return sha256.Sum256(pubkey) }

// String returns a short, log-safe form of the id: "0x" and its first 8 bytes in hex.
func (k KeyID) String() string { return "0x" + hex.EncodeToString(k[:8]) }

// Reason says why a request was refused. The values are the API's 412 error reasons, and the only values of the
// prevented-signings metric label.
type Reason string

// Refusal reasons.
const (
	// ReasonDoubleProposal: a different block, or one with an unknown signing root, is recorded at the slot.
	ReasonDoubleProposal Reason = "SLASHING_DOUBLE_PROPOSAL"
	// ReasonDoubleVote: a different attestation, or one with an unknown signing root, is recorded at the target.
	ReasonDoubleVote Reason = "SLASHING_DOUBLE_VOTE"
	// ReasonSurroundingVote: a recorded attestation surrounds the requested one.
	ReasonSurroundingVote Reason = "SLASHING_SURROUNDING_VOTE"
	// ReasonSurroundedVote: the requested attestation surrounds a recorded one.
	ReasonSurroundedVote Reason = "SLASHING_SURROUNDED_VOTE"
	// ReasonBelowWatermark: the slot, source or target epoch is at or below the validator's low watermark and the
	// request is not a repeat of a recorded message (EIP-3076 conditions 3-5).
	ReasonBelowWatermark Reason = "SLASHING_BELOW_WATERMARK"
	// ReasonAboveHighWatermark: the slot or an epoch is at or beyond the global high watermark.
	ReasonAboveHighWatermark Reason = "SLASHING_ABOVE_HIGH_WATERMARK"
	// ReasonValidatorDisabled: the validator is disabled in the store.
	ReasonValidatorDisabled Reason = "VALIDATOR_DISABLED"
)

// Decision is the outcome of a check-and-record call.
type Decision struct {
	// Allowed reports whether the message may be signed.
	Allowed bool
	// Repeat reports that the message was allowed as an identical repeat of a recorded one; nothing was written.
	Repeat bool
	// Reason is set when Allowed is false.
	Reason Reason
}

// BlockRequest asks to sign a block proposal.
type BlockRequest struct {
	PublicKey             []byte
	GenesisValidatorsRoot Root
	Slot                  uint64
	SigningRoot           Root
}

// AttestationRequest asks to sign an attestation.
type AttestationRequest struct {
	PublicKey             []byte
	GenesisValidatorsRoot Root
	SourceEpoch           uint64
	TargetEpoch           uint64
	SigningRoot           Root
}

// Protector decides whether a block or attestation may be signed and records it in the same atomic step.
type Protector interface {
	// RegisterValidators makes keys known to the protector and the store. A newly registered key is enabled; a key
	// that is already registered keeps its enabled flag.
	RegisterValidators(ctx context.Context, pubkeys [][]byte) error
	// ValidatorEnabled reports whether a registered key is enabled.
	ValidatorEnabled(ctx context.Context, pubkey []byte) (bool, error)
	// SetValidatorEnabled enables or disables a registered key.
	SetValidatorEnabled(ctx context.Context, pubkey []byte, enabled bool) error
	// CheckAndRecordBlock applies the block rules and records an allowed block before returning.
	CheckAndRecordBlock(ctx context.Context, req BlockRequest) (Decision, error)
	// CheckAndRecordAttestation applies the attestation rules and records an allowed attestation before returning.
	CheckAndRecordAttestation(ctx context.Context, req AttestationRequest) (Decision, error)
	// HighWatermark returns the global high watermark; the zero value means none is set.
	HighWatermark(ctx context.Context) (HighWatermark, error)
}

// Errors shared by the engine and the stores.
var (
	// ErrInvalidPublicKey: a public key is not PublicKeyLength bytes long.
	ErrInvalidPublicKey = errors.New("slashing: public key must be 2592 bytes")
	// ErrValidatorNotRegistered: the key was never registered.
	ErrValidatorNotRegistered = errors.New("slashing: validator is not registered")
	// ErrDuplicateRecord: a block is already recorded at the slot, or an attestation at the target epoch.
	ErrDuplicateRecord = errors.New("slashing: a record already exists at this slot or target epoch")
	// ErrWatermarkConflict: a low watermark would exceed the high watermark, or a high watermark would not exceed
	// every low watermark.
	ErrWatermarkConflict = errors.New("slashing: low watermarks must stay at or below the high watermark")
	// ErrNoGenesisValidatorsRoot: a high watermark was set before the store was pinned to a network.
	ErrNoGenesisValidatorsRoot = errors.New("slashing: the store has no genesis validators root yet")

	// ErrGenesisValidatorsRootMismatch: the request's genesis validators root differs from the store's. The server
	// rejects such a request earlier with 400 FORK_INFO_MISMATCH; if the engine sees one, it maps to the same 400.
	ErrGenesisValidatorsRootMismatch = errors.New("slashing: genesis validators root does not match the store's")
	// ErrSourceAfterTarget: the attestation's source epoch is greater than its target epoch. The server rejects such
	// a request earlier with 400 INVARIANT_VIOLATION; if the engine sees one, it maps to the same 400.
	ErrSourceAfterTarget = errors.New("slashing: source epoch is greater than target epoch")
)

// CheckPublicKey returns ErrInvalidPublicKey unless pubkey is PublicKeyLength bytes long.
func CheckPublicKey(pubkey []byte) error {
	if len(pubkey) != PublicKeyLength {
		return ErrInvalidPublicKey
	}
	return nil
}
