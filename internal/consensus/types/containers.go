// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package types defines the QRL consensus containers the signer hashes and
// their hash-tree-roots.
//
// Shapes follow the Ethereum consensus specs v1.5.0 and builder specs
// (CC0-1.0), with the QRL deltas taken as facts: ML-DSA-87 public keys of
// 2,592 bytes and signatures of 4,627 bytes, 64-byte execution addresses, and
// per-participant signature lists where Ethereum has one aggregate
// signature. Fields are hashed in declaration order.
//
// The hash-tree-roots do not depend on the preset. The one preset-dependent
// field, SyncCommitteeContribution.AggregationBits (2 bytes on minimal, 16 on
// mainnet), fits one chunk either way; checking its length against the
// network's preset is the request decoder's job.
package types

import (
	"fmt"

	"github.com/rgeraldes24/go-remotesigner/internal/ssz"
)

// QRL sizes and list limits.
const (
	PubkeyLength    = 2592 // ML-DSA-87 public key
	SignatureLength = 4627 // ML-DSA-87 signature
	AddressLength   = 64   // QRL execution address

	// MaxAttestationSignatures is the limit of Attestation.AggregationBits
	// (a Bitlist) and of Attestation.Signatures: MAX_VALIDATORS_PER_COMMITTEE,
	// 32 in every preset.
	MaxAttestationSignatures = 32
	// MaxContributionSignatures is the limit of
	// SyncCommitteeContribution.Signatures, 128 in every preset.
	MaxContributionSignatures = 128
)

type (
	// Pubkey is an ML-DSA-87 public key, Vector[byte, 2592].
	Pubkey [PubkeyLength]byte
	// Signature is an ML-DSA-87 signature, Vector[byte, 4627].
	Signature [SignatureLength]byte
	// Address is a QRL execution address, Vector[byte, 64].
	Address [AddressLength]byte
)

// Uint64 is a bare uint64 signed as an object: the slot of AGGREGATION_SLOT.
type Uint64 uint64

// HashTreeRoot returns the 8 little-endian bytes right-padded to 32.
func (v Uint64) HashTreeRoot() ([32]byte, error) {
	return ssz.Uint64Root(uint64(v)), nil
}

// Bytes32 is a bare 32-byte root signed as an object: the block root of
// SYNC_COMMITTEE_MESSAGE. Its hash-tree-root is the bytes themselves.
type Bytes32 [32]byte

// HashTreeRoot returns b.
func (b Bytes32) HashTreeRoot() ([32]byte, error) {
	return b, nil
}

// BeaconBlockHeader is the object of BLOCK_V2. Its root equals the root of the
// full or blinded block it summarises.
type BeaconBlockHeader struct {
	Slot          uint64
	ProposerIndex uint64
	ParentRoot    [32]byte
	StateRoot     [32]byte
	BodyRoot      [32]byte
}

// HashTreeRoot returns the container root of the five fields.
func (h BeaconBlockHeader) HashTreeRoot() ([32]byte, error) {
	return ssz.ContainerRoot(
		ssz.Uint64Root(h.Slot),
		ssz.Uint64Root(h.ProposerIndex),
		h.ParentRoot,
		h.StateRoot,
		h.BodyRoot,
	), nil
}

// Checkpoint is an epoch and a block root.
type Checkpoint struct {
	Epoch uint64
	Root  [32]byte
}

// HashTreeRoot returns the container root of the two fields.
func (c Checkpoint) HashTreeRoot() ([32]byte, error) {
	return ssz.ContainerRoot(ssz.Uint64Root(c.Epoch), c.Root), nil
}

// AttestationData is the object of ATTESTATION. Index is the committee index
// (`index` on the wire).
type AttestationData struct {
	Slot            uint64
	Index           uint64
	BeaconBlockRoot [32]byte
	Source          Checkpoint
	Target          Checkpoint
}

// HashTreeRoot returns the container root of the five fields.
func (d AttestationData) HashTreeRoot() ([32]byte, error) {
	source, _ := d.Source.HashTreeRoot()
	target, _ := d.Target.HashTreeRoot()
	return ssz.ContainerRoot(
		ssz.Uint64Root(d.Slot),
		ssz.Uint64Root(d.Index),
		d.BeaconBlockRoot,
		source,
		target,
	), nil
}

// Attestation is the aggregate inside AGGREGATE_AND_PROOF.
type Attestation struct {
	// AggregationBits is the serialized Bitlist[32], delimiter bit included.
	AggregationBits []byte
	Data            AttestationData
	// Signatures is List[Signature, 32], one per set bit.
	Signatures []Signature
}

// HashTreeRoot fails if AggregationBits is not a valid Bitlist[32] or there
// are more than 32 signatures. It does not check that the signature count
// matches the set bits; that is a request invariant, not an SSZ rule.
func (a *Attestation) HashTreeRoot() ([32]byte, error) {
	bits, err := ssz.BitlistRoot(a.AggregationBits, MaxAttestationSignatures)
	if err != nil {
		return [32]byte{}, fmt.Errorf("attestation aggregation_bits: %w", err)
	}
	data, _ := a.Data.HashTreeRoot()
	sigs, err := signatureListRoot(a.Signatures, MaxAttestationSignatures)
	if err != nil {
		return [32]byte{}, fmt.Errorf("attestation signatures: %w", err)
	}
	return ssz.ContainerRoot(bits, data, sigs), nil
}

// AggregateAttestationAndProof is the object of AGGREGATE_AND_PROOF.
type AggregateAttestationAndProof struct {
	AggregatorIndex uint64
	Aggregate       Attestation
	SelectionProof  Signature
}

// HashTreeRoot fails if the aggregate is invalid (see Attestation).
func (p *AggregateAttestationAndProof) HashTreeRoot() ([32]byte, error) {
	agg, err := p.Aggregate.HashTreeRoot()
	if err != nil {
		return [32]byte{}, err
	}
	return ssz.ContainerRoot(ssz.Uint64Root(p.AggregatorIndex), agg, p.SelectionProof.root()), nil
}

// VoluntaryExit is the object of VOLUNTARY_EXIT.
type VoluntaryExit struct {
	Epoch          uint64
	ValidatorIndex uint64
}

// HashTreeRoot returns the container root of the two fields.
func (e VoluntaryExit) HashTreeRoot() ([32]byte, error) {
	return ssz.ContainerRoot(ssz.Uint64Root(e.Epoch), ssz.Uint64Root(e.ValidatorIndex)), nil
}

// SyncAggregatorSelectionData is the object of SYNC_COMMITTEE_SELECTION_PROOF.
type SyncAggregatorSelectionData struct {
	Slot              uint64
	SubcommitteeIndex uint64
}

// HashTreeRoot returns the container root of the two fields.
func (s SyncAggregatorSelectionData) HashTreeRoot() ([32]byte, error) {
	return ssz.ContainerRoot(ssz.Uint64Root(s.Slot), ssz.Uint64Root(s.SubcommitteeIndex)), nil
}

// SyncCommitteeContribution is the contribution inside
// SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF.
type SyncCommitteeContribution struct {
	Slot              uint64
	BeaconBlockRoot   [32]byte
	SubcommitteeIndex uint64
	// AggregationBits is the serialized Bitvector of the subcommittee size:
	// 2 bytes (16 bits) on minimal presets, 16 bytes (128 bits) on mainnet.
	// It is hashed as a Bitvector of 8*len bits.
	AggregationBits []byte
	// Signatures is List[Signature, 128], one per set bit.
	Signatures []Signature
}

// HashTreeRoot fails if AggregationBits is empty or there are more than 128
// signatures.
func (c *SyncCommitteeContribution) HashTreeRoot() ([32]byte, error) {
	bits, err := ssz.BitvectorRoot(c.AggregationBits, 8*uint64(len(c.AggregationBits)))
	if err != nil {
		return [32]byte{}, fmt.Errorf("contribution aggregation_bits: %w", err)
	}
	sigs, err := signatureListRoot(c.Signatures, MaxContributionSignatures)
	if err != nil {
		return [32]byte{}, fmt.Errorf("contribution signatures: %w", err)
	}
	return ssz.ContainerRoot(
		ssz.Uint64Root(c.Slot),
		c.BeaconBlockRoot,
		ssz.Uint64Root(c.SubcommitteeIndex),
		bits,
		sigs,
	), nil
}

// ContributionAndProof is the object of SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF.
type ContributionAndProof struct {
	AggregatorIndex uint64
	Contribution    SyncCommitteeContribution
	SelectionProof  Signature
}

// HashTreeRoot fails if the contribution is invalid (see
// SyncCommitteeContribution).
func (p *ContributionAndProof) HashTreeRoot() ([32]byte, error) {
	contribution, err := p.Contribution.HashTreeRoot()
	if err != nil {
		return [32]byte{}, err
	}
	return ssz.ContainerRoot(ssz.Uint64Root(p.AggregatorIndex), contribution, p.SelectionProof.root()), nil
}

// ValidatorRegistrationV1 is the object of VALIDATOR_REGISTRATION.
type ValidatorRegistrationV1 struct {
	FeeRecipient Address
	GasLimit     uint64
	Timestamp    uint64
	Pubkey       Pubkey
}

// HashTreeRoot returns the container root of the four fields.
func (r *ValidatorRegistrationV1) HashTreeRoot() ([32]byte, error) {
	return ssz.ContainerRoot(
		byteVectorRoot(r.FeeRecipient[:]),
		ssz.Uint64Root(r.GasLimit),
		ssz.Uint64Root(r.Timestamp),
		byteVectorRoot(r.Pubkey[:]),
	), nil
}

// root returns the hash-tree-root of a signature: 145 chunks padded to 256
// leaves.
func (s *Signature) root() [32]byte {
	return byteVectorRoot(s[:])
}

// byteVectorRoot is ssz.ByteVectorRoot for the fixed-size arrays above,
// which are never empty.
func byteVectorRoot(b []byte) [32]byte {
	return ssz.Merkleize(ssz.Pack(b))
}

// signatureListRoot returns the root of List[Signature, limit]. It checks the
// limit before hashing anything.
func signatureListRoot(sigs []Signature, limit uint64) ([32]byte, error) {
	if uint64(len(sigs)) > limit {
		return [32]byte{}, fmt.Errorf("%w: %d signatures, limit %d", ssz.ErrLimit, len(sigs), limit)
	}
	roots := make([][32]byte, len(sigs))
	for i := range sigs {
		roots[i] = sigs[i].root()
	}
	return ssz.ListRoot(roots, limit)
}
