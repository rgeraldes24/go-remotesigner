// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package signingroot

import (
	"errors"
	"fmt"
)

// ArtifactType is the `type` of a sign request.
type ArtifactType string

// The artifact types of the consensus signing API.
const (
	BlockV2                           ArtifactType = "BLOCK_V2"
	Attestation                       ArtifactType = "ATTESTATION"
	AggregationSlot                   ArtifactType = "AGGREGATION_SLOT"
	AggregateAndProof                 ArtifactType = "AGGREGATE_AND_PROOF"
	VoluntaryExit                     ArtifactType = "VOLUNTARY_EXIT"
	SyncCommitteeMessage              ArtifactType = "SYNC_COMMITTEE_MESSAGE"
	SyncCommitteeSelectionProof       ArtifactType = "SYNC_COMMITTEE_SELECTION_PROOF"
	SyncCommitteeContributionAndProof ArtifactType = "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF"
	ValidatorRegistration             ArtifactType = "VALIDATOR_REGISTRATION"
)

// EpochRule says how a request selects the fork version of its domain.
type EpochRule uint8

const (
	// EpochOfSlot: the request supplies a slot; the fork version is the one
	// at compute_epoch_at_slot(slot).
	EpochOfSlot EpochRule = iota + 1
	// EpochAsGiven: the request supplies the epoch itself.
	EpochAsGiven
	// GenesisFork: no epoch. The domain is compute_domain(type,
	// GENESIS_FORK_VERSION, zero root), as the builder specification defines
	// for validator registrations.
	GenesisFork
)

// Rule is the signing-domain rule of one artifact type.
type Rule struct {
	DomainType DomainType
	Epoch      EpochRule
}

// rules maps each artifact type to its domain type and epoch rule. The
// comment names the request field that supplies the slot or epoch.
var rules = map[ArtifactType]Rule{
	BlockV2:                           {DomainBeaconProposer, EpochOfSlot},              // beacon_block.block_header.slot
	Attestation:                       {DomainBeaconAttester, EpochAsGiven},             // attestation.target.epoch
	AggregationSlot:                   {DomainSelectionProof, EpochOfSlot},              // aggregation_slot.slot
	AggregateAndProof:                 {DomainAggregateAndProof, EpochOfSlot},           // aggregate_and_proof.aggregate.data.slot
	VoluntaryExit:                     {DomainVoluntaryExit, EpochAsGiven},              // voluntary_exit.epoch; no EIP-7044 pin
	SyncCommitteeMessage:              {DomainSyncCommittee, EpochOfSlot},               // sync_committee_message.slot
	SyncCommitteeSelectionProof:       {DomainSyncCommitteeSelectionProof, EpochOfSlot}, // sync_aggregator_selection_data.slot
	SyncCommitteeContributionAndProof: {DomainContributionAndProof, EpochOfSlot},        // contribution_and_proof.contribution.slot
	ValidatorRegistration:             {DomainApplicationBuilder, GenesisFork},          // none
}

// RuleFor returns the rule of t and whether t is a known artifact type.
func RuleFor(t ArtifactType) (Rule, bool) {
	r, ok := rules[t]
	return r, ok
}

var (
	// ErrUnknownArtifactType is returned for a type with no signing rule.
	ErrUnknownArtifactType = errors.New("signingroot: unknown artifact type")
	// ErrSlotsPerEpoch is returned when a chain has no slots per epoch.
	ErrSlotsPerEpoch = errors.New("signingroot: slots per epoch must be positive")
)

// Chain is the network data that domains depend on. It comes from the
// signer's own network configuration, never from a request.
type Chain struct {
	GenesisForkVersion    Version
	GenesisValidatorsRoot [32]byte
	SlotsPerEpoch         uint64
	// Fork is the fork schedule that get_domain selects versions from. QRL
	// networks have a single fork, {genesis, genesis, 0}.
	Fork Fork
}

// NewChain returns a single-fork chain: every epoch signs with the genesis
// fork version.
func NewChain(genesisForkVersion Version, genesisValidatorsRoot [32]byte, slotsPerEpoch uint64) (Chain, error) {
	if slotsPerEpoch == 0 {
		return Chain{}, ErrSlotsPerEpoch
	}
	return Chain{
		GenesisForkVersion:    genesisForkVersion,
		GenesisValidatorsRoot: genesisValidatorsRoot,
		SlotsPerEpoch:         slotsPerEpoch,
		Fork:                  Fork{PreviousVersion: genesisForkVersion, CurrentVersion: genesisForkVersion},
	}, nil
}

// SigningEpoch returns the epoch whose fork version signs an artifact of
// type t, given the slot or epoch the type's rule reads (see Rule). ok is
// false for GenesisFork types, which have no such epoch.
func (c Chain) SigningEpoch(t ArtifactType, at uint64) (epoch uint64, ok bool, err error) {
	r, known := rules[t]
	if !known {
		return 0, false, fmt.Errorf("%w: %q", ErrUnknownArtifactType, t)
	}
	switch r.Epoch {
	case EpochOfSlot:
		if c.SlotsPerEpoch == 0 {
			return 0, false, ErrSlotsPerEpoch
		}
		return ComputeEpochAtSlot(at, c.SlotsPerEpoch), true, nil
	case EpochAsGiven:
		return at, true, nil
	default:
		return 0, false, nil
	}
}

// DomainFor returns the signing domain of an artifact of type t. at is the
// slot or epoch that t's rule reads; GenesisFork types ignore it.
func (c Chain) DomainFor(t ArtifactType, at uint64) (Domain, error) {
	epoch, ok, err := c.SigningEpoch(t, at)
	if err != nil {
		return Domain{}, err
	}
	dt := rules[t].DomainType
	if !ok {
		return ComputeDomain(dt, c.GenesisForkVersion, [32]byte{}), nil
	}
	return GetDomain(c.Fork, epoch, dt, c.GenesisValidatorsRoot), nil
}

// SigningRoot returns the signing root of an artifact of type t whose object
// has hash-tree-root objectRoot. at is as for DomainFor.
func (c Chain) SigningRoot(t ArtifactType, objectRoot [32]byte, at uint64) ([32]byte, error) {
	d, err := c.DomainFor(t, at)
	if err != nil {
		return [32]byte{}, err
	}
	return ComputeSigningRoot(objectRoot, d), nil
}
