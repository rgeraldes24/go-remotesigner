// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package signingroot computes signing domains and signing roots.
//
// It follows the Ethereum consensus specs v1.5.0 (CC0-1.0):
// compute_fork_data_root, compute_domain, get_domain and compute_signing_root.
// QRL uses the same domain type values as Ethereum. The per-type rules (which
// domain type, and which epoch picks the fork version) are in artifact.go.
package signingroot

import (
	"github.com/rgeraldes24/go-remotesigner/internal/ssz"
)

// DomainType is the 4-byte domain type that prefixes a domain.
type DomainType [4]byte

// Version is a 4-byte fork version.
type Version [4]byte

// Domain is a 32-byte signing domain: a domain type followed by the first 28
// bytes of a fork data root.
type Domain [32]byte

// Domain types. The values are Ethereum's.
var (
	DomainBeaconProposer              = DomainType{0x00, 0x00, 0x00, 0x00}
	DomainBeaconAttester              = DomainType{0x01, 0x00, 0x00, 0x00}
	DomainDeposit                     = DomainType{0x03, 0x00, 0x00, 0x00}
	DomainVoluntaryExit               = DomainType{0x04, 0x00, 0x00, 0x00}
	DomainSelectionProof              = DomainType{0x05, 0x00, 0x00, 0x00}
	DomainAggregateAndProof           = DomainType{0x06, 0x00, 0x00, 0x00}
	DomainSyncCommittee               = DomainType{0x07, 0x00, 0x00, 0x00}
	DomainSyncCommitteeSelectionProof = DomainType{0x08, 0x00, 0x00, 0x00}
	DomainContributionAndProof        = DomainType{0x09, 0x00, 0x00, 0x00}
	DomainApplicationBuilder          = DomainType{0x00, 0x00, 0x00, 0x01}
)

// Ethereum's DOMAIN_RANDAO (0x02000000) is deliberately absent: a QRL RANDAO
// reveal is a hash-onion preimage, never a signature.

// Fork is a fork-schedule entry (the consensus Fork container). It is never
// hashed for signing; it only selects the version that goes into a domain.
type Fork struct {
	PreviousVersion Version
	CurrentVersion  Version
	Epoch           uint64
}

// VersionAt is get_domain's version choice: the previous version before the
// fork epoch, the current version from it on.
func (f Fork) VersionAt(epoch uint64) Version {
	if epoch < f.Epoch {
		return f.PreviousVersion
	}
	return f.CurrentVersion
}

// ComputeForkDataRoot returns hash_tree_root(ForkData{currentVersion,
// genesisValidatorsRoot}).
func ComputeForkDataRoot(currentVersion Version, genesisValidatorsRoot [32]byte) [32]byte {
	var v [32]byte
	copy(v[:], currentVersion[:])
	return ssz.ContainerRoot(v, genesisValidatorsRoot)
}

// ComputeDomain returns domainType followed by the first 28 bytes of the fork
// data root of forkVersion and genesisValidatorsRoot.
func ComputeDomain(domainType DomainType, forkVersion Version, genesisValidatorsRoot [32]byte) Domain {
	forkDataRoot := ComputeForkDataRoot(forkVersion, genesisValidatorsRoot)
	var d Domain
	copy(d[:4], domainType[:])
	copy(d[4:], forkDataRoot[:28])
	return d
}

// GetDomain is get_domain: the domain of domainType at epoch, with the fork
// version that fork selects for that epoch.
func GetDomain(fork Fork, epoch uint64, domainType DomainType, genesisValidatorsRoot [32]byte) Domain {
	return ComputeDomain(domainType, fork.VersionAt(epoch), genesisValidatorsRoot)
}

// ComputeSigningRoot returns hash_tree_root(SigningData{objectRoot, domain}).
func ComputeSigningRoot(objectRoot [32]byte, domain Domain) [32]byte {
	return ssz.ContainerRoot(objectRoot, domain)
}

// ComputeEpochAtSlot returns slot / slotsPerEpoch. slotsPerEpoch must not be
// zero.
func ComputeEpochAtSlot(slot, slotsPerEpoch uint64) uint64 {
	return slot / slotsPerEpoch
}
