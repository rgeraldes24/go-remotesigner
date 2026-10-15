// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package types

// Mirror structs for the differential fuzz in fastssz_test.go: the QRL
// containers declared again with fastssz tags, so that fastssz's code
// generator, an implementation independent of internal/ssz, computes their
// hash-tree-roots. The two contribution presets get one mirror each,
// because fastssz fixes the bitvector length in a tag.
//
// fastssz_mirror_htr_test.go is generated from this file. To regenerate:
// copy this file to an empty directory as mirror.go, run
//
//	go run github.com/ferranbt/fastssz/sszgen@v1.0.0 --path mirror.go
//
// and keep only the HashTreeRoot, HashTreeRootWith and GetTree methods of the
// output, under the header of fastssz_mirror_htr_test.go.

type mirrorHeader struct {
	Slot          uint64
	ProposerIndex uint64
	ParentRoot    []byte `ssz-size:"32"`
	StateRoot     []byte `ssz-size:"32"`
	BodyRoot      []byte `ssz-size:"32"`
}

type mirrorCheckpoint struct {
	Epoch uint64
	Root  []byte `ssz-size:"32"`
}

type mirrorAttestationData struct {
	Slot            uint64
	Index           uint64
	BeaconBlockRoot []byte `ssz-size:"32"`
	Source          *mirrorCheckpoint
	Target          *mirrorCheckpoint
}

type mirrorAttestation struct {
	AggregationBits []byte `ssz:"bitlist" ssz-max:"32"`
	Data            *mirrorAttestationData
	Signatures      [][]byte `ssz-max:"32" ssz-size:"?,4627"`
}

type mirrorAggregateAndProof struct {
	AggregatorIndex uint64
	Aggregate       *mirrorAttestation
	SelectionProof  []byte `ssz-size:"4627"`
}

type mirrorVoluntaryExit struct {
	Epoch          uint64
	ValidatorIndex uint64
}

type mirrorSelectionData struct {
	Slot              uint64
	SubcommitteeIndex uint64
}

type mirrorContributionMinimal struct {
	Slot              uint64
	BeaconBlockRoot   []byte `ssz-size:"32"`
	SubcommitteeIndex uint64
	AggregationBits   []byte   `ssz-size:"2"`
	Signatures        [][]byte `ssz-max:"128" ssz-size:"?,4627"`
}

type mirrorContributionMainnet struct {
	Slot              uint64
	BeaconBlockRoot   []byte `ssz-size:"32"`
	SubcommitteeIndex uint64
	AggregationBits   []byte   `ssz-size:"16"`
	Signatures        [][]byte `ssz-max:"128" ssz-size:"?,4627"`
}

type mirrorContributionAndProofMinimal struct {
	AggregatorIndex uint64
	Contribution    *mirrorContributionMinimal
	SelectionProof  []byte `ssz-size:"4627"`
}

type mirrorContributionAndProofMainnet struct {
	AggregatorIndex uint64
	Contribution    *mirrorContributionMainnet
	SelectionProof  []byte `ssz-size:"4627"`
}

type mirrorRegistration struct {
	FeeRecipient []byte `ssz-size:"64"`
	GasLimit     uint64
	Timestamp    uint64
	Pubkey       []byte `ssz-size:"2592"`
}

type mirrorForkData struct {
	CurrentVersion        []byte `ssz-size:"4"`
	GenesisValidatorsRoot []byte `ssz-size:"32"`
}

type mirrorSigningData struct {
	ObjectRoot []byte `ssz-size:"32"`
	Domain     []byte `ssz-size:"32"`
}
