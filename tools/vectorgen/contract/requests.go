// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"

	fssz "github.com/prysmaticlabs/fastssz"
	"github.com/theQRL/go-bitfield"
	"github.com/theQRL/qrysm/beacon-chain/core/signing"
	fieldparams "github.com/theQRL/qrysm/config/fieldparams"
	"github.com/theQRL/qrysm/config/params"
	"github.com/theQRL/qrysm/consensus-types/primitives"
	qrysmpb "github.com/theQRL/qrysm/proto/qrysm/v1alpha1"
	validatorpb "github.com/theQRL/qrysm/proto/qrysm/v1alpha1/validator-client"
	"github.com/theQRL/qrysm/testing/util"
	"github.com/theQRL/qrysm/time/slots"
	web3signerv1 "github.com/theQRL/qrysm/validator/keymanager/remote-web3signer/v1"
)

// signCase is one SignRequest as the qrysm validator hands it to its
// keymanager.
type signCase struct {
	oneof string // the oneof's proto field name
	typ   string // the artifact type the client maps it to
	req   *validatorpb.SignRequest
}

// signRequests builds one request per signing oneof of SignRequest for the
// key pub on the active configuration cfg, whose genesis validators root is
// gvr. Each signing root is computed by qrysm the way its validator does:
// get_domain over the single fork for the type's epoch, compute_domain with
// the genesis fork version and a zero root for the registration, then
// ComputeSigningRoot. The objects are small and fixed; their slots are far
// behind the clock of any signer started at or after genesisTime, so no
// clock bound refuses them, and the two blocks have different slots, so
// slashing protection allows both.
func signRequests(cfg *params.BeaconChainConfig, gvr [32]byte, pub []byte, genesisTime uint64) ([]signCase, error) {
	const slot = primitives.Slot(13)
	att := &qrysmpb.AttestationData{
		Slot:            slot,
		CommitteeIndex:  1,
		BeaconBlockRoot: fill(32, 0x11),
		Source:          &qrysmpb.Checkpoint{Epoch: 0, Root: fill(32, 0x12)},
		Target:          &qrysmpb.Checkpoint{Epoch: slots.ToEpoch(slot), Root: fill(32, 0x13)},
	}
	block := util.HydrateBeaconBlockZond(&qrysmpb.BeaconBlockZond{
		Slot: slot, ParentRoot: fill(32, 0x21), StateRoot: fill(32, 0x22),
	})
	blinded := util.HydrateBlindedBeaconBlockZond(&qrysmpb.BlindedBeaconBlockZond{
		Slot: slot + 1, ParentRoot: fill(32, 0x23), StateRoot: fill(32, 0x24),
	})
	aggregate := &qrysmpb.AggregateAttestationAndProof{
		Aggregate: &qrysmpb.Attestation{
			AggregationBits: bitfield.Bitlist{0x03}, // one participant
			Data:            att,
			Signatures:      [][]byte{fill(fieldparams.MLDSA87SignatureLength, 0x31)},
		},
		SelectionProof: fill(fieldparams.MLDSA87SignatureLength, 0x32),
	}
	exit := &qrysmpb.VoluntaryExit{Epoch: 1}
	exitSlot, err := slots.EpochStart(exit.Epoch)
	if err != nil {
		return nil, err
	}
	syncRoot := primitives.SSZBytes(fill(32, 0x41))
	selection := &qrysmpb.SyncAggregatorSelectionData{Slot: slot}
	// The contribution's bitvector has the network's subcommittee size.
	bits := make([]byte, cfg.SyncCommitteeSize/cfg.SyncCommitteeSubnetCount/8)
	bits[0] = 0x01
	contribution := &qrysmpb.ContributionAndProof{
		Contribution: &qrysmpb.SyncCommitteeContribution{
			Slot:            slot,
			BlockRoot:       fill(32, 0x42),
			AggregationBits: bits,
			Signatures:      [][]byte{fill(fieldparams.MLDSA87SignatureLength, 0x43)},
		},
		SelectionProof: fill(fieldparams.MLDSA87SignatureLength, 0x44),
	}
	contributionRoot, err := contributionHashRoot(contribution)
	if err != nil {
		return nil, err
	}
	registration := &qrysmpb.ValidatorRegistrationV1{
		FeeRecipient: fill(fieldparams.FeeRecipientLength, 0x51),
		GasLimit:     30_000_000,
		Timestamp:    genesisTime,
		Pubkey:       pub,
	}
	aggSlot := primitives.SSZUint64(slot)

	fork := &qrysmpb.Fork{PreviousVersion: cfg.GenesisForkVersion, CurrentVersion: cfg.GenesisForkVersion}
	cases := []struct {
		oneof  string
		typ    string
		req    *validatorpb.SignRequest // Object and SigningSlot
		root   fssz.HashRoot
		domain [4]byte
		epoch  primitives.Epoch
	}{
		{"block_zond", web3signerv1.TypeBlockV2,
			&validatorpb.SignRequest{Object: &validatorpb.SignRequest_BlockZond{BlockZond: block}, SigningSlot: block.Slot},
			block, cfg.DomainBeaconProposer, slots.ToEpoch(block.Slot)},
		{"blinded_block_zond", web3signerv1.TypeBlockV2,
			&validatorpb.SignRequest{Object: &validatorpb.SignRequest_BlindedBlockZond{BlindedBlockZond: blinded}, SigningSlot: blinded.Slot},
			blinded, cfg.DomainBeaconProposer, slots.ToEpoch(blinded.Slot)},
		{"attestation_data", web3signerv1.TypeAttestation,
			&validatorpb.SignRequest{Object: &validatorpb.SignRequest_AttestationData{AttestationData: att}, SigningSlot: att.Slot},
			att, cfg.DomainBeaconAttester, att.Target.Epoch},
		{"aggregate_attestation_and_proof", web3signerv1.TypeAggregateAndProof,
			&validatorpb.SignRequest{Object: &validatorpb.SignRequest_AggregateAttestationAndProof{AggregateAttestationAndProof: aggregate}, SigningSlot: att.Slot},
			aggregate, cfg.DomainAggregateAndProof, slots.ToEpoch(att.Slot)},
		{"slot", web3signerv1.TypeAggregationSlot,
			&validatorpb.SignRequest{Object: &validatorpb.SignRequest_Slot{Slot: slot}, SigningSlot: slot},
			&aggSlot, cfg.DomainSelectionProof, slots.ToEpoch(slot)},
		{"exit", web3signerv1.TypeVoluntaryExit,
			&validatorpb.SignRequest{Object: &validatorpb.SignRequest_Exit{Exit: exit}, SigningSlot: exitSlot},
			exit, cfg.DomainVoluntaryExit, exit.Epoch},
		{"sync_message_block_root", web3signerv1.TypeSyncCommitteeMessage,
			&validatorpb.SignRequest{Object: &validatorpb.SignRequest_SyncMessageBlockRoot{SyncMessageBlockRoot: syncRoot}, SigningSlot: slot},
			&syncRoot, cfg.DomainSyncCommittee, slots.ToEpoch(slot)},
		{"sync_aggregator_selection_data", web3signerv1.TypeSyncCommitteeSelectionProof,
			&validatorpb.SignRequest{Object: &validatorpb.SignRequest_SyncAggregatorSelectionData{SyncAggregatorSelectionData: selection}, SigningSlot: slot},
			selection, cfg.DomainSyncCommitteeSelectionProof, slots.ToEpoch(slot)},
		{"contribution_and_proof", web3signerv1.TypeSyncCommitteeContributionAndProof,
			&validatorpb.SignRequest{Object: &validatorpb.SignRequest_ContributionAndProof{ContributionAndProof: contribution}, SigningSlot: slot},
			contributionRoot, cfg.DomainContributionAndProof, slots.ToEpoch(slot)},
		{"registration", web3signerv1.TypeValidatorRegistration,
			&validatorpb.SignRequest{Object: &validatorpb.SignRequest_Registration{Registration: registration}},
			registration, cfg.DomainApplicationBuilder, 0},
	}

	out := make([]signCase, 0, len(cases))
	for _, c := range cases {
		var d []byte
		if c.typ == web3signerv1.TypeValidatorRegistration {
			d, err = signing.ComputeDomain(c.domain, nil, nil)
		} else {
			d, err = signing.Domain(fork, c.epoch, c.domain, gvr[:])
		}
		if err != nil {
			return nil, fmt.Errorf("%s: domain: %w", c.oneof, err)
		}
		root, err := signing.ComputeSigningRoot(c.root, d)
		if err != nil {
			return nil, fmt.Errorf("%s: signing root: %w", c.oneof, err)
		}
		c.req.PublicKey = pub
		c.req.SigningRoot = root[:]
		c.req.SignatureDomain = d
		out = append(out, signCase{oneof: c.oneof, typ: c.typ, req: c.req})
	}
	return out, nil
}

// contributionHashRoot returns p for hashing, or a copy whose bitvector is
// padded to the length of qrysm's generated SSZ code, which is the mainnet
// one. A minimal-preset bitvector padded with zeros has the same root, since
// both fit in one chunk; the golden vectors use the same fallback (G2 §8.3).
func contributionHashRoot(p *qrysmpb.ContributionAndProof) (fssz.HashRoot, error) {
	bits := p.Contribution.AggregationBits
	if len(bits) == fieldparams.SyncCommitteeAggregationBytesLength {
		return p, nil
	}
	if len(bits) > fieldparams.SyncCommitteeAggregationBytesLength {
		return nil, fmt.Errorf("contribution bitvector of %d bytes", len(bits))
	}
	padded := make([]byte, fieldparams.SyncCommitteeAggregationBytesLength)
	copy(padded, bits)
	c := p.Contribution
	return &qrysmpb.ContributionAndProof{
		AggregatorIndex: p.AggregatorIndex,
		Contribution: &qrysmpb.SyncCommitteeContribution{
			Slot:              c.Slot,
			BlockRoot:         c.BlockRoot,
			SubcommitteeIndex: c.SubcommitteeIndex,
			AggregationBits:   padded,
			Signatures:        c.Signatures,
		},
		SelectionProof: p.SelectionProof,
	}, nil
}

func fill(n int, b byte) []byte { return bytes.Repeat([]byte{b}, n) }
