// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/theQRL/qrysm/beacon-chain/state"
	"github.com/theQRL/qrysm/consensus-types/blocks"
	"github.com/theQRL/qrysm/consensus-types/interfaces"
	"github.com/theQRL/qrysm/crypto/ml_dsa_87"
	qrysmpb "github.com/theQRL/qrysm/proto/qrysm/v1alpha1"
	"github.com/theQRL/qrysm/runtime/interop"
	"github.com/theQRL/qrysm/testing/util"
)

// deterministicKey makes qrysm's block generator reproducible: it signs
// attestations and the block in deterministic mode instead of hedged.
type deterministicKey struct{ ml_dsa_87.MLDSA87Key }

func (k deterministicKey) Sign(msg []byte) (ml_dsa_87.Signature, error) {
	return k.SignDeterministic(msg)
}

// genesisState returns qrysm's full e2e genesis of the mainnet fixture
// network, built once.
func (g *generator) genesisState() (state.BeaconState, error) {
	if g.genesis == nil {
		st, err := fullGenesis(g.mainnet)
		if err != nil {
			return nil, err
		}
		g.genesis = st
	}
	return g.genesis.Copy(), nil
}

// realBlockCase builds a BLOCK_V2 case from a real block: qrysm's
// GenerateFullBlockZond on the end-to-end-mainnet genesis, with an attestation,
// transactions and withdrawals. The record carries the full and the blinded
// block, whose roots must both equal the header's (G2 §4.4). It needs the
// mainnet build, so the minimal preset has no such case.
func (g *generator) realBlockCase() (signCase, error) {
	c := g.mainnet
	st, err := g.genesisState()
	if err != nil {
		return signCase{}, err
	}
	type built struct {
		full    *qrysmpb.BeaconBlockZond
		blinded *qrysmpb.BlindedBeaconBlockZond
		header  *qrysmpb.BeaconBlockHeader
	}
	b, err := withConfig(c.cfg, func() (built, error) {
		prv, _, err := interop.DeterministicallyGenerateKeys(0, c.cfg.MinGenesisActiveValidatorCount)
		if err != nil {
			return built{}, err
		}
		keys := make([]ml_dsa_87.MLDSA87Key, len(prv))
		for i := range prv {
			keys[i] = deterministicKey{prv[i]}
		}
		conf := &util.BlockGenConfig{NumAttestations: 1, NumTransactions: 3}
		signed, err := util.GenerateFullBlockZond(st, keys, conf, 1)
		if err != nil {
			return built{}, err
		}
		wsb, err := blocks.NewSignedBeaconBlock(signed)
		if err != nil {
			return built{}, err
		}
		bl, err := wsb.ToBlinded()
		if err != nil {
			return built{}, err
		}
		bpb, err := bl.Block().Proto()
		if err != nil {
			return built{}, err
		}
		blinded, ok := bpb.(*qrysmpb.BlindedBeaconBlockZond)
		if !ok {
			return built{}, fmt.Errorf("blinded block is %T", bpb)
		}
		h, err := interfaces.BeaconBlockHeaderFromBlock(signed.Block)
		if err != nil {
			return built{}, err
		}
		return built{full: signed.Block, blinded: blinded, header: h}, nil
	})
	if err != nil {
		return signCase{}, fmt.Errorf("real block: %w", err)
	}
	fullRoot, err := b.full.HashTreeRoot()
	if err != nil {
		return signCase{}, err
	}
	blindedRoot, err := b.blinded.HashTreeRoot()
	if err != nil {
		return signCase{}, err
	}
	headerRoot, err := b.header.HashTreeRoot()
	if err != nil {
		return signCase{}, err
	}
	if fullRoot != headerRoot || blindedRoot != headerRoot {
		return signCase{}, fmt.Errorf("real block roots differ: full %#x blinded %#x header %#x", fullRoot, blindedRoot, headerRoot)
	}
	return signCase{
		name: "real_block",
		key:  0,
		o:    blockObject(b.header),
		block: obj{}.
			set("full_ssz_hex", hx(marshal(b.full))).
			set("full_root", hx(fullRoot[:])).
			set("blinded_ssz_hex", hx(marshal(b.blinded))).
			set("blinded_root", hx(blindedRoot[:])),
	}, nil
}
