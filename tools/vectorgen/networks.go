// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"

	"github.com/theQRL/qrysm/beacon-chain/core/blocks"
	"github.com/theQRL/qrysm/beacon-chain/core/helpers"
	"github.com/theQRL/qrysm/beacon-chain/state"
	statenative "github.com/theQRL/qrysm/beacon-chain/state/state-native"
	"github.com/theQRL/qrysm/beacon-chain/state/stateutil"
	fieldparams "github.com/theQRL/qrysm/config/fieldparams"
	"github.com/theQRL/qrysm/config/params"
	"github.com/theQRL/qrysm/container/trie"
	"github.com/theQRL/qrysm/encoding/bytesutil"
	qrysmpb "github.com/theQRL/qrysm/proto/qrysm/v1alpha1"
	"github.com/theQRL/qrysm/runtime/interop"
	"github.com/theQRL/qrysm/runtime/version"
)

// genesisTime is the genesis time every fixture that needs one uses, the
// value of the contract's worked examples.
const genesisTime = 1760000000

// netDef is a network qrysm defines in code. The signer embeds all four; the
// two end-to-end networks also carry the signing fixtures, one per preset.
type netDef struct {
	name   string // the signer's --network name
	file   string // under internal/network/embedded/
	config func() *params.BeaconChainConfig
	// preset is the fixture preset this network carries, or "".
	preset string
}

var networks = []netDef{
	{name: "minimal", file: "minimal.yaml", config: params.MinimalSpecConfig},
	{name: "end-to-end", file: "end-to-end.yaml", config: params.E2ETestConfig, preset: "minimal"},
	{name: "end-to-end-mainnet", file: "end-to-end-mainnet.yaml", config: params.E2EMainnetTestConfig, preset: "mainnet"},
	{name: "interop", file: "interop.yaml", config: params.InteropConfig},
}

// chain is a fixture network: the configuration plus its genesis validators
// root, which is the root of qrysm's interop genesis with the network's
// MIN_GENESIS_ACTIVE_VALIDATOR_COUNT deterministic keys, as the qrysm e2e
// builds it.
type chain struct {
	def    netDef
	cfg    *params.BeaconChainConfig
	gvr    [32]byte
	preset string
	// subcommitteeBits is SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT.
	subcommitteeBits uint64
}

func (c *chain) forkVersion() []byte { return c.cfg.GenesisForkVersion }

// fork is the single-fork schedule {G, G, 0} qrysm's MapForkInfo sends.
func (c *chain) fork() *qrysmpb.Fork {
	return &qrysmpb.Fork{PreviousVersion: c.forkVersion(), CurrentVersion: c.forkVersion(), Epoch: 0}
}

// recordNetwork is the per-record network object (testdata/vectors/README.md).
func (c *chain) recordNetwork() obj {
	return obj{}.
		set("config_name", c.cfg.ConfigName).
		set("genesis_fork_version", hx(c.forkVersion())).
		set("gvr", hx(c.gvr[:])).
		set("slots_per_epoch", u64s(uint64(c.cfg.SlotsPerEpoch)))
}

// forkInfo is the request's fork_info.
func (c *chain) forkInfo() obj {
	return obj{}.
		set("fork", obj{}.
			set("previous_version", hx(c.forkVersion())).
			set("current_version", hx(c.forkVersion())).
			set("epoch", "0")).
		set("genesis_validators_root", hx(c.gvr[:]))
}

// withConfig runs fn with cfg as qrysm's active configuration.
func withConfig[T any](cfg *params.BeaconChainConfig, fn func() (T, error)) (T, error) {
	undo, err := params.SetActiveWithUndo(cfg)
	if err != nil {
		var zero T
		return zero, err
	}
	defer func() { _ = undo() }()
	return fn()
}

// loadChain builds the fixture network of def.
func loadChain(def netDef) (*chain, error) {
	cfg := def.config()
	gvr, err := withConfig(cfg, func() ([32]byte, error) {
		return genesisValidatorsRoot(cfg.MinGenesisActiveValidatorCount)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", def.name, err)
	}
	return &chain{
		def:              def,
		cfg:              cfg,
		gvr:              gvr,
		preset:           def.preset,
		subcommitteeBits: cfg.SyncCommitteeSize / cfg.SyncCommitteeSubnetCount,
	}, nil
}

// genesisValidatorsRoot returns the GVR of the interop genesis with n
// validators under the active configuration. It runs the deposit part of
// qrysm's NewPreminedGenesis (interop keys, deposit data, pre-genesis deposit
// processing) and hashes the validator registry; the rest of that function
// does not touch the validators. It works for both presets in qrysm's
// mainnet build, whereas the full genesis state needs the build's preset.
func genesisValidatorsRoot(n uint64) ([32]byte, error) {
	ctx := context.Background()
	prv, pub, err := interop.DeterministicallyGenerateKeys(0, n)
	if err != nil {
		return [32]byte{}, err
	}
	dds, roots, err := interop.DepositDataFromKeys(prv, pub)
	if err != nil {
		return [32]byte{}, err
	}
	t, err := trie.GenerateTrieFromItems(roots, params.BeaconConfig().DepositContractTreeDepth)
	if err != nil {
		return [32]byte{}, err
	}
	deposits, err := interop.GenerateDepositsFromData(dds, t)
	if err != nil {
		return [32]byte{}, err
	}
	st, err := emptyGenesisState()
	if err != nil {
		return [32]byte{}, err
	}
	empty, err := trie.NewTrie(params.BeaconConfig().DepositContractTreeDepth)
	if err != nil {
		return [32]byte{}, err
	}
	emptyRoot, err := empty.HashTreeRoot()
	if err != nil {
		return [32]byte{}, err
	}
	if err := st.SetExecutionData(&qrysmpb.ExecutionData{DepositRoot: emptyRoot[:], BlockHash: make([]byte, 32)}); err != nil {
		return [32]byte{}, err
	}
	if _, err := helpers.UpdateGenesisExecutionData(st, deposits, st.ExecutionData()); err != nil {
		return [32]byte{}, err
	}
	if _, err := blocks.ProcessPreGenesisDeposits(ctx, st, deposits); err != nil {
		return [32]byte{}, err
	}
	if uint64(st.NumValidators()) != n {
		return [32]byte{}, fmt.Errorf("genesis has %d validators, want %d", st.NumValidators(), n)
	}
	return stateutil.ValidatorRegistryRoot(st.Validators())
}

// emptyGenesisState is the empty Zond state NewPreminedGenesis starts from.
func emptyGenesisState() (state.BeaconState, error) {
	roots := func(n int) [][]byte {
		out := make([][]byte, n)
		for i := range out {
			out[i] = make([]byte, 32)
		}
		return out
	}
	st, err := statenative.InitializeFromProtoZond(&qrysmpb.BeaconStateZond{
		BlockRoots:       roots(fieldparams.BlockRootsLength),
		StateRoots:       roots(fieldparams.StateRootsLength),
		RandaoMixes:      roots(fieldparams.RandaoMixesLength),
		Balances:         []uint64{},
		InactivityScores: []uint64{},
		Validators:       []*qrysmpb.Validator{},
	})
	if err != nil {
		return nil, err
	}
	if err := st.SetExecutionDataVotes([]*qrysmpb.ExecutionData{}); err != nil {
		return nil, err
	}
	return st, nil
}

// fullGenesis builds qrysm's complete e2e genesis state for a mainnet-preset
// network, the same call the qrysm e2e makes. It cross-checks
// genesisValidatorsRoot and provides the genesis.ssz prefix fixture and the
// parent state of the real-block fixtures.
func fullGenesis(c *chain) (state.BeaconState, error) {
	if c.preset != fieldparams.Preset {
		return nil, fmt.Errorf("%s: the full genesis needs a %s build", c.def.name, c.preset)
	}
	return withConfig(c.cfg, func() (state.BeaconState, error) {
		gb := interop.GqrlTestnetGenesis(genesisTime, c.cfg).ToBlock()
		st, err := interop.NewPreminedGenesis(context.Background(), genesisTime,
			c.cfg.MinGenesisActiveValidatorCount, version.Zond, gb)
		if err != nil {
			return nil, err
		}
		if got := bytesutil.ToBytes32(st.GenesisValidatorsRoot()); got != c.gvr {
			return nil, fmt.Errorf("%s: full genesis GVR %#x differs from the deposit-only GVR %#x", c.def.name, got, c.gvr)
		}
		return st, nil
	})
}

// yamlHeader prefixes the generated network files: the signer's header for
// a new file (PROVENANCE.md), and where the values come from.
const yamlHeader = `# Copyright 2026 The go-remotesigner Authors.
# SPDX-License-Identifier: Apache-2.0
#
# Generated by tools/vectorgen (make vectors) with params.ConfigToYaml(params.%s())
# at the qrysm commit pinned in tools/vectorgen/go.mod. Do not edit: CI regenerates
# this file and fails on any difference. Keys absent here inherit from PRESET_BASE.

`

// configFuncName names the qrysm function that builds def's configuration.
func configFuncName(def netDef) string {
	switch def.name {
	case "minimal":
		return "MinimalSpecConfig"
	case "end-to-end":
		return "E2ETestConfig"
	case "end-to-end-mainnet":
		return "E2EMainnetTestConfig"
	case "interop":
		return "InteropConfig"
	}
	panic("unknown network " + def.name)
}

// genNetworks writes the embedded network YAMLs, networks.json and the
// genesis-state prefix fixture.
func genNetworks(g *generator) error {
	var list []obj
	for _, def := range networks {
		cfg := def.config()
		y := fmt.Sprintf(yamlHeader, configFuncName(def)) + string(params.ConfigToYaml(cfg)) + "\n"
		if err := writeFile(g.repo, "internal/network/embedded/"+def.file, []byte(y)); err != nil {
			return err
		}
		e := obj{}.
			set("name", def.name).
			set("config_name", cfg.ConfigName).
			set("preset_base", cfg.PresetBase).
			set("genesis_fork_version", hx(cfg.GenesisForkVersion)).
			set("seconds_per_slot", u64s(cfg.SecondsPerSlot)).
			set("slots_per_epoch", u64s(uint64(cfg.SlotsPerEpoch))).
			set("deposit_chain_id", u64s(cfg.DepositChainID)).
			set("deposit_network_id", u64s(cfg.DepositNetworkID)).
			set("sync_committee_size", u64s(cfg.SyncCommitteeSize)).
			set("sync_committee_subnet_count", u64s(cfg.SyncCommitteeSubnetCount)).
			set("min_genesis_active_validator_count", u64s(cfg.MinGenesisActiveValidatorCount))
		if c, ok := g.chainByName(def.name); ok {
			e = e.set("interop_genesis_validators_root", hx(c.gvr[:]))
		}
		list = append(list, e)
	}
	if err := writeJSON(g.vectors, "networks.json", obj{}.
		set("description", g.description("The networks qrysm defines in code, as the embedded network YAMLs carry them. "+
			"interop_genesis_validators_root is the root of qrysm's interop genesis with min_genesis_active_validator_count "+
			"deterministic keys, which is what the qrysm e2e runs.")).
		set("generator", g.info).
		set("networks", list)); err != nil {
		return err
	}
	return genGenesisPrefix(g)
}

// genGenesisPrefix writes the first bytes of qrysm's SSZ-encoded genesis
// state for the end-to-end-mainnet network, which the signer's
// --network-genesis-state reader parses.
func genGenesisPrefix(g *generator) error {
	c := g.mainnet
	st, err := g.genesisState()
	if err != nil {
		return err
	}
	enc, err := st.MarshalSSZ()
	if err != nil {
		return err
	}
	const prefix = 128
	return writeJSON(g.vectors, "networks/genesis-state-prefix.json", obj{}.
		set("description", g.description("The first 128 bytes of qrysm's SSZ-encoded interop genesis state for "+
			c.def.name+" (genesis_time "+u64s(genesisTime)+"), and the fields the signer reads from them.")).
		set("generator", g.info).
		set("network", c.def.name).
		set("ssz_prefix_hex", hx(enc[:prefix])).
		set("ssz_length", len(enc)).
		set("genesis_time", u64s(st.GenesisTime())).
		set("genesis_validators_root", hx(st.GenesisValidatorsRoot())).
		set("slot", u64s(uint64(st.Slot()))).
		set("fork", obj{}.
			set("previous_version", hx(st.Fork().PreviousVersion)).
			set("current_version", hx(st.Fork().CurrentVersion)).
			set("epoch", u64s(uint64(st.Fork().Epoch)))))
}
