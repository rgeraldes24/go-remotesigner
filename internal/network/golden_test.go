// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/vectors"
)

// TestGoldenNetworks checks every embedded network against the values
// qrysm's configuration has at the pinned commit (testdata/vectors
// networks.json). The embedded YAMLs are generated from the same commit, so
// this also checks the loader's preset inheritance.
func TestGoldenNetworks(t *testing.T) {
	golden := vectors.Networks(t)
	var names []string
	for _, g := range golden {
		names = append(names, g.Name)
		t.Run(g.Name, func(t *testing.T) {
			n, err := Load(Sources{Network: g.Name})
			if err != nil {
				t.Fatal(err)
			}
			c := n.Config
			checks := []struct {
				field string
				got   uint64
				want  string
			}{
				{"SECONDS_PER_SLOT", c.SecondsPerSlot, g.SecondsPerSlot},
				{"SLOTS_PER_EPOCH", c.SlotsPerEpoch, g.SlotsPerEpoch},
				{"DEPOSIT_CHAIN_ID", c.DepositChainID, g.DepositChainID},
				{"DEPOSIT_NETWORK_ID", c.DepositNetworkID, g.DepositNetworkID},
				{"SYNC_COMMITTEE_SIZE", c.SyncCommitteeSize, g.SyncCommitteeSize},
				{"SYNC_COMMITTEE_SUBNET_COUNT", c.SyncCommitteeSubnetCount, g.SyncCommitteeSubnetCount},
			}
			for _, ch := range checks {
				if ch.got != vectors.U64(t, ch.want) {
					t.Errorf("%s = %d, want %s", ch.field, ch.got, ch.want)
				}
			}
			if c.ConfigName != g.ConfigName || c.PresetBase != g.PresetBase {
				t.Errorf("CONFIG_NAME %q PRESET_BASE %q, want %q %q", c.ConfigName, c.PresetBase, g.ConfigName, g.PresetBase)
			}
			if c.GenesisForkVersion != [4]byte(vectors.Hex(t, g.GenesisForkVersion)) {
				t.Errorf("GENESIS_FORK_VERSION %#x, want %s", c.GenesisForkVersion, g.GenesisForkVersion)
			}
		})
	}
	slices.Sort(names)
	var builtins []string
	for _, n := range builtin {
		builtins = append(builtins, n.name)
	}
	slices.Sort(builtins)
	if !slices.Equal(names, builtins) {
		t.Errorf("golden networks %v, built-in %v", names, builtins)
	}
}

// TestGoldenGenesisStatePrefix reads the first bytes of qrysm's own SSZ
// genesis state, as a --network-genesis-state file, and binds the network
// it was built for.
func TestGoldenGenesisStatePrefix(t *testing.T) {
	var g vectors.GenesisPrefix
	vectors.Load(t, "networks/genesis-state-prefix.json", &g)
	raw := vectors.Hex(t, g.SSZPrefixHex)
	p, err := ParseGenesisPrefix(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := GenesisPrefix{
		GenesisTime:           vectors.U64(t, g.GenesisTime),
		GenesisValidatorsRoot: vectors.Hex32(t, g.GenesisValidatorsRoot),
		Slot:                  vectors.U64(t, g.Slot),
		Fork: Fork{
			PreviousVersion: [4]byte(vectors.Hex(t, g.Fork.PreviousVersion)),
			CurrentVersion:  [4]byte(vectors.Hex(t, g.Fork.CurrentVersion)),
			Epoch:           vectors.U64(t, g.Fork.Epoch),
		},
	}
	if p != want {
		t.Fatalf("prefix = %+v, want %+v", p, want)
	}

	path := filepath.Join(t.TempDir(), "genesis.ssz")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := Load(Sources{Network: g.Network, GenesisStateFile: path})
	if err != nil {
		t.Fatal(err)
	}
	if n.GenesisValidatorsRoot != want.GenesisValidatorsRoot || n.GenesisTime != want.GenesisTime ||
		n.GVRSource != SourceGenesisState || n.GenesisTimeSource != SourceGenesisState {
		t.Fatalf("bound GVR %#x (%v), genesis time %d (%v)", n.GenesisValidatorsRoot, n.GVRSource, n.GenesisTime, n.GenesisTimeSource)
	}
	for _, info := range vectors.Networks(t) {
		if info.Name == g.Network && info.InteropGenesisValidatorsRoot != g.GenesisValidatorsRoot {
			t.Errorf("networks.json GVR %s differs from the genesis state's %s", info.InteropGenesisValidatorsRoot, g.GenesisValidatorsRoot)
		}
	}
}
