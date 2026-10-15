// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"errors"
	"strings"
	"testing"
)

// e2eComponentYAML has the shape qrysm's e2e component writes: ConfigToYaml
// output (more keys than the signer reads) with DEPOSIT_CONTRACT_ADDRESS
// appended a second time.
const e2eComponentYAML = `PRESET_BASE: 'minimal'
CONFIG_NAME: 'end-to-end'
MIN_GENESIS_ACTIVE_VALIDATOR_COUNT: 256
GENESIS_DELAY: 10
GENESIS_FORK_VERSION: 0x000000fd
SECONDS_PER_SLOT: 10
SLOTS_PER_EPOCH: 6
DEPOSIT_CHAIN_ID: 1337
DEPOSIT_NETWORK_ID: 1337
DEPOSIT_CONTRACT_ADDRESS: Q4242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242
DEPOSIT_CONTRACT_ADDRESS: Q1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
`

// metadataYAML has the shape of a go-qrl-metadata config.yml: quoted values,
// slot timing left to the preset.
const metadataYAML = `CONFIG_NAME: 'testnet'
PRESET_BASE: 'mainnet'
GENESIS_FORK_VERSION: '0x20000089'
DEPOSIT_CHAIN_ID: 1337
DEPOSIT_NETWORK_ID: 1337
DEPOSIT_CONTRACT_ADDRESS: 'Q4242424242424242424242424242424242424242'
`

func TestParseConfig(t *testing.T) {
	mainnet, minimal := presets[PresetMainnet], presets[PresetMinimal]
	with := func(c Config, f func(*Config)) Config { f(&c); return c }

	tests := []struct {
		name string
		yaml string
		want Config
	}{
		{"qrysm e2e component output", e2eComponentYAML, Config{
			ConfigName: "end-to-end", PresetBase: PresetMinimal, GenesisForkVersion: [4]byte{0, 0, 0, 0xfd},
			SecondsPerSlot: 10, SlotsPerEpoch: 6, DepositChainID: 1337, DepositNetworkID: 1337,
			SyncCommitteeSize: 16, SyncCommitteeSubnetCount: 1,
		}},
		{"go-qrl-metadata config.yml inherits slot timing", metadataYAML, with(mainnet, func(c *Config) {
			c.ConfigName = "testnet"
			c.GenesisForkVersion = [4]byte{0x20, 0, 0, 0x89}
			c.DepositChainID, c.DepositNetworkID = 1337, 1337
		})},
		{"preset only, default name", "PRESET_BASE: minimal\n", with(minimal, func(c *Config) {
			c.ConfigName = "devnet"
		})},
		{"duplicate keys: last wins", "PRESET_BASE: mainnet\nSECONDS_PER_SLOT: 12\nSECONDS_PER_SLOT: 30\nPRESET_BASE: minimal\n",
			with(minimal, func(c *Config) { c.ConfigName = "devnet"; c.SecondsPerSlot = 30 })},
		{"unknown and legacy keys are ignored", "PRESET_BASE: mainnet\nALTAIR_FORK_VERSION: 0x20000090\nSHARDS: [1, 2]\nNESTED: {a: 1}\n",
			with(mainnet, func(c *Config) { c.ConfigName = "devnet" })},
		{"sync committee override", "PRESET_BASE: mainnet\nSYNC_COMMITTEE_SIZE: 512\nSYNC_COMMITTEE_SUBNET_COUNT: 4\n",
			with(mainnet, func(c *Config) { c.ConfigName = "devnet"; c.SyncCommitteeSize = 512; c.SyncCommitteeSubnetCount = 4 })},
		{"alias value", "PRESET_BASE: mainnet\nX: &slot 15\nSECONDS_PER_SLOT: *slot\n",
			with(mainnet, func(c *Config) { c.ConfigName = "devnet"; c.SecondsPerSlot = 15 })},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseConfig([]byte(tt.yaml))
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("got  %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestParseConfigErrors(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string // substring of the error
	}{
		{"empty", "", "mapping"},
		{"not a mapping", "- a\n- b\n", "mapping"},
		{"invalid YAML", "PRESET_BASE: [\n", "invalid config"},
		{"missing PRESET_BASE", "CONFIG_NAME: x\n", "PRESET_BASE is missing"},
		{"unknown preset", "PRESET_BASE: interop\n", "PRESET_BASE \"interop\""},
		{"fork version without 0x", "PRESET_BASE: mainnet\nGENESIS_FORK_VERSION: 000000fd\n", "GENESIS_FORK_VERSION"},
		{"short fork version", "PRESET_BASE: mainnet\nGENESIS_FORK_VERSION: 0xfd\n", "GENESIS_FORK_VERSION"},
		{"long fork version", "PRESET_BASE: mainnet\nGENESIS_FORK_VERSION: 0x000000fd00\n", "GENESIS_FORK_VERSION"},
		{"non-hex fork version", "PRESET_BASE: mainnet\nGENESIS_FORK_VERSION: 0x000000zz\n", "GENESIS_FORK_VERSION"},
		{"negative integer", "PRESET_BASE: mainnet\nSECONDS_PER_SLOT: -1\n", "SECONDS_PER_SLOT"},
		{"hex integer", "PRESET_BASE: mainnet\nSLOTS_PER_EPOCH: 0x10\n", "SLOTS_PER_EPOCH"},
		{"overflowing integer", "PRESET_BASE: mainnet\nDEPOSIT_CHAIN_ID: 18446744073709551616\n", "DEPOSIT_CHAIN_ID"},
		{"zero slot time", "PRESET_BASE: mainnet\nSECONDS_PER_SLOT: 0\n", "SECONDS_PER_SLOT must be positive"},
		{"zero slots per epoch", "PRESET_BASE: mainnet\nSLOTS_PER_EPOCH: 0\n", "SLOTS_PER_EPOCH must be positive"},
		{"zero subnet count", "PRESET_BASE: mainnet\nSYNC_COMMITTEE_SUBNET_COUNT: 0\n", "SUBNET_COUNT must be positive"},
		{"zero committee", "PRESET_BASE: mainnet\nSYNC_COMMITTEE_SIZE: 0\n", "SYNC_COMMITTEE_SIZE must be positive"},
		{"committee not divisible", "PRESET_BASE: mainnet\nSYNC_COMMITTEE_SUBNET_COUNT: 3\n", "multiple"},
		{"empty config name", "PRESET_BASE: mainnet\nCONFIG_NAME: ''\n", "CONFIG_NAME"},
		{"list for a known key", "PRESET_BASE: mainnet\nSECONDS_PER_SLOT: [1]\n", "want a scalar"},
		{"non-scalar key", "PRESET_BASE: mainnet\n? [a, b]\n: 1\n", "non-scalar key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseConfig([]byte(tt.yaml))
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("err = %v, want ErrInvalidConfig", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %q, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestSyncSubcommitteeSize(t *testing.T) {
	tests := []struct {
		preset string
		want   uint64
	}{
		{PresetMainnet, 128}, // 16-byte contribution bitvector
		{PresetMinimal, 16},  // 2-byte contribution bitvector
	}
	for _, tt := range tests {
		c := presets[tt.preset]
		if got := c.SyncSubcommitteeSize(); got != tt.want {
			t.Errorf("%s: SyncSubcommitteeSize = %d, want %d", tt.preset, got, tt.want)
		}
	}
}

func FuzzParseConfig(f *testing.F) {
	for _, s := range []string{e2eComponentYAML, metadataYAML, "PRESET_BASE: minimal\n", "", "a: [", "PRESET_BASE: mainnet\nSECONDS_PER_SLOT: 0\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := ParseConfig(data)
		if err != nil {
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("error %v is not ErrInvalidConfig", err)
			}
			return
		}
		if c.validate() != nil || c.ConfigName == "" {
			t.Fatalf("accepted an invalid config %+v", c)
		}
		if _, ok := presets[c.PresetBase]; !ok {
			t.Fatalf("accepted preset %q", c.PresetBase)
		}
	})
}
