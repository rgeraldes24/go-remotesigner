// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ErrInvalidConfig reports a network YAML that cannot be used.
var ErrInvalidConfig = errors.New("network: invalid config")

// Preset names accepted in PRESET_BASE.
const (
	PresetMainnet = "mainnet"
	PresetMinimal = "minimal"
)

// defaultConfigName is the name of a file network without CONFIG_NAME.
const defaultConfigName = "devnet"

// Config is the part of a qrysm chain configuration the signer uses.
type Config struct {
	ConfigName               string  // CONFIG_NAME
	PresetBase               string  // PRESET_BASE: PresetMainnet or PresetMinimal
	GenesisForkVersion       [4]byte // GENESIS_FORK_VERSION
	SecondsPerSlot           uint64  // SECONDS_PER_SLOT
	SlotsPerEpoch            uint64  // SLOTS_PER_EPOCH
	DepositChainID           uint64  // DEPOSIT_CHAIN_ID
	DepositNetworkID         uint64  // DEPOSIT_NETWORK_ID
	SyncCommitteeSize        uint64  // SYNC_COMMITTEE_SIZE
	SyncCommitteeSubnetCount uint64  // SYNC_COMMITTEE_SUBNET_COUNT
}

// SyncSubcommitteeSize is the bit length of a sync-committee contribution's
// aggregation bits, SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT.
func (c *Config) SyncSubcommitteeSize() uint64 {
	return c.SyncCommitteeSize / c.SyncCommitteeSubnetCount
}

// presets are the bases a YAML inherits unspecified values from, as qrysm's
// loader does. The values are qrysm's mainnet and minimal configurations.
var presets = map[string]Config{
	PresetMainnet: {
		ConfigName:               "mainnet",
		PresetBase:               PresetMainnet,
		GenesisForkVersion:       [4]byte{0x00, 0x00, 0x00, 0x00},
		SecondsPerSlot:           60,
		SlotsPerEpoch:            128,
		DepositChainID:           1,
		DepositNetworkID:         1,
		SyncCommitteeSize:        128,
		SyncCommitteeSubnetCount: 1,
	},
	PresetMinimal: {
		ConfigName:               "minimal",
		PresetBase:               PresetMinimal,
		GenesisForkVersion:       [4]byte{0x00, 0x00, 0x00, 0x01},
		SecondsPerSlot:           6,
		SlotsPerEpoch:            8,
		DepositChainID:           5,
		DepositNetworkID:         5,
		SyncCommitteeSize:        16,
		SyncCommitteeSubnetCount: 1,
	},
}

// field binds a YAML key to the Config field it sets.
type field struct {
	key string
	set func(c *Config, value string) error
}

var fields = []field{
	{"CONFIG_NAME", func(c *Config, v string) error {
		if v == "" {
			return errors.New("empty")
		}
		c.ConfigName = v
		return nil
	}},
	{"GENESIS_FORK_VERSION", func(c *Config, v string) error { return parseVersion(&c.GenesisForkVersion, v) }},
	{"SECONDS_PER_SLOT", uintField(func(c *Config) *uint64 { return &c.SecondsPerSlot })},
	{"SLOTS_PER_EPOCH", uintField(func(c *Config) *uint64 { return &c.SlotsPerEpoch })},
	{"DEPOSIT_CHAIN_ID", uintField(func(c *Config) *uint64 { return &c.DepositChainID })},
	{"DEPOSIT_NETWORK_ID", uintField(func(c *Config) *uint64 { return &c.DepositNetworkID })},
	{"SYNC_COMMITTEE_SIZE", uintField(func(c *Config) *uint64 { return &c.SyncCommitteeSize })},
	{"SYNC_COMMITTEE_SUBNET_COUNT", uintField(func(c *Config) *uint64 { return &c.SyncCommitteeSubnetCount })},
}

func uintField(ptr func(*Config) *uint64) func(*Config, string) error {
	return func(c *Config, v string) error {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return errors.New("not a decimal unsigned integer")
		}
		*ptr(c) = n
		return nil
	}
}

func parseVersion(dst *[4]byte, v string) error {
	h, ok := strings.CutPrefix(v, "0x")
	if !ok || len(h) != 2*len(dst) {
		return errors.New("want 0x followed by 8 hex digits")
	}
	if _, err := hex.Decode(dst[:], []byte(h)); err != nil {
		return errors.New("want 0x followed by 8 hex digits")
	}
	return nil
}

// ParseConfig parses a qrysm-format network YAML: the output of qrysm's
// ConfigToYaml or a go-qrl-metadata config.yml.
//
//   - PRESET_BASE is required and names the preset (mainnet or minimal) that
//     every unspecified value is inherited from.
//   - Unknown keys are ignored, so files carrying more keys than the signer
//     uses parse.
//   - A key that appears more than once takes its last value. qrysm's e2e
//     component writes DEPOSIT_CONTRACT_ADDRESS twice, and a plain YAML decode
//     would reject that.
//   - CONFIG_NAME defaults to "devnet", as in qrysm.
func ParseConfig(data []byte) (Config, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return Config{}, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return Config{}, fmt.Errorf("%w: want a YAML mapping of KEY: value", ErrInvalidConfig)
	}

	values := map[string]string{} // last occurrence wins
	m := doc.Content[0]
	for i := 0; i+1 < len(m.Content); i += 2 {
		k, v := m.Content[i], m.Content[i+1]
		if k.Kind != yaml.ScalarNode {
			return Config{}, fmt.Errorf("%w: line %d: non-scalar key", ErrInvalidConfig, k.Line)
		}
		if !known(k.Value) {
			continue
		}
		if v.Kind == yaml.AliasNode && v.Alias != nil {
			v = v.Alias
		}
		if v.Kind != yaml.ScalarNode {
			return Config{}, fmt.Errorf("%w: %s (line %d): want a scalar value", ErrInvalidConfig, k.Value, k.Line)
		}
		values[k.Value] = v.Value
	}

	base, ok := values["PRESET_BASE"]
	if !ok {
		return Config{}, fmt.Errorf("%w: PRESET_BASE is missing", ErrInvalidConfig)
	}
	cfg, ok := presets[base]
	if !ok {
		return Config{}, fmt.Errorf("%w: PRESET_BASE %q is not %q or %q", ErrInvalidConfig, base, PresetMainnet, PresetMinimal)
	}
	cfg.ConfigName = defaultConfigName
	for _, f := range fields {
		v, ok := values[f.key]
		if !ok {
			continue
		}
		if err := f.set(&cfg, v); err != nil {
			return Config{}, fmt.Errorf("%w: %s %q: %v", ErrInvalidConfig, f.key, v, err)
		}
	}
	if err := cfg.validate(); err != nil {
		return Config{}, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	return cfg, nil
}

func known(key string) bool {
	if key == "PRESET_BASE" {
		return true
	}
	for _, f := range fields {
		if f.key == key {
			return true
		}
	}
	return false
}

func (c *Config) validate() error {
	switch {
	case c.SecondsPerSlot == 0:
		return errors.New("SECONDS_PER_SLOT must be positive")
	case c.SlotsPerEpoch == 0:
		return errors.New("SLOTS_PER_EPOCH must be positive")
	case c.SyncCommitteeSize == 0:
		return errors.New("SYNC_COMMITTEE_SIZE must be positive")
	case c.SyncCommitteeSubnetCount == 0:
		return errors.New("SYNC_COMMITTEE_SUBNET_COUNT must be positive")
	case c.SyncCommitteeSize%c.SyncCommitteeSubnetCount != 0:
		return errors.New("SYNC_COMMITTEE_SIZE must be a multiple of SYNC_COMMITTEE_SUBNET_COUNT")
	}
	return nil
}
