// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	fieldparams "github.com/theQRL/qrysm/config/fieldparams"
	"github.com/theQRL/qrysm/config/params"
)

// vectors is what the contract takes from the golden vectors: the genesis
// validators root of the network's interop genesis, which the validator
// learns at chain start, and interop key 0, which the signer holds.
type vectors struct {
	gvr [32]byte
	key interopKey
}

type interopKey struct {
	pub         []byte
	commitment  [32]byte // x_L of the key's onion, as interop genesis stores it
	firstReveal [32]byte // x_{L-1}
}

// loadVectors reads networks.json and keys/interop.json from dir. The
// network entry must agree with qrysm's configuration on the fork version
// and slot timing; if it does not, the two qrysm pins have drifted apart.
func loadVectors(dir string, cfg *params.BeaconChainConfig) (*vectors, error) {
	var nets struct {
		Networks []struct {
			ConfigName         string `json:"config_name"`
			GenesisForkVersion string `json:"genesis_fork_version"`
			SecondsPerSlot     string `json:"seconds_per_slot"`
			SlotsPerEpoch      string `json:"slots_per_epoch"`
			GVR                string `json:"interop_genesis_validators_root"`
		} `json:"networks"`
	}
	if err := readJSON(filepath.Join(dir, "networks.json"), &nets); err != nil {
		return nil, err
	}
	var v vectors
	found := false
	for _, n := range nets.Networks {
		if n.ConfigName != cfg.ConfigName {
			continue
		}
		found = true
		for _, f := range []struct{ name, golden, qrysm string }{
			{"genesis_fork_version", n.GenesisForkVersion, "0x" + hex.EncodeToString(cfg.GenesisForkVersion)},
			{"seconds_per_slot", n.SecondsPerSlot, strconv.FormatUint(cfg.SecondsPerSlot, 10)},
			{"slots_per_epoch", n.SlotsPerEpoch, strconv.FormatUint(uint64(cfg.SlotsPerEpoch), 10)},
		} {
			if f.golden != f.qrysm {
				return nil, fmt.Errorf("networks.json has %s %s for %s, qrysm %s", f.name, f.golden, cfg.ConfigName, f.qrysm)
			}
		}
		if err := unhexInto(v.gvr[:], n.GVR); err != nil {
			return nil, fmt.Errorf("networks.json %s genesis validators root: %w", cfg.ConfigName, err)
		}
	}
	if !found {
		return nil, fmt.Errorf("networks.json has no network %s", cfg.ConfigName)
	}

	var keys struct {
		Keys []struct {
			Index             int    `json:"index"`
			Pubkey            string `json:"pubkey"`
			RandaoCommitment  string `json:"randao_commitment"`
			RandaoFirstReveal string `json:"randao_first_reveal"`
		} `json:"keys"`
	}
	if err := readJSON(filepath.Join(dir, "keys", "interop.json"), &keys); err != nil {
		return nil, err
	}
	if len(keys.Keys) == 0 || keys.Keys[0].Index != 0 {
		return nil, fmt.Errorf("keys/interop.json does not start with interop key 0")
	}
	k := keys.Keys[0]
	v.key.pub = make([]byte, fieldparams.MLDSA87PubkeyLength)
	for _, f := range []struct {
		dst  []byte
		name string
		hex  string
	}{
		{v.key.pub, "pubkey", k.Pubkey},
		{v.key.commitment[:], "randao_commitment", k.RandaoCommitment},
		{v.key.firstReveal[:], "randao_first_reveal", k.RandaoFirstReveal},
	} {
		if err := unhexInto(f.dst, f.hex); err != nil {
			return nil, fmt.Errorf("keys/interop.json key 0 %s: %w", f.name, err)
		}
	}
	return &v, nil
}

func readJSON(path string, out any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// unhexInto decodes a 0x-prefixed hex string of exactly len(dst) bytes.
func unhexInto(dst []byte, s string) error {
	h, ok := strings.CutPrefix(s, "0x")
	if !ok {
		return fmt.Errorf("%.20q is not 0x-prefixed hex", s)
	}
	if hex.DecodedLen(len(h)) != len(dst) {
		return fmt.Errorf("%d hex digits, want %d bytes", len(h), len(dst))
	}
	_, err := hex.Decode(dst, []byte(h))
	return err
}
