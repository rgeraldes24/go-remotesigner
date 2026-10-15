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
)

// The fixture shapes verify reads back. They mirror what the writers above
// produce; unknown fields are ignored.

type fxNetwork struct {
	ConfigName         string `json:"config_name"`
	GenesisForkVersion string `json:"genesis_fork_version"`
	GVR                string `json:"gvr"`
	SlotsPerEpoch      string `json:"slots_per_epoch"`
}

type fxExpect struct {
	Status int    `json:"status"`
	Reason string `json:"reason"`
}

type fxSignCase struct {
	Name                   string          `json:"name"`
	Type                   string          `json:"type"`
	Preset                 string          `json:"preset"`
	Network                fxNetwork       `json:"network"`
	KeyIndex               int             `json:"key_index"`
	Pubkey                 string          `json:"pubkey"`
	ObjectSSZHex           string          `json:"object_ssz_hex"`
	ObjectRoot             string          `json:"object_root"`
	Domain                 string          `json:"domain"`
	SigningRoot            string          `json:"signing_root"`
	RequestJSON            json.RawMessage `json:"request_json"`
	DeterministicSignature string          `json:"deterministic_signature"`
	Expect                 fxExpect        `json:"expect"`
}

type fxSignFile struct {
	Type   string       `json:"type"`
	Preset string       `json:"preset"`
	Cases  []fxSignCase `json:"cases"`
}

type fxNegCase struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	KeyIndex   int    `json:"key_index"`
	Identifier string `json:"identifier"`
	Signer     *struct {
		VoluntaryExitsEnabled *bool `json:"voluntary_exits_enabled"`
	} `json:"signer"`
	RequestBody string   `json:"request_body"`
	Expect      fxExpect `json:"expect"`
}

type fxNegFile struct {
	Preset  string      `json:"preset"`
	Network fxNetwork   `json:"network"`
	Cases   []fxNegCase `json:"cases"`
}

type fxKey struct {
	Index             int    `json:"index"`
	Seed              string `json:"seed"`
	Pubkey            string `json:"pubkey"`
	RandaoCommitment  string `json:"randao_commitment"`
	RandaoFirstReveal string `json:"randao_first_reveal"`
}

type fxRandaoRequest struct {
	Name             string          `json:"name"`
	Preset           string          `json:"preset"`
	KeyIndex         int             `json:"key_index"`
	SlotOffset       int64           `json:"slot_offset"`
	RandaoCommitment string          `json:"randao_commitment"`
	ForkInfo         json.RawMessage `json:"fork_info"`
	Expect           fxExpect        `json:"expect"`
}

// fixtures is the part of testdata/vectors that verify posts.
type fixtures struct {
	signing  map[string][]fxSignFile // by preset
	negative map[string]fxNegFile    // by preset
	keys     []fxKey
	randao   []fxRandaoRequest
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func loadFixtures(dir string) (*fixtures, error) {
	fx := &fixtures{signing: map[string][]fxSignFile{}, negative: map[string]fxNegFile{}}
	for _, preset := range []string{"minimal", "mainnet"} {
		files, err := filepath.Glob(filepath.Join(dir, "signing", preset, "*.json"))
		if err != nil {
			return nil, err
		}
		if len(files) == 0 {
			return nil, fmt.Errorf("no signing fixtures for %s under %s", preset, dir)
		}
		for _, f := range files {
			var sf fxSignFile
			if err := readJSON(f, &sf); err != nil {
				return nil, err
			}
			fx.signing[preset] = append(fx.signing[preset], sf)
		}
		var nf fxNegFile
		if err := readJSON(filepath.Join(dir, "negative", preset+".json"), &nf); err != nil {
			return nil, err
		}
		fx.negative[preset] = nf
	}
	var keys struct {
		Keys []fxKey `json:"keys"`
	}
	if err := readJSON(filepath.Join(dir, "keys", "interop.json"), &keys); err != nil {
		return nil, err
	}
	fx.keys = keys.Keys
	var rq struct {
		Cases []fxRandaoRequest `json:"cases"`
	}
	if err := readJSON(filepath.Join(dir, "randao", "requests.json"), &rq); err != nil {
		return nil, err
	}
	fx.randao = rq.Cases
	return fx, nil
}

// parseU64 parses a decimal uint64 string.
func parseU64(s string) (uint64, error) { return strconv.ParseUint(s, 10, 64) }

// unhex decodes 0x-prefixed hex.
func unhex(s string) ([]byte, error) {
	h, ok := strings.CutPrefix(s, "0x")
	if !ok {
		return nil, fmt.Errorf("%.20q: no 0x prefix", s)
	}
	return hex.DecodeString(h)
}
