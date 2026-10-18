// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package consensus

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/rgeraldes24/go-remotesigner/internal/consensus/signingroot"
	"github.com/rgeraldes24/go-remotesigner/internal/network"
)

// APIVersion is the contract version, info.version of api/openapi/consensus.yaml.
const APIVersion = "1.0.0"

// Values of the capabilities slashing_protection field.
const (
	ProtectionBolt     = "bolt"
	ProtectionPostgres = "postgres"
	ProtectionDisabled = "disabled"
)

// Capabilities describes what `capabilities` reports (docs/contract.md
// section 16).
type Capabilities struct {
	// Network is the bound chain.
	Network *network.Network
	// Types returns the enabled artifact types, in contract order.
	Types func() []signingroot.ArtifactType
	// GenesisValidatorsRoot returns the bound GVR, or false while a
	// trust-on-first-use pin is pending.
	GenesisValidatorsRoot func() ([32]byte, bool)
	// SelectionProofMode is "deterministic" or "hedged".
	SelectionProofMode string
	// SlashingProtection is ProtectionBolt, ProtectionPostgres or ProtectionDisabled.
	SlashingProtection string
}

type capabilitiesBody struct {
	APIVersion         string      `json:"api_version"`
	Types              []string    `json:"types"`
	RandaoReveal       bool        `json:"randao_reveal"`
	SelectionProofMode string      `json:"selection_proof_mode"`
	SlashingProtection string      `json:"slashing_protection"`
	Network            networkBody `json:"network"`
}

type networkBody struct {
	ConfigName            string  `json:"config_name"`
	GenesisForkVersion    string  `json:"genesis_fork_version"`
	GenesisValidatorsRoot *string `json:"genesis_validators_root"`
	GenesisTime           *string `json:"genesis_time"`
	SecondsPerSlot        string  `json:"seconds_per_slot"`
	SlotsPerEpoch         string  `json:"slots_per_epoch"`
}

// Handler serves GET /api/v1/consensus/capabilities, the VC's startup
// handshake. randao_reveal is false while genesis time is unknown, since no
// new RANDAO layer can then be released; genesis_validators_root is null
// while a trust-on-first-use pin is pending, and genesis_time null when
// unknown.
func (c Capabilities) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := c.Network
		body := capabilitiesBody{
			APIVersion:         APIVersion,
			Types:              []string{},
			RandaoReveal:       n.GenesisTimeKnown(),
			SelectionProofMode: c.SelectionProofMode,
			SlashingProtection: c.SlashingProtection,
			Network: networkBody{
				ConfigName:         n.Config.ConfigName,
				GenesisForkVersion: "0x" + hex.EncodeToString(n.Config.GenesisForkVersion[:]),
				SecondsPerSlot:     strconv.FormatUint(n.Config.SecondsPerSlot, 10),
				SlotsPerEpoch:      strconv.FormatUint(n.Config.SlotsPerEpoch, 10),
			},
		}
		for _, t := range c.Types() {
			body.Types = append(body.Types, string(t))
		}
		if gvr, ok := c.GenesisValidatorsRoot(); ok {
			s := "0x" + hex.EncodeToString(gvr[:])
			body.Network.GenesisValidatorsRoot = &s
		}
		if n.GenesisTimeKnown() {
			s := strconv.FormatUint(n.GenesisTime, 10)
			body.Network.GenesisTime = &s
		}
		data, err := json.Marshal(body)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(data)
	})
}
