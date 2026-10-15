// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

// capabilitiesResponse is a GET …/capabilities body for chain c, with
// overrides applied to the network object or the top level.
func capabilitiesResponse(c *chain, top map[string]any, network map[string]any) obj {
	types := []string{tBlock, tAttestation, tAggSlot, tAggAndProof, tSyncMessage, tSyncSelect, tContribution, tRegistration}
	netw := obj{}.
		set("config_name", c.cfg.ConfigName).
		set("genesis_fork_version", hx(c.forkVersion())).
		set("genesis_validators_root", hx(c.gvr[:])).
		set("genesis_time", u64s(genesisTime)).
		set("seconds_per_slot", u64s(c.cfg.SecondsPerSlot)).
		set("slots_per_epoch", u64s(uint64(c.cfg.SlotsPerEpoch)))
	for i, e := range netw {
		if v, ok := network[e.k]; ok {
			netw[i].v = v
		}
	}
	r := obj{}.
		set("api_version", "1.0.0").
		set("types", types).
		set("randao_reveal", true).
		set("selection_proof_mode", "deterministic").
		set("slashing_protection", "bolt").
		set("network", netw)
	for i, e := range r {
		if v, ok := top[e.k]; ok {
			r[i].v = v
		}
	}
	return r
}

// genCapabilities writes capabilities.json: the startup handshake of
// docs/contract.md section 16 as the qrysm client must judge it, for the
// client's Q2 tests. Each case pairs the chain the client knows with a
// capabilities response and whether the client must accept it.
func genCapabilities(g *generator) error {
	var recs []obj
	for _, c := range g.chains() {
		vc := obj{}.
			set("genesis_fork_version", hx(c.forkVersion())).
			set("genesis_validators_root", hx(c.gvr[:])).
			set("genesis_time", u64s(genesisTime)).
			set("seconds_per_slot", u64s(c.cfg.SecondsPerSlot)).
			set("slots_per_epoch", u64s(uint64(c.cfg.SlotsPerEpoch)))
		other := c.def.name + ":other"
		for _, tc := range []struct {
			name   string
			top    map[string]any
			netw   map[string]any
			accept bool
			check  string
		}{
			{name: "matching", accept: true},
			{name: "gvr_pending_tofu", netw: map[string]any{"genesis_validators_root": nil}, accept: true, check: "genesis_validators_root"},
			{name: "minor_api_version", top: map[string]any{"api_version": "1.1.0"}, accept: true},
			{name: "hedged_selection_proofs", top: map[string]any{"selection_proof_mode": "hedged"}, accept: true},
			{name: "protection_disabled", top: map[string]any{"slashing_protection": "disabled"}, accept: true},
			{name: "wrong_gvr", netw: map[string]any{"genesis_validators_root": hx(fill32(other))}, check: "genesis_validators_root"},
			{name: "wrong_fork_version", netw: map[string]any{"genesis_fork_version": "0x20000089"}, check: "genesis_fork_version"},
			{name: "wrong_genesis_time", netw: map[string]any{"genesis_time": u64s(genesisTime + 1)}, check: "genesis_time"},
			{name: "genesis_time_unknown", netw: map[string]any{"genesis_time": nil}, check: "genesis_time"},
			{name: "wrong_seconds_per_slot", netw: map[string]any{"seconds_per_slot": u64s(c.cfg.SecondsPerSlot + 1)}, check: "seconds_per_slot"},
			{name: "wrong_slots_per_epoch", netw: map[string]any{"slots_per_epoch": u64s(uint64(c.cfg.SlotsPerEpoch) * 2)}, check: "slots_per_epoch"},
			{name: "randao_reveal_off", top: map[string]any{"randao_reveal": false}, check: "randao_reveal"},
			{name: "unsupported_api_major", top: map[string]any{"api_version": "2.0.0"}, check: "api_version"},
		} {
			e := obj{}.set("accept", tc.accept)
			if tc.check != "" {
				e = e.set("check", tc.check)
			}
			if tc.accept && tc.check != "" {
				e = e.set("log", "WARN")
			}
			recs = append(recs, obj{}.
				set("name", c.preset+"/"+tc.name).
				set("preset", c.preset).
				set("client_chain", vc).
				set("response", capabilitiesResponse(c, tc.top, tc.netw)).
				set("expect", e))
		}
	}
	return writeJSON(g.vectors, "capabilities.json", obj{}.
		set("description", g.description("The capabilities handshake of docs/contract.md section 16. "+
			"client_chain is what the qrysm client knows after WaitForChainStart; response is the signer's "+
			"GET /api/v1/consensus/capabilities body; expect.accept says whether the client may start, and "+
			"expect.check names the field that decides it. A pending TOFU pin (null GVR) is accepted with a WARN.")).
		set("generator", g.info).
		set("cases", recs))
}
