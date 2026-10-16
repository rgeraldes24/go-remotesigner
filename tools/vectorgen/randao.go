// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"slices"

	"github.com/theQRL/qrysm/consensus-types/primitives"
	"github.com/theQRL/qrysm/crypto/randao"
)

// layerValues returns the layers at the given indices of the onion of seed,
// using qrysm's Onion (with its checkpoints) when the onion is long and
// Origin/Next otherwise, and checks every consecutive pair with
// randao.Verify.
func layerValues(seed []byte, layers uint64, indices []uint64) (map[uint64][32]byte, error) {
	out := map[uint64][32]byte{}
	o, err := randao.NewOnion(seed, layers)
	if err != nil {
		return nil, err
	}
	for _, j := range indices {
		v, err := o.Layer(j)
		if err != nil {
			return nil, fmt.Errorf("layer %d: %w", j, err)
		}
		if j > 0 {
			prev, err := o.Layer(j - 1)
			if err != nil {
				return nil, err
			}
			if !randao.Verify(prev, v) {
				return nil, fmt.Errorf("layer %d does not verify against layer %d", j, j-1)
			}
		}
		out[j] = v
	}
	return out, nil
}

// onionVector is one of the note's vectors V1-V3 (docs/spec/randao-onion.md).
type onionVector struct {
	id      string
	seed    []byte
	layers  uint64
	indices []uint64
}

func seed0() []byte {
	s := make([]byte, 48)
	for i := range s {
		s[i] = byte(i)
	}
	return s
}

// genRandao writes the RANDAO vectors: onion.json (V1-V3), interop.json (V4),
// requests.json (V5) and frontier.json (V6).
func genRandao(g *generator) error {
	if err := genOnionVectors(g); err != nil {
		return err
	}
	if err := genInteropCommitments(g); err != nil {
		return err
	}
	if err := genRandaoRequests(g); err != nil {
		return err
	}
	return genFrontier(g)
}

func genOnionVectors(g *generator) error {
	vs := []onionVector{
		{id: "V1", seed: seed0(), layers: 8, indices: []uint64{0, 1, 2, 3, 4, 5, 6, 7, 8}},
		{id: "V2", seed: []byte("seed-a"), layers: 5, indices: []uint64{0, 4, 5}},
		{id: "V3", seed: seed0(), layers: randao.DefaultLayers,
			indices: []uint64{0, 1, 1023, 1024, 1025, randao.DefaultLayers - 1, randao.DefaultLayers}},
	}
	var recs []obj
	for _, v := range vs {
		vals, err := layerValues(v.seed, v.layers, v.indices)
		if err != nil {
			return fmt.Errorf("%s: %w", v.id, err)
		}
		commitment := randao.Commitment(v.seed, v.layers)
		if commitment != vals[v.layers] {
			return fmt.Errorf("%s: Commitment differs from the onion's top layer", v.id)
		}
		o, err := randao.NewOnion(v.seed, v.layers)
		if err != nil {
			return err
		}
		reveal, err := o.Reveal(commitment)
		if err != nil {
			return err
		}
		var layers []obj
		for _, j := range v.indices {
			x := vals[j]
			layers = append(layers, obj{}.set("index", j).set("value", hx(x[:])))
		}
		recs = append(recs, obj{}.
			set("id", v.id).
			set("seed", hx(v.seed)).
			set("layers", v.layers).
			set("values", layers).
			set("commitment", hx(commitment[:])).
			set("reveal", hx(reveal[:])))
	}
	return writeJSON(g.vectors, "randao/onion.json", obj{}.
		set("description", g.description("Hash-onion vectors V1-V3 of docs/spec/randao-onion.md, computed by "+
			"qrysm's crypto/randao (Origin, Next, Commitment, Onion.Layer and Onion.Reveal). values lists x_index; "+
			"commitment is x_layers and reveal its pre-image x_{layers-1}.")).
		set("generator", g.info).
		set("tag", "qrl-randao-onion-v1").
		set("cases", recs))
}

// genInteropCommitments writes V4: the commitment and first reveal of every
// interop key of the e2e genesis, cross-checked against the commitments
// qrysm's genesis builder stored in the validator registry.
func genInteropCommitments(g *generator) error {
	st, err := g.genesisState()
	if err != nil {
		return err
	}
	var recs []obj
	for _, k := range g.keys {
		v, err := st.ValidatorAtIndex(primitives.ValidatorIndex(k.index))
		if err != nil {
			return err
		}
		if [32]byte(v.RandaoCommitment) != k.commitment {
			return fmt.Errorf("V4: key %d commitment %#x differs from genesis %#x", k.index, k.commitment, v.RandaoCommitment)
		}
		recs = append(recs, obj{}.
			set("index", k.index).
			set("seed", hx(k.seed)).
			set("commitment", hx(k.commitment[:])).
			set("first_reveal", hx(k.firstReveal[:])))
	}
	return writeJSON(g.vectors, "randao/interop.json", obj{}.
		set("description", g.description("Vector V4: the RANDAO commitments (x_L, L = 2^20) and first reveals "+
			"(x_{L-1}) of the interop keys of the qrysm e2e genesis, checked against the randao_commitment that "+
			"qrysm's NewPreminedGenesis stores for each validator. seed is the 48-byte interop wallet seed.")).
		set("generator", g.info).
		set("layers", randao.DefaultLayers).
		set("genesis_validators_root", hx(g.mainnet.gvr[:])).
		set("keys", recs))
}

// genRandaoRequests writes V5: reveal requests the signer must refuse
// whatever its state, built per key. slot_offset is added to the signer's
// current slot so the request is inside the reveal window.
func genRandaoRequests(g *generator) error {
	type rq struct {
		name       string
		key        int
		commitment string
		status     int
		reason     string
		note       string
	}
	// Each refused case uses its own key, so a signer scans every onion at
	// most once and the scan budget (--randao-full-scan-min-interval) never
	// decides an outcome.
	k2, k5 := g.keys[2], g.keys[5]
	vals2, err := layerValues(k2.seed, 1, []uint64{0})
	if err != nil {
		return err
	}
	vals5, err := layerValues(k5.seed, randao.DefaultLayers+1, []uint64{randao.DefaultLayers + 1})
	if err != nil {
		return err
	}
	x0, beyond := vals2[0], vals5[randao.DefaultLayers+1]
	zero := make([]byte, 32)
	k0, k1 := g.keys[0], g.keys[1]
	cases := []rq{
		{"exhausted_x0", 2, hx(x0[:]), 422, "RANDAO_ONION_EXHAUSTED",
			"x_0 of key 2's onion, sent to a key with no reveal state (with state, the frontier rule may refuse the slot first)"},
		{"other_keys_commitment", 3, hx(k1.commitment[:]), 422, "RANDAO_UNKNOWN_COMMITMENT", "key 1's commitment sent to key 3"},
		{"zero_commitment", 4, hx(zero), 422, "RANDAO_UNKNOWN_COMMITMENT", ""},
		{"beyond_max_layers", 5, hx(beyond[:]), 422, "RANDAO_UNKNOWN_COMMITMENT", "x_{2^20+1} of key 5's onion, outside the default --randao-max-layers"},
		{"commitment_31_bytes", 0, hx(k0.commitment[:31]), 400, "BAD_FIELD", ""},
		{"commitment_33_bytes", 0, hx(append(k0.commitment[:], 0)), 400, "BAD_FIELD", ""},
	}
	var recs []obj
	for _, c := range g.chains() {
		for _, rc := range cases {
			r := obj{}.
				set("name", c.preset+"/"+rc.name).
				set("preset", c.preset).
				set("key_index", rc.key).
				set("slot_offset", 0).
				set("randao_commitment", rc.commitment).
				set("fork_info", c.forkInfo())
			if rc.note != "" {
				r = r.set("notes", rc.note)
			}
			recs = append(recs, r.set("expect", obj{}.set("status", rc.status).set("reason", rc.reason)))
		}
	}
	return writeJSON(g.vectors, "randao/requests.json", obj{}.
		set("description", g.description("Vector V5: RANDAO reveal requests the signer refuses (docs/contract.md "+
			"section 14). The body is {slot, randao_commitment, fork_info} with slot = the signer's current slot + "+
			"slot_offset.")).
		set("generator", g.info).
		set("cases", recs))
}

// The V6 frontier scripts: the signer settings they assume.
const (
	scriptSkew        = 1
	scriptReorgWindow = 1024
	scriptBurst       = 3
	// scriptScanSlots is --randao-full-scan-min-interval in slots (its
	// default, SECONDS_PER_SLOT).
	scriptScanSlots = 1
)

// step is one reveal request of a frontier script and what the contract's
// frontier rule (docs/contract.md sections 14.3 and 14.4) answers.
type step struct {
	now, slot uint64
	// layer is the commitment's onion index; commitment overrides it with
	// another value ("zero", "other_key").
	layer      uint64
	commitment string
	status     int
	reason     string
	result     string // the consensus_randao_reveals_total result label
	reveal     uint64 // the released layer, for status 200
	// m and last are the stored state after the step; hasState false means
	// none is stored.
	m, last  uint64
	hasState bool
}

type script struct {
	name, scenario string
	// refillEpochs is --randao-new-layer-refill-epochs; 0 turns the bucket off.
	refillEpochs uint64
	steps        []step
}

const bigL = randao.DefaultLayers

// released is a 200 that releases layer-1 and stores (m, last).
func released(now, slot, layer uint64, result string, m, last uint64) step {
	return step{now: now, slot: slot, layer: layer, status: 200, result: result, reveal: layer - 1, m: m, last: last, hasState: true}
}

// reReveal is a 200 that leaves the state (m, last) unchanged.
func reReveal(now, slot, layer, m, last uint64) step {
	return step{now: now, slot: slot, layer: layer, status: 200, result: "re_reveal", reveal: layer - 1, m: m, last: last, hasState: true}
}

func refused(now, slot, layer uint64, status int, reason string, m, last uint64, hasState bool) step {
	return step{now: now, slot: slot, layer: layer, status: status, reason: reason, result: "refused", m: m, last: last, hasState: hasState}
}

// frontierScripts are the fork, reorg, orphan, retry and walking scenarios
// under the contract's frontier rule, each from an empty state on key 0, whose onion has L = 2^20 layers. Steps
// that need a slow-path scan from x_0 are two slots apart, so the default
// --randao-full-scan-min-interval (one slot) never decides an outcome. The
// one exception is the contract's §22 example of a second gap advance in the
// same slot, where the scan budget, checked before conditions N (§14.4),
// refuses it with 429; gap_advanced_slot_rule shows the slot rule refusing a
// gap advance once the budget has refilled.
func frontierScripts() []script {
	L := uint64(bigL)
	return []script{
		{name: "first_use", scenario: "first proposal after the deposit, or of a key migrated from a client that kept no reveal state", refillEpochs: 1, steps: []step{
			released(100, 100, L, "first_use", L-1, 100),
		}},
		{name: "next_proposal", scenario: "next proposal after an included one", refillEpochs: 1, steps: []step{
			released(100, 100, L, "first_use", L-1, 100),
			released(200, 200, L-1, "new_layer", L-2, 200),
		}},
		{name: "orphaned_or_missed_proposal", scenario: "previous block orphaned, proposal missed after the release, or the VC's head behind the canonical chain", refillEpochs: 1, steps: []step{
			released(100, 100, L, "first_use", L-1, 100),
			reReveal(250, 250, L, L-1, 100),
		}},
		{name: "retry_within_slot", scenario: "retry within the slot: response lost after the commit, or a VC restart", refillEpochs: 1, steps: []step{
			released(100, 100, L, "first_use", L-1, 100),
			reReveal(100, 100, L, L-1, 100),
		}},
		{name: "walking_in_one_slot", scenario: "contract §22", refillEpochs: 1, steps: []step{
			released(100, 100, L, "first_use", L-1, 100),
			refused(100, 100, L-1, 412, "RANDAO_SLOT_NOT_INCREASING", L-1, 100, true),
		}},
		{name: "skew_allows_next_slot", scenario: "contract §22", refillEpochs: 1, steps: []step{
			released(100, 100, L, "first_use", L-1, 100),
			released(100, 101, L-1, "new_layer", L-2, 101),
			refused(100, 102, L-2, 412, "RANDAO_SLOT_OUT_OF_WINDOW", L-2, 101, true),
		}},
		{name: "out_of_window", scenario: "contract §14.3 condition 1", refillEpochs: 1, steps: []step{
			refused(100, 500, L, 412, "RANDAO_SLOT_OUT_OF_WINDOW", 0, 0, false),
			refused(102, 100, L, 412, "RANDAO_SLOT_OUT_OF_WINDOW", 0, 0, false),
			released(104, 103, L, "first_use", L-1, 103),
		}},
		{name: "gap_advanced", scenario: "a commitment deeper than the frontier: a minority fork, or a second signer with its own store; contract §22, §14.4: a second advance in the same slot needs a scan inside the budget's interval", refillEpochs: 1, steps: []step{
			released(100, 100, L, "first_use", L-1, 100),
			released(200, 200, L-10, "gap_advanced", L-11, 200),
			refused(200, 200, L-20, 429, "RANDAO_SCAN_RATE_LIMITED", L-11, 200, true),
		}},
		{name: "gap_advanced_slot_rule", scenario: "contract §22: once the scan budget has refilled, the slot rule refuses a second advance for the same slot", refillEpochs: 1, steps: []step{
			released(100, 100, L, "first_use", L-1, 100),
			released(200, 201, L-10, "gap_advanced", L-11, 201),
			refused(202, 201, L-20, 412, "RANDAO_SLOT_NOT_INCREASING", L-11, 201, true),
		}},
		{name: "deep_reorg_within_window", scenario: "deep reorg orphaning several of the key's blocks", refillEpochs: 1, steps: []step{
			released(100, 100, L, "first_use", L-1, 100),
			released(200, 200, L-1, "new_layer", L-2, 200),
			released(300, 300, L-2, "new_layer", L-3, 300),
			reReveal(400, 400, L, L-3, 300),
		}},
		{name: "deep_reorg_beyond_window", scenario: "deep reorg beyond the reorg window (slow path)", refillEpochs: 1, steps: []step{
			released(100, 100, L-2000, "first_use", L-2001, 100),
			reReveal(200, 200, L, L-2001, 100),
		}},
		{name: "minority_fork_runs_ahead", scenario: "minority fork holding a block of the key that the canonical chain lacks", refillEpochs: 1, steps: []step{
			released(100, 100, L, "first_use", L-1, 100),
			released(200, 200, L-1, "new_layer", L-2, 200),
			reReveal(300, 300, L-1, L-2, 200),
			reReveal(300, 300, L, L-2, 200),
		}},
		{name: "exhausted", scenario: "onion exhausted: the commitment is x_0", refillEpochs: 1, steps: []step{
			refused(100, 100, 0, 422, "RANDAO_ONION_EXHAUSTED", 0, 0, false),
		}},
		{name: "unknown_commitment", scenario: "commitment not in this onion: zero, another key's, or above the maximum length", refillEpochs: 1, steps: []step{
			{now: 100, slot: 100, commitment: "zero", status: 422, reason: "RANDAO_UNKNOWN_COMMITMENT", result: "refused"},
			{now: 102, slot: 102, commitment: "other_key", status: 422, reason: "RANDAO_UNKNOWN_COMMITMENT", result: "refused"},
			refused(104, 104, L+1, 422, "RANDAO_UNKNOWN_COMMITMENT", 0, 0, false),
		}},
		{name: "new_layer_bucket", scenario: "contract §14.3 bucket, §22", refillEpochs: 1, steps: []step{
			// Slots 97-100 lie in one epoch of 6 slots, so the outcome is the
			// same whether the bucket refills continuously or per epoch.
			released(97, 97, L, "first_use", L-1, 97),
			released(98, 98, L-1, "new_layer", L-2, 98),
			released(99, 99, L-2, "new_layer", L-3, 99),
			refused(100, 100, L-3, 412, "RANDAO_NEW_LAYER_RATE_LIMITED", L-3, 99, true),
			released(106, 106, L-3, "new_layer", L-4, 106),
		}},
		{name: "malicious_beacon_node", scenario: "malicious beacon node asking for a reveal in every slot", refillEpochs: 0, steps: []step{
			released(100, 100, L, "first_use", L-1, 100),
			refused(100, 100, L-1, 412, "RANDAO_SLOT_NOT_INCREASING", L-1, 100, true),
			released(101, 101, L-1, "new_layer", L-2, 101),
			refused(101, 101, L-2, 412, "RANDAO_SLOT_NOT_INCREASING", L-2, 101, true),
			released(102, 102, L-2, "new_layer", L-3, 102),
			released(103, 103, L-3, "new_layer", L-4, 103),
			released(104, 104, L-4, "new_layer", L-5, 104),
		}},
		{name: "two_vcs_same_slot", scenario: "two VCs with one key on one signer, in the same slot", refillEpochs: 1, steps: []step{
			released(100, 100, L, "first_use", L-1, 100),
			released(200, 200, L-1, "new_layer", L-2, 200),
			reReveal(200, 200, L-1, L-2, 200),
		}},
	}
}

// genFrontier writes V6: the frontier-rule scripts with every referenced
// layer of key 0's onion resolved to its value by qrysm's onion.
func genFrontier(g *generator) error {
	k0 := g.keys[0]
	scripts := frontierScripts()
	var indices []uint64
	for _, s := range scripts {
		for _, st := range s.steps {
			if st.commitment == "" {
				indices = append(indices, st.layer)
				if st.status == 200 {
					indices = append(indices, st.reveal)
				}
			}
			if st.hasState {
				indices = append(indices, st.m)
			}
		}
	}
	slices.Sort(indices)
	indices = slices.Compact(indices)
	vals, err := layerValues(k0.seed, bigL+1, indices)
	if err != nil {
		return err
	}
	var layers []obj
	for _, j := range indices {
		v := vals[j]
		layers = append(layers, obj{}.set("index", j).set("value", hx(v[:])))
	}
	var recs []obj
	for _, s := range scripts {
		var steps []obj
		for _, st := range s.steps {
			e := obj{}.set("now_slot", u64s(st.now)).set("slot", u64s(st.slot))
			switch st.commitment {
			case "":
				v := vals[st.layer]
				e = e.set("commitment_layer", st.layer).set("randao_commitment", hx(v[:]))
			case "zero":
				e = e.set("randao_commitment", hx(make([]byte, 32)))
			case "other_key":
				e = e.set("randao_commitment", hx(g.keys[1].commitment[:]))
			}
			x := obj{}.set("status", st.status)
			if st.status == 200 {
				r := vals[st.reveal]
				if !randao.Verify(r, vals[st.layer]) {
					return fmt.Errorf("V6 %s: reveal does not verify", s.name)
				}
				x = x.set("reveal_layer", st.reveal).set("randao_reveal", hx(r[:]))
			} else {
				x = x.set("reason", st.reason)
			}
			x = x.set("result", st.result)
			if st.hasState {
				r := vals[st.m]
				x = x.set("state", obj{}.set("m", st.m).set("reveal", hx(r[:])).set("last", u64s(st.last)))
			} else {
				x = x.set("state", nil)
			}
			steps = append(steps, e.set("expect", x))
		}
		recs = append(recs, obj{}.
			set("name", s.name).
			set("scenario", s.scenario).
			set("signer", obj{}.
				set("randao_max_layers", bigL).
				set("randao_reorg_window", scriptReorgWindow).
				set("signing_clock_skew_slots", scriptSkew).
				set("randao_new_layer_burst", scriptBurst).
				set("randao_new_layer_refill_epochs", s.refillEpochs).
				set("randao_full_scan_min_interval_slots", scriptScanSlots)).
			set("steps", steps))
	}
	return writeJSON(g.vectors, "randao/frontier.json", obj{}.
		set("description", g.description("Vector V6: frontier-rule scripts for fork, reorg, orphan, retry and walking scenarios under "+
			"docs/contract.md sections 14.3 and 14.4, on interop key 0 (onion length 2^20) of the end-to-end network "+
			"(6 slots per epoch). Each script starts from an empty reveal state; now_slot is the signer's clock. "+
			"The expectations are the contract's; every layer value was computed by qrysm's crypto/randao, and "+
			"layers lists each index the scripts use. state is the stored (m, x_m, last) after the step, or null.")).
		set("generator", g.info).
		set("network", g.minimal.def.name).
		set("key_index", 0).
		set("layers", layers).
		set("scripts", recs))
}
