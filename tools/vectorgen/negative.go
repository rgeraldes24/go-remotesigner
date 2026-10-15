// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/hex"
	"fmt"
	"strings"

	qrysmpb "github.com/theQRL/qrysm/proto/qrysm/v1alpha1"
)

// negCase is a request the signer must refuse.
type negCase struct {
	name, typ  string
	key        int
	identifier string // overrides the canonical identifier of key
	body       string
	status     int
	reason     string
	signer     obj // signer settings the expectation depends on
}

// with returns a copy of o with the value at path replaced.
func with(o obj, path string, v any) obj {
	head, rest, nested := strings.Cut(path, ".")
	out := make(obj, len(o))
	copy(out, o)
	for i := range out {
		if out[i].k != head {
			continue
		}
		if nested {
			out[i].v = with(out[i].v.(obj), rest, v)
		} else {
			out[i].v = v
		}
		return out
	}
	panic("no key " + head + " in path " + path)
}

// without returns a copy of o without the key at path.
func without(o obj, path string) obj {
	head, rest, nested := strings.Cut(path, ".")
	out := make(obj, 0, len(o))
	for _, e := range o {
		switch {
		case e.k != head:
			out = append(out, e)
		case nested:
			out = append(out, kv{e.k, without(e.v.(obj), rest)})
		}
	}
	return out
}

// plus returns a copy of o with key k added to the object at path ("" for
// the top level).
func plus(o obj, path, k string, v any) obj {
	if path == "" {
		out := make(obj, len(o), len(o)+1)
		copy(out, o)
		return append(out, kv{k, v})
	}
	head, rest, _ := strings.Cut(path, ".")
	out := make(obj, len(o))
	copy(out, o)
	for i := range out {
		if out[i].k == head {
			out[i].v = plus(out[i].v.(obj), rest, k, v)
			return out
		}
	}
	panic("no key " + head)
}

// renamed returns a copy of o with the key at path renamed to k.
func renamed(o obj, path, k string) obj {
	head, rest, nested := strings.Cut(path, ".")
	out := make(obj, len(o))
	copy(out, o)
	for i := range out {
		if out[i].k != head {
			continue
		}
		if nested {
			out[i].v = renamed(out[i].v.(obj), rest, k)
		} else {
			out[i].k = k
		}
		return out
	}
	panic("no key " + head)
}

func hexN(label string, n int) string { return hx(fill(label, n)) }

// negativeCases builds the negative fixtures of chain c from its valid
// requests: one or more per 400 reason of docs/contract.md section 11
// (G2 §8.3 item 5), plus the exit gate.
func (g *generator) negativeCases(c *chain) ([]negCase, error) {
	valid := map[string]obj{}
	for _, t := range artifactTypes {
		ex, err := g.specExample(t)
		if err != nil {
			return nil, err
		}
		switch {
		case t == tAggAndProof:
			// One participant keeps the many aggregate cases small.
			ex = aggregate("neg:agg", []byte{0x03}, typicalData(), 17)
		case t == tContribution && c.preset == "mainnet":
			sig, _ := g.specSignature()
			ex = contributionObject(7, &qrysmpb.SyncCommitteeContribution{
				Slot: 61, BlockRoot: mustHex(specBlockRoot), Signatures: [][]byte{sig, sig},
			}, bitvector(int(c.subcommitteeBits), 0, 2), sig)
		}
		_, _, root, err := c.roots(ex)
		if err != nil {
			return nil, err
		}
		valid[t] = c.requestJSON(ex, root)
	}
	att, slot, agg, contrib, reg := valid[tAttestation], valid[tAggSlot], valid[tAggAndProof], valid[tContribution], valid[tRegistration]
	block, sel := valid[tBlock], valid[tSyncSelect]
	policy := func(o obj) obj { return without(o, "signing_root") } // policy-stage cases do not depend on step order
	sig := hexN("neg:sig", 4627)

	var cs []negCase
	add := func(name, typ string, body any, status int, reason string) {
		s, ok := body.(string)
		if !ok {
			s = compact(body)
		}
		cs = append(cs, negCase{name: name, typ: typ, body: s, status: status, reason: reason})
	}
	bad := func(name, typ string, body any) { add(name, typ, body, 400, "BAD_FIELD") }

	// BAD_IDENTIFIER: a valid body sent to a malformed identifier.
	pk := hx(g.keys[0].pub)
	for _, id := range []struct{ name, id string }{
		{"identifier_too_short", "0x1234"},
		{"identifier_no_prefix", strings.TrimPrefix(pk, "0x")},
		{"identifier_non_hex", pk[:len(pk)-1] + "g"},
		{"identifier_alias_65_hex", "0x" + strings.Repeat("a", 65)},
		{"identifier_one_byte_short", pk[:len(pk)-2]},
	} {
		cs = append(cs, negCase{name: id.name, typ: tAggSlot, identifier: id.id, body: compact(slot), status: 400, reason: "BAD_IDENTIFIER"})
	}

	// MALFORMED_JSON.
	slotJSON := compact(slot)
	add("not_json", tAggSlot, "not json", 400, "MALFORMED_JSON")
	add("empty_body", tAggSlot, "", 400, "MALFORMED_JSON")
	add("truncated", tAggSlot, slotJSON[:len(slotJSON)-1], 400, "MALFORMED_JSON")
	add("trailing_data", tAggSlot, slotJSON+" {}", 400, "MALFORMED_JSON")
	add("duplicate_top_level_key", tAggSlot, `{"type":"AGGREGATION_SLOT",`+slotJSON[1:], 400, "MALFORMED_JSON")
	add("duplicate_nested_key", tAggSlot, strings.Replace(slotJSON, `"epoch":"0"`, `"epoch":"0","epoch":"0"`, 1), 400, "MALFORMED_JSON")
	add("signing_root_and_alias", tAggSlot, plus(slot, "", "signingRoot", hx(fill32("x"))), 400, "MALFORMED_JSON")

	// UNKNOWN_FIELD.
	add("unknown_top_level_field", tAttestation, plus(att, "", "extra", "1"), 400, "UNKNOWN_FIELD")
	add("unknown_nested_field", tAttestation, plus(att, "attestation.source", "extra", "1"), 400, "UNKNOWN_FIELD")
	add("singular_signature", tAggAndProof, renamed(agg, "aggregate_and_proof.aggregate.signatures", "signature"), 400, "UNKNOWN_FIELD")
	add("signature_beside_signatures", tAggAndProof, plus(agg, "aggregate_and_proof.aggregate", "signature", sig), 400, "UNKNOWN_FIELD")
	add("fork_info_on_registration", tRegistration, plus(reg, "", "fork_info", c.forkInfo()), 400, "UNKNOWN_FIELD")
	add("payload_of_another_type", tAttestation, plus(att, "", "aggregation_slot", obj{}.set("slot", "61")), 400, "UNKNOWN_FIELD")
	add("full_block_instead_of_header", tBlock, plus(block, "beacon_block", "block", obj{}), 400, "UNKNOWN_FIELD")
	add("signature_domain_field", tAttestation, plus(att, "", "signature_domain", hx(fill32("d"))), 400, "UNKNOWN_FIELD")

	// BAD_FIELD: JSON types, uint64 forms, lengths, prefixes, bitfields.
	bad("missing_type", tAttestation, without(att, "type"))
	bad("type_not_string", tAttestation, with(att, "type", 5))
	bad("uint64_as_number", tAttestation, with(att, "attestation.slot", 61))
	bad("uint64_leading_zero", tAttestation, with(att, "attestation.slot", "061"))
	bad("uint64_negative", tAttestation, with(att, "attestation.slot", "-1"))
	bad("uint64_overflow", tAttestation, with(att, "attestation.slot", "18446744073709551616"))
	bad("uint64_empty", tAttestation, with(att, "attestation.slot", ""))
	bad("uint64_plus_sign", tAttestation, with(att, "attestation.slot", "+61"))
	bad("missing_field", tAttestation, without(att, "attestation.target"))
	bad("missing_payload", tAttestation, without(att, "attestation"))
	bad("root_31_bytes", tAttestation, with(att, "attestation.beacon_block_root", hexN("r31", 31)))
	bad("root_33_bytes", tAttestation, with(att, "attestation.beacon_block_root", hexN("r33", 33)))
	bad("root_no_prefix", tAttestation, with(att, "attestation.beacon_block_root", hex.EncodeToString(fill32("np"))))
	bad("root_q_prefix", tAttestation, with(att, "attestation.beacon_block_root", "Q"+hex.EncodeToString(fill32("q"))))
	bad("root_non_hex", tAttestation, with(att, "attestation.beacon_block_root", "0x"+strings.Repeat("zz", 32)))
	bad("fork_version_3_bytes", tAttestation, with(att, "fork_info.fork.current_version", "0x0000fd"))
	bad("signature_4626_bytes", tAggAndProof, with(agg, "aggregate_and_proof.selection_proof", hexN("s", 4626)))
	bad("signature_4628_bytes", tAggAndProof, with(agg, "aggregate_and_proof.selection_proof", hexN("s", 4628)))
	bad("signature_list_element_short", tAggAndProof, with(agg, "aggregate_and_proof.aggregate.signatures",
		[]string{hexN("s", 4626)}))
	bad("bitlist_without_delimiter", tAggAndProof, with(agg, "aggregate_and_proof.aggregate.aggregation_bits", "0x00"))
	bad("bitlist_empty", tAggAndProof, with(agg, "aggregate_and_proof.aggregate.aggregation_bits", "0x"))
	bad("bitlist_33_bits", tAggAndProof, with(agg, "aggregate_and_proof.aggregate.aggregation_bits", "0x0000000002"))
	bad("bitlist_6_bytes", tAggAndProof, with(agg, "aggregate_and_proof.aggregate.aggregation_bits", "0x000000000001"))
	n := int(c.subcommitteeBits) / 8
	bad(fmt.Sprintf("contribution_bits_%d_bytes", n-1), tContribution, with(contrib, "contribution_and_proof.contribution.aggregation_bits", hx(append([]byte{0x05}, make([]byte, n-2)...))))
	bad(fmt.Sprintf("contribution_bits_%d_bytes", n+1), tContribution, with(contrib, "contribution_and_proof.contribution.aggregation_bits", hx(append([]byte{0x05}, make([]byte, n)...))))
	bad("block_version_not_zond", tBlock, with(block, "beacon_block.version", "BELLATRIX"))
	bad("fee_recipient_0x_prefix", tRegistration, with(reg, "validator_registration.fee_recipient", "0x"+specFeeRecipient))
	bad("fee_recipient_63_bytes", tRegistration, with(reg, "validator_registration.fee_recipient", "Q"+specFeeRecipient[:126]))
	bad("pubkey_2591_bytes", tRegistration, with(reg, "validator_registration.pubkey", hx(g.keys[0].pub[:2591])))
	bad("signatures_not_array", tAggAndProof, with(agg, "aggregate_and_proof.aggregate.signatures", sig))

	// UNKNOWN_TYPE.
	for _, t := range []string{"attestation", "DEPOSIT", "RANDAO_REVEAL", "AGGREGATE_AND_PROOF_V2", "BLOCK"} {
		add("unknown_type_"+strings.ToLower(t), tAttestation, with(att, "type", t), 400, "UNKNOWN_TYPE")
	}

	// MISSING_FORK_INFO.
	add("attestation_without_fork_info", tAttestation, without(att, "fork_info"), 400, "MISSING_FORK_INFO")
	add("block_without_fork_info", tBlock, without(block, "fork_info"), 400, "MISSING_FORK_INFO")

	// FORK_INFO_MISMATCH (policy; signing_root left out).
	other := []byte{0x00, 0x00, 0x00, 0xfe}
	if c.preset == "mainnet" {
		other = []byte{0x00, 0x00, 0x00, 0xfd}
	}
	add("fork_info_other_network_version", tAttestation, policy(with(with(att, "fork_info.fork.current_version", hx(other)),
		"fork_info.fork.previous_version", hx(other))), 400, "FORK_INFO_MISMATCH")
	add("fork_info_previous_differs", tAttestation, policy(with(att, "fork_info.fork.previous_version", hx(other))), 400, "FORK_INFO_MISMATCH")
	add("fork_info_epoch_not_zero", tAttestation, policy(with(att, "fork_info.fork.epoch", "1")), 400, "FORK_INFO_MISMATCH")
	add("fork_info_wrong_gvr", tAttestation, policy(with(att, "fork_info.genesis_validators_root", hx(fill32("gvr")))), 400, "FORK_INFO_MISMATCH")

	// SIGNING_ROOT_MISMATCH.
	add("signing_root_mismatch", tAttestation, with(att, "signing_root", hx(fill32("wrong"))), 400, "SIGNING_ROOT_MISMATCH")
	add("signing_root_alias_mismatch", tAggSlot, renamed(with(slot, "signing_root", hx(fill32("wrong"))), "signing_root", "signingRoot"), 400, "SIGNING_ROOT_MISMATCH")
	add("signing_root_mismatch_registration", tRegistration, with(reg, "signing_root", hx(fill32("wrong"))), 400, "SIGNING_ROOT_MISMATCH")

	// INVARIANT_VIOLATION (policy; signing_root left out).
	iv := func(name, typ string, body obj) { add(name, typ, policy(body), 400, "INVARIANT_VIOLATION") }
	iv("source_after_target", tAttestation, with(att, "attestation.source.epoch", "11"))
	iv("aggregate_popcount_mismatch", tAggAndProof, with(agg, "aggregate_and_proof.aggregate.signatures", []string{sig, sig}))
	iv("aggregate_33_signatures", tAggAndProof, with(with(agg, "aggregate_and_proof.aggregate.aggregation_bits", "0xffffffff01"),
		"aggregate_and_proof.aggregate.signatures", repeat(sig, 33)))
	iv("selection_subcommittee_index_1", tSyncSelect, with(sel, "sync_aggregator_selection_data.subcommittee_index", "1"))
	iv("contribution_subcommittee_index_1", tContribution, with(contrib, "contribution_and_proof.contribution.subcommittee_index", "1"))
	iv("contribution_popcount_mismatch", tContribution, with(contrib, "contribution_and_proof.contribution.signatures", []string{sig}))
	iv("contribution_zero_signatures", tContribution, with(with(contrib, "contribution_and_proof.contribution.aggregation_bits", hx(make([]byte, n))),
		"contribution_and_proof.contribution.signatures", []string{}))
	if c.preset == "mainnet" {
		iv("contribution_129_signatures", tContribution, with(with(contrib, "contribution_and_proof.contribution.aggregation_bits", hx(bitvector(128, seq(128)...))),
			"contribution_and_proof.contribution.signatures", repeat(sig, 129)))
	}

	// PUBKEY_MISMATCH: key 1's registration sent to key 0.
	add("registration_pubkey_of_another_key", tRegistration, policy(with(reg, "validator_registration.pubkey", hx(g.keys[1].pub))), 400, "PUBKEY_MISMATCH")

	// ARTIFACT_TYPE_DISABLED: exits while --voluntary-exit-signing-enabled is off.
	cs = append(cs, negCase{name: "voluntary_exit_disabled", typ: tExit, body: compact(valid[tExit]), status: 403,
		reason: "ARTIFACT_TYPE_DISABLED", signer: obj{}.set("voluntary_exits_enabled", false)})
	return cs, nil
}

func repeat(s string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = s
	}
	return out
}

// genNegative writes negative/<preset>.json.
func genNegative(g *generator) error {
	for _, c := range g.chains() {
		cs, err := g.negativeCases(c)
		if err != nil {
			return err
		}
		recs := make([]obj, 0, len(cs))
		for _, n := range cs {
			r := obj{}.set("name", n.name).set("type", n.typ).set("key_index", n.key)
			if n.identifier != "" {
				r = r.set("identifier", n.identifier)
			}
			if n.signer != nil {
				r = r.set("signer", n.signer)
			}
			recs = append(recs, r.set("request_body", n.body).
				set("expect", obj{}.set("status", n.status).set("reason", n.reason)))
		}
		if err := writeJSON(g.vectors, "negative/"+c.preset+".json", obj{}.
			set("description", g.description("Requests the signer must refuse, on the "+c.def.name+" network ("+
				c.preset+" preset), with the status and reason of docs/contract.md section 11. request_body is the "+
				"raw body; identifier, when present, replaces the canonical identifier of key_index. Cases whose "+
				"expectation depends on signer settings name them in signer. Policy-stage cases carry no "+
				"signing_root, so their outcome does not depend on the order of the pipeline steps.")).
			set("generator", g.info).
			set("preset", c.preset).
			set("network", c.recordNetwork()).
			set("cases", recs)); err != nil {
			return err
		}
	}
	return nil
}
