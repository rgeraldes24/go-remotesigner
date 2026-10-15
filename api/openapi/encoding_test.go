// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package openapi

import (
	"math/big"
	"math/rand"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// These tables pin the strict JSON encoding rules of docs/contract.md
// ("Encoding rules") at the schema level. Rules a JSON schema cannot express
// (duplicate keys, popcount == len(signatures), the preset's bitvector
// length, fork_info equal to the network) are server checks and are
// exercised by the signer's own tests.

func accepts(s *openapi3.Schema, v any) error {
	return s.VisitJSON(v, openapi3.VisitAsRequest())
}

func TestUint64Pattern(t *testing.T) {
	s := schema(t, "Uint64")
	tests := []struct {
		in   any
		want bool
	}{
		{"0", true},
		{"1", true},
		{"1234", true},
		{"9223372036854775808", true},
		{"18446744073709551609", true},
		{"18446744073709551614", true},
		{"18446744073709551615", true}, // 2^64-1
		{"18446744073709551616", false},
		{"18446744073709551620", false},
		{"18446744073709552000", false},
		{"19000000000000000000", false},
		{"99999999999999999999", false},
		{"100000000000000000000", false},
		{"", false},
		{"01", false},
		{"00", false},
		{"+1", false},
		{"-1", false},
		{" 1", false},
		{"1.0", false},
		{"1e3", false},
		{"0x10", false},
		{float64(1), false}, // a JSON number
		{nil, false},
	}
	for _, tt := range tests {
		if err := accepts(s, tt.in); (err == nil) != tt.want {
			t.Errorf("Uint64 %#v: accepted=%v, want %v (%v)", tt.in, err == nil, tt.want, err)
		}
	}

	// The pattern must encode exactly the uint64 range.
	maxU64 := new(big.Int).SetUint64(^uint64(0))
	rng := rand.New(rand.NewSource(1))
	for range 20000 {
		n := new(big.Int).Rand(rng, new(big.Int).Lsh(big.NewInt(1), uint(1+rng.Intn(70))))
		want := n.Cmp(maxU64) <= 0
		if err := accepts(s, n.String()); (err == nil) != want {
			t.Fatalf("Uint64 %s: accepted=%v, want %v", n, err == nil, want)
		}
	}
}

func TestFixedLengthHex(t *testing.T) {
	hex := func(bytes int, c string) string { return "0x" + strings.Repeat(c, bytes) }
	tests := []struct {
		schema string
		in     string
		want   bool
	}{
		{"Bytes4", "0x000000fd", true},
		{"Bytes4", "0x000000FD", true},
		{"Bytes4", "0x0000fd", false},
		{"Bytes4", "000000fd", false},
		{"Root", hex(32, "ab"), true},
		{"Root", hex(31, "ab"), false},
		{"Root", hex(33, "ab"), false},
		{"Root", "0X" + strings.Repeat("ab", 32), false},
		{"Root", hex(31, "ab") + "zz", false},
		{"Pubkey", hex(2592, "a5"), true},
		{"Pubkey", hex(2592, "A5"), true},
		{"Pubkey", hex(2591, "a5"), false},
		{"Pubkey", hex(2593, "a5"), false},
		{"Pubkey", hex(2591, "a5") + "g5", false},
		{"Signature", hex(4627, "5a"), true},
		{"Signature", hex(4626, "5a"), false},
		{"Signature", hex(4628, "5a"), false},
		{"Signature", "5a" + hex(4627, "5a")[2:], false},
		{"Identifier", hex(2592, "a5"), true},
		{"Identifier", hex(32, "6a"), true},
		{"Identifier", hex(33, "6a"), false},
		{"Identifier", hex(2592, "a5")[1:], false},
		{"Identifier", hex(31, "6a") + "6", false},
		{"Identifier", strings.Repeat("6a", 32), false},
		{"QAddress", "Q" + strings.Repeat("ab", 64), true},
		{"QAddress", "Q" + strings.Repeat("AB", 64), true},
		{"QAddress", "0x" + strings.Repeat("ab", 64), false},
		{"QAddress", "q" + strings.Repeat("ab", 64), false},
		{"QAddress", "Q" + strings.Repeat("ab", 20), false},
		{"QAddress", "Q" + strings.Repeat("ab", 65), false},
	}
	for _, tt := range tests {
		if err := accepts(schema(t, tt.schema), tt.in); (err == nil) != tt.want {
			t.Errorf("%s %.24q (len %d): accepted=%v, want %v", tt.schema, tt.in, len(tt.in), err == nil, tt.want)
		}
	}
}

func TestBitfieldPatterns(t *testing.T) {
	tests := []struct {
		schema string
		in     string
		want   bool
	}{
		{"Bitlist32", "0x01", true},          // empty bitlist: delimiter only
		{"Bitlist32", "0x1f", true},          // 4 bits set
		{"Bitlist32", "0x1F", true},          // either case
		{"Bitlist32", "0xff01", true},        // 8 bits
		{"Bitlist32", "0x00000080", true},    // 31 bits, delimiter in bit 31
		{"Bitlist32", "0xffffffff01", true},  // 32 bits: the 5-byte edge
		{"Bitlist32", "0x0000000001", true},  // 32 zero bits
		{"Bitlist32", "0x", false},           // no delimiter byte
		{"Bitlist32", "0x00", false},         // missing delimiter
		{"Bitlist32", "0x0100", false},       // last byte zero
		{"Bitlist32", "0x0000000002", false}, // 33 bits
		{"Bitlist32", "0x00000000ff", false}, // 39 bits
		{"Bitlist32", "0x000000000001", false},
		{"Bitlist32", "0x1", false},
		{"SyncContributionBitvector", "0x0500", true},                        // minimal: 16 bits
		{"SyncContributionBitvector", "0x" + strings.Repeat("00", 16), true}, // mainnet: 128 bits
		{"SyncContributionBitvector", "0x05", false},
		{"SyncContributionBitvector", "0x050000", false},
		{"SyncContributionBitvector", "0x" + strings.Repeat("00", 15), false},
		{"SyncContributionBitvector", "0x" + strings.Repeat("00", 17), false},
	}
	for _, tt := range tests {
		if err := accepts(schema(t, tt.schema), tt.in); (err == nil) != tt.want {
			t.Errorf("%s %q: accepted=%v, want %v", tt.schema, tt.in, err == nil, tt.want)
		}
	}
}

// signExample returns a fresh copy of the sign example for typ.
func signExample(t *testing.T, typ string) map[string]any {
	t.Helper()
	op := loadSpec(t).Paths.Value("/api/v1/consensus/sign/{identifier}").Post
	ex, ok := op.RequestBody.Value.Content.Get("application/json").Examples[typ]
	if !ok {
		t.Fatalf("no sign example for %s", typ)
	}
	return deepCopy(t, ex.Value.Value).(map[string]any)
}

// at walks a decoded JSON object along keys and returns the innermost map.
func at(m map[string]any, keys ...string) map[string]any {
	for _, k := range keys {
		m = m[k].(map[string]any)
	}
	return m
}

func repeatSig(n int) []any {
	sig := "0x" + strings.Repeat("5a", 4627)
	out := make([]any, n)
	for i := range out {
		out[i] = sig
	}
	return out
}

func TestSignRequestStrictness(t *testing.T) {
	signReq := schema(t, "SignRequest")
	tests := []struct {
		name   string
		typ    string
		mutate func(m map[string]any)
		want   bool
	}{
		{"example as is", "ATTESTATION", func(map[string]any) {}, true},
		{"signingRoot alias alone", "ATTESTATION", func(m map[string]any) {
			m["signingRoot"] = m["signing_root"]
			delete(m, "signing_root")
		}, true},
		{"no signing root", "ATTESTATION", func(m map[string]any) { delete(m, "signing_root") }, true},
		{"uint64 at the maximum", "ATTESTATION", func(m map[string]any) { at(m, "attestation")["slot"] = "18446744073709551615" }, true},

		{"signing_root and signingRoot together", "ATTESTATION", func(m map[string]any) { m["signingRoot"] = m["signing_root"] }, false},
		{"uint64 as a JSON number", "ATTESTATION", func(m map[string]any) { at(m, "attestation")["slot"] = float64(61) }, false},
		{"uint64 with a leading zero", "ATTESTATION", func(m map[string]any) { at(m, "attestation")["slot"] = "061" }, false},
		{"uint64 above the maximum", "ATTESTATION", func(m map[string]any) { at(m, "attestation")["slot"] = "18446744073709551616" }, false},
		{"unknown top-level field", "ATTESTATION", func(m map[string]any) { m["extra"] = "x" }, false},
		{"unknown nested field", "ATTESTATION", func(m map[string]any) { at(m, "attestation", "source")["extra"] = "x" }, false},
		{"unknown field in fork_info", "ATTESTATION", func(m map[string]any) { at(m, "fork_info")["extra"] = "x" }, false},
		{"proto name committee_index", "ATTESTATION", func(m map[string]any) {
			a := at(m, "attestation")
			a["committee_index"] = a["index"]
			delete(a, "index")
		}, false},
		{"lower-case type", "ATTESTATION", func(m map[string]any) { m["type"] = "attestation" }, false},
		{"unknown type", "ATTESTATION", func(m map[string]any) { m["type"] = "RANDAO_REVEAL" }, false},
		{"missing fork_info", "ATTESTATION", func(m map[string]any) { delete(m, "fork_info") }, false},
		{"short GVR", "ATTESTATION", func(m map[string]any) { at(m, "fork_info")["genesis_validators_root"] = "0x00" }, false},

		{"block header", "BLOCK_V2", func(map[string]any) {}, true},
		{"block version not ZOND", "BLOCK_V2", func(m map[string]any) { at(m, "beacon_block")["version"] = "CAPELLA" }, false},
		{"block version lower case", "BLOCK_V2", func(m map[string]any) { at(m, "beacon_block")["version"] = "zond" }, false},
		{"full block instead of header", "BLOCK_V2", func(m map[string]any) {
			b := at(m, "beacon_block")
			b["block"] = b["block_header"]
			delete(b, "block_header")
		}, false},

		{"aggregate with 32 signatures", "AGGREGATE_AND_PROOF", func(m map[string]any) {
			at(m, "aggregate_and_proof", "aggregate")["signatures"] = repeatSig(32)
		}, true},
		{"aggregate with no signatures", "AGGREGATE_AND_PROOF", func(m map[string]any) {
			at(m, "aggregate_and_proof", "aggregate")["signatures"] = []any{}
		}, true},
		{"aggregate with 33 signatures", "AGGREGATE_AND_PROOF", func(m map[string]any) {
			at(m, "aggregate_and_proof", "aggregate")["signatures"] = repeatSig(33)
		}, false},
		{"singular signature on the aggregate", "AGGREGATE_AND_PROOF", func(m map[string]any) {
			a := at(m, "aggregate_and_proof", "aggregate")
			a["signature"] = repeatSig(1)[0]
			delete(a, "signatures")
		}, false},
		{"short selection proof", "AGGREGATE_AND_PROOF", func(m map[string]any) {
			at(m, "aggregate_and_proof")["selection_proof"] = "0x" + strings.Repeat("5a", 4626)
		}, false},
		{"bitlist without delimiter", "AGGREGATE_AND_PROOF", func(m map[string]any) {
			at(m, "aggregate_and_proof", "aggregate")["aggregation_bits"] = "0x00"
		}, false},
		{"V2 wrapper shape", "AGGREGATE_AND_PROOF", func(m map[string]any) {
			m["aggregate_and_proof"] = map[string]any{"version": "ZOND", "data": m["aggregate_and_proof"]}
		}, false},

		{"contribution with 128 signatures", "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF", func(m map[string]any) {
			at(m, "contribution_and_proof", "contribution")["signatures"] = repeatSig(128)
		}, true},
		{"contribution with 129 signatures", "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF", func(m map[string]any) {
			at(m, "contribution_and_proof", "contribution")["signatures"] = repeatSig(129)
		}, false},
		{"contribution with no signatures", "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF", func(m map[string]any) {
			at(m, "contribution_and_proof", "contribution")["signatures"] = []any{}
		}, false},
		{"contribution with a 3-byte bitvector", "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF", func(m map[string]any) {
			at(m, "contribution_and_proof", "contribution")["aggregation_bits"] = "0x050000"
		}, false},
		{"proto name block_root", "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF", func(m map[string]any) {
			c := at(m, "contribution_and_proof", "contribution")
			c["block_root"] = c["beacon_block_root"]
			delete(c, "beacon_block_root")
		}, false},

		{"sync message root too short", "SYNC_COMMITTEE_MESSAGE", func(m map[string]any) {
			at(m, "sync_committee_message")["beacon_block_root"] = "0x44dd"
		}, false},
		{"exit epoch as a number", "VOLUNTARY_EXIT", func(m map[string]any) { at(m, "voluntary_exit")["epoch"] = float64(10) }, false},
		{"aggregation slot extra field", "AGGREGATION_SLOT", func(m map[string]any) { at(m, "aggregation_slot")["epoch"] = "1" }, false},
		{"selection data missing subcommittee", "SYNC_COMMITTEE_SELECTION_PROOF", func(m map[string]any) {
			delete(at(m, "sync_aggregator_selection_data"), "subcommittee_index")
		}, false},

		{"registration as is", "VALIDATOR_REGISTRATION", func(map[string]any) {}, true},
		{"registration with fork_info", "VALIDATOR_REGISTRATION", func(m map[string]any) {
			m["fork_info"] = signExample(t, "ATTESTATION")["fork_info"]
		}, false},
		{"registration with a 0x fee recipient", "VALIDATOR_REGISTRATION", func(m map[string]any) {
			r := at(m, "validator_registration")
			r["fee_recipient"] = "0x" + r["fee_recipient"].(string)[1:]
		}, false},
		{"registration with a 20-byte fee recipient", "VALIDATOR_REGISTRATION", func(m map[string]any) {
			at(m, "validator_registration")["fee_recipient"] = "Q" + strings.Repeat("ab", 20)
		}, false},
		{"registration with a short pubkey", "VALIDATOR_REGISTRATION", func(m map[string]any) {
			at(m, "validator_registration")["pubkey"] = "0x" + strings.Repeat("a5", 48)
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.typ+"/"+tt.name, func(t *testing.T) {
			m := signExample(t, tt.typ)
			tt.mutate(m)
			err := signReq.VisitJSON(m, openapi3.VisitAsRequest())
			if (err == nil) != tt.want {
				t.Errorf("accepted=%v, want %v (%v)", err == nil, tt.want, err)
			}
		})
	}
}

func TestRandaoRequestStrictness(t *testing.T) {
	s := schema(t, "RandaoRevealRequest")
	base := func() map[string]any {
		op := loadSpec(t).Paths.Value("/api/v1/consensus/randao_reveal/{identifier}").Post
		return deepCopy(t, op.RequestBody.Value.Content.Get("application/json").Example).(map[string]any)
	}
	tests := []struct {
		name   string
		mutate func(m map[string]any)
		want   bool
	}{
		{"example as is", func(map[string]any) {}, true},
		{"slot as a number", func(m map[string]any) { m["slot"] = float64(62) }, false},
		{"missing slot", func(m map[string]any) { delete(m, "slot") }, false},
		{"missing fork_info", func(m map[string]any) { delete(m, "fork_info") }, false},
		{"commitment of 31 bytes", func(m map[string]any) { m["randao_commitment"] = "0x" + strings.Repeat("e1", 31) }, false},
		{"camelCase commitment", func(m map[string]any) {
			m["randaoCommitment"] = m["randao_commitment"]
			delete(m, "randao_commitment")
		}, false},
		{"unknown field", func(m map[string]any) { m["epoch"] = "10" }, false},
	}
	for _, tt := range tests {
		m := base()
		tt.mutate(m)
		if err := s.VisitJSON(m, openapi3.VisitAsRequest()); (err == nil) != tt.want {
			t.Errorf("%s: accepted=%v, want %v (%v)", tt.name, err == nil, tt.want, err)
		}
	}
}

// TestNullableSitsNextToType enforces the OpenAPI 3.0.3 rule that nullable
// has an effect only in a Schema Object that also sets type. kin-openapi is
// more lenient than strict validators and code generators here, so a
// nullable beside an allOf would pass these tests and still break clients.
func TestNullableSitsNextToType(t *testing.T) {
	doc := loadSpec(t)
	seen := map[*openapi3.Schema]bool{}
	var walk func(where string, ref *openapi3.SchemaRef)
	walk = func(where string, ref *openapi3.SchemaRef) {
		if ref == nil || ref.Value == nil || seen[ref.Value] {
			return
		}
		s := ref.Value
		seen[s] = true
		if s.Nullable && (s.Type == nil || len(*s.Type) == 0) {
			t.Errorf("%s: nullable without type has no effect under OpenAPI 3.0.3", where)
		}
		for name, p := range s.Properties {
			walk(where+"."+name, p)
		}
		walk(where+"[]", s.Items)
		for i, sub := range slices.Concat(s.OneOf, s.AnyOf, s.AllOf) {
			walk(where+"#"+strconv.Itoa(i), sub)
		}
	}
	for name, s := range doc.Components.Schemas {
		walk("components.schemas."+name, s)
	}
	for _, o := range operations(t) {
		at := o.method + " " + o.path
		if rb := o.op.RequestBody; rb != nil {
			for ct, mt := range rb.Value.Content {
				walk(at+" request "+ct, mt.Schema)
			}
		}
		for code, resp := range o.op.Responses.Map() {
			for ct, mt := range resp.Value.Content {
				walk(at+" response "+code+" "+ct, mt.Schema)
			}
		}
	}
}

func TestCapabilitiesNullableNetworkFields(t *testing.T) {
	network := schema(t, "Capabilities").Properties["network"].Value
	gvr := network.Properties["genesis_validators_root"].Value
	genesisTime := network.Properties["genesis_time"].Value

	// The fields are inlined copies of Root and Uint64; keep them in step.
	if gvr.Pattern != schema(t, "Root").Pattern {
		t.Errorf("genesis_validators_root pattern %q differs from Root's", gvr.Pattern)
	}
	if genesisTime.Pattern != schema(t, "Uint64").Pattern {
		t.Errorf("genesis_time pattern differs from Uint64's")
	}

	tests := []struct {
		name  string
		field *openapi3.Schema
		in    any
		want  bool
	}{
		{"gvr null", gvr, nil, true},
		{"gvr root", gvr, "0x" + strings.Repeat("7a", 32), true},
		{"gvr short", gvr, "0x" + strings.Repeat("7a", 31), false},
		{"gvr empty", gvr, "", false},
		{"time null", genesisTime, nil, true},
		{"time decimal", genesisTime, "1760000000", true},
		{"time number", genesisTime, float64(1760000000), false},
		{"time over uint64", genesisTime, "18446744073709551616", false},
	}
	for _, tt := range tests {
		if err := tt.field.VisitJSON(tt.in, openapi3.VisitAsResponse()); (err == nil) != tt.want {
			t.Errorf("%s %#v: accepted=%v, want %v (%v)", tt.name, tt.in, err == nil, tt.want, err)
		}
	}
}

func TestHighWatermarkIsBothFieldsOrNone(t *testing.T) {
	s := schema(t, "HighWatermark")
	tests := []struct {
		in   string
		want bool
	}{
		{`{}`, true},
		{`{"epoch":"1200","slot":"7200"}`, true},
		{`{"epoch":"1200"}`, false},
		{`{"slot":"7200"}`, false},
		{`{"epoch":"1200","slot":"7200","extra":"1"}`, false},
		{`{"epoch":1200,"slot":"7200"}`, false},
	}
	for _, tt := range tests {
		if err := s.VisitJSON(decode(t, tt.in), openapi3.VisitAsResponse()); (err == nil) != tt.want {
			t.Errorf("HighWatermark %s: accepted=%v, want %v (%v)", tt.in, err == nil, tt.want, err)
		}
	}
}
