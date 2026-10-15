// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/signingroot"
)

var (
	minimal = Params{SyncSubcommitteeSize: 16}
	mainnet = Params{SyncSubcommitteeSize: 128}
)

// specExamples returns the sign-request examples of the contract as JSON,
// by example name, plus the RANDAO request example.
func specExamples(t *testing.T) (sign map[string][]byte, randao []byte) {
	t.Helper()
	raw, err := os.ReadFile("../../../api/openapi/consensus.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]map[string]struct {
			RequestBody struct {
				Content map[string]struct {
					Example any `yaml:"example"`
				} `yaml:"content"`
			} `yaml:"requestBody"`
		} `yaml:"paths"`
		Components struct {
			Examples map[string]struct {
				Value any `yaml:"value"`
			} `yaml:"examples"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	sign = map[string][]byte{}
	for name, ex := range spec.Components.Examples {
		body, err := json.Marshal(ex.Value)
		if err != nil {
			t.Fatal(err)
		}
		sign[name] = body
	}
	ex := spec.Paths["/api/v1/consensus/randao_reveal/{identifier}"]["post"].RequestBody.Content["application/json"].Example
	if randao, err = json.Marshal(ex); err != nil {
		t.Fatal(err)
	}
	return sign, randao
}

// Every example in the frozen contract decodes, re-encodes canonically and
// decodes to the same request. The AGGREGATION_SLOT example carries a real
// signing root (docs/spec/signing-roots.md section 4).
func TestSpecExamples(t *testing.T) {
	sign, randao := specExamples(t)
	if len(sign) != 9 {
		t.Fatalf("%d sign examples, want 9", len(sign))
	}
	seen := map[signingroot.ArtifactType]bool{}
	for name, body := range sign {
		t.Run(name, func(t *testing.T) {
			req, err := DecodeSignRequest(body, minimal)
			if err != nil {
				t.Fatal(err)
			}
			seen[req.Type()] = true
			if req.SigningRoot == nil {
				t.Error("example has no signing root")
			}
			if (req.ForkInfo == nil) != (req.Type() == signingroot.ValidatorRegistration) {
				t.Errorf("fork_info presence wrong for %s", req.Type())
			}
			if _, err := req.Payload.ObjectRoot(); err != nil {
				t.Errorf("object root: %v", err)
			}
			roundTrip(t, req, minimal)
		})
	}
	if len(seen) != 9 {
		t.Errorf("examples cover %d types", len(seen))
	}

	req, err := DecodeSignRequest(sign["AggregationSlot"], minimal)
	if err != nil {
		t.Fatal(err)
	}
	chain, _ := signingroot.NewChain(req.ForkInfo.Fork.CurrentVersion, req.ForkInfo.GenesisValidatorsRoot, 6)
	root, err := req.SigningRootFor(chain)
	if err != nil {
		t.Fatal(err)
	}
	if root != *req.SigningRoot {
		t.Errorf("AGGREGATION_SLOT signing root %x, example says %x", root, *req.SigningRoot)
	}

	r, err := DecodeRandaoRevealRequest(randao)
	if err != nil {
		t.Fatal(err)
	}
	if r.Slot != 62 || hex.EncodeToString(r.RandaoCommitment[:4]) != "e17fb348" {
		t.Errorf("RANDAO example decoded to %+v", r)
	}
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := DecodeRandaoRevealRequest(out); err != nil || !reflect.DeepEqual(again, r) {
		t.Errorf("RANDAO round trip: %v", err)
	}
}

// roundTrip checks that req encodes, decodes to an equal request and
// re-encodes to the same bytes.
func roundTrip(t *testing.T, req *SignRequest, p Params) {
	t.Helper()
	out, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	again, err := DecodeSignRequest(out, p)
	if err != nil {
		t.Fatalf("re-decode: %v\n%.300s", err, out)
	}
	if !reflect.DeepEqual(again, req) {
		t.Fatal("round trip changed the request")
	}
	if out2, _ := json.Marshal(again); !bytes.Equal(out, out2) {
		t.Fatal("encoding is not canonical")
	}
}

// sig is a recognisable signature hex string.
func sigHex(b byte) string {
	return "0x" + strings.Repeat(hex.EncodeToString([]byte{b}), SignatureLength)
}

const (
	gvrHex  = "0x7a1e2c4d5b6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809"
	rootHex = "0x44dd55ee66ff778899001122334455667788990011aabbccddeeff0011223344"
	forkObj = `{"fork":{"previous_version":"0x000000fd","current_version":"0x000000fd","epoch":"0"},"genesis_validators_root":"` + gvrHex + `"}`
	dataObj = `{"slot":"61","index":"0","beacon_block_root":"` + rootHex + `","source":{"epoch":"8","root":"` + rootHex + `"},"target":{"epoch":"10","root":"` + rootHex + `"}}`
)

// validBodies are minimal valid requests of every type, for mutation.
func validBodies() map[signingroot.ArtifactType]string {
	env := func(typ, key, payload string) string {
		return `{"type":"` + typ + `","fork_info":` + forkObj + `,"signing_root":"` + rootHex + `","` + key + `":` + payload + `}`
	}
	pk := "0x" + strings.Repeat("a5", PubkeyLength)
	return map[signingroot.ArtifactType]string{
		signingroot.BlockV2: env("BLOCK_V2", "beacon_block", `{"version":"ZOND","block_header":{"slot":"62","proposer_index":"17","parent_root":"`+
			rootHex+`","state_root":"`+rootHex+`","body_root":"`+rootHex+`"}}`),
		signingroot.Attestation:     env("ATTESTATION", "attestation", dataObj),
		signingroot.AggregationSlot: env("AGGREGATION_SLOT", "aggregation_slot", `{"slot":"61"}`),
		signingroot.AggregateAndProof: env("AGGREGATE_AND_PROOF", "aggregate_and_proof", `{"aggregator_index":"17","aggregate":{"aggregation_bits":"0x07","data":`+
			dataObj+`,"signatures":["`+sigHex(1)+`","`+sigHex(2)+`"]},"selection_proof":"`+sigHex(3)+`"}`),
		signingroot.VoluntaryExit:        env("VOLUNTARY_EXIT", "voluntary_exit", `{"epoch":"10","validator_index":"42"}`),
		signingroot.SyncCommitteeMessage: env("SYNC_COMMITTEE_MESSAGE", "sync_committee_message", `{"beacon_block_root":"`+rootHex+`","slot":"61"}`),
		signingroot.SyncCommitteeSelectionProof: env("SYNC_COMMITTEE_SELECTION_PROOF", "sync_aggregator_selection_data",
			`{"slot":"61","subcommittee_index":"0"}`),
		signingroot.SyncCommitteeContributionAndProof: env("SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF", "contribution_and_proof",
			`{"aggregator_index":"7","selection_proof":"`+sigHex(4)+`","contribution":{"slot":"61","beacon_block_root":"`+rootHex+
				`","subcommittee_index":"0","aggregation_bits":"0x0500","signatures":["`+sigHex(5)+`","`+sigHex(6)+`"]}}`),
		signingroot.ValidatorRegistration: `{"type":"VALIDATOR_REGISTRATION","signing_root":"` + rootHex + `","validator_registration":{"fee_recipient":"Q` +
			strings.Repeat("2b", AddressLength) + `","gas_limit":"30000000","timestamp":"1760000000","pubkey":"` + pk + `"}}`,
	}
}

func TestValidBodies(t *testing.T) {
	for typ, body := range validBodies() {
		req, err := DecodeSignRequest([]byte(body), minimal)
		if err != nil {
			t.Errorf("%s: %v", typ, err)
			continue
		}
		if req.Type() != typ {
			t.Errorf("%s decoded as %s", typ, req.Type())
		}
		roundTrip(t, req, minimal)
	}
}

// The strict-decoding table of docs/contract.md section 4: each mutation of
// a valid body is refused with the listed reason and field path.
func TestStrictDecoding(t *testing.T) {
	bodies := validBodies()
	blk, att, agg := bodies[signingroot.BlockV2], bodies[signingroot.Attestation], bodies[signingroot.AggregateAndProof]
	sel, con, reg := bodies[signingroot.SyncCommitteeSelectionProof], bodies[signingroot.SyncCommitteeContributionAndProof],
		bodies[signingroot.ValidatorRegistration]
	exit := bodies[signingroot.VoluntaryExit]
	rep := func(s, old, new string) string {
		if !strings.Contains(s, old) {
			t.Fatalf("mutation target %q not in body", old)
		}
		return strings.Replace(s, old, new, 1)
	}
	q := strings.Repeat("2b", AddressLength)
	tests := []struct {
		name  string
		body  string
		p     Params
		r     apierr.Reason
		field string
	}{
		// Numbers for uint64 fields, at several depths.
		{"number slot", rep(blk, `"slot":"62"`, `"slot":62`), minimal, apierr.BadField, "beacon_block.block_header.slot"},
		{"number epoch", rep(att, `"target":{"epoch":"10"`, `"target":{"epoch":10`), minimal, apierr.BadField, "attestation.target.epoch"},
		{"number fork epoch", rep(att, `"epoch":"0"`, `"epoch":0`), minimal, apierr.BadField, "fork_info.fork.epoch"},
		{"number gas limit", rep(reg, `"30000000"`, `30000000`), minimal, apierr.BadField, "validator_registration.gas_limit"},
		{"leading zero", rep(exit, `"epoch":"10"`, `"epoch":"010"`), minimal, apierr.BadField, "voluntary_exit.epoch"},
		{"uint64 overflow", rep(exit, `"epoch":"10"`, `"epoch":"18446744073709551616"`), minimal, apierr.BadField, "voluntary_exit.epoch"},
		{"negative", rep(exit, `"epoch":"10"`, `"epoch":"-1"`), minimal, apierr.BadField, "voluntary_exit.epoch"},

		// Unknown fields at every level.
		{"unknown top", rep(att, `{"type"`, `{"extra":"1","type"`), minimal, apierr.UnknownField, "extra"},
		{"unknown payload", rep(att, `"slot":"61"`, `"slot":"61","committee_index":"0"`), minimal, apierr.UnknownField, "attestation.committee_index"},
		{"unknown nested", rep(att, `"source":{"epoch":"8"`, `"source":{"slot":"1","epoch":"8"`), minimal, apierr.UnknownField, "attestation.source.slot"},
		{"unknown fork", rep(att, `"epoch":"0"`, `"epoch":"0","next_version":"0x00000000"`), minimal, apierr.UnknownField, "fork_info.fork.next_version"},
		{"singular signature", rep(agg, `"signatures":[`, `"signature":"`+sigHex(9)+`","signatures":[`), minimal, apierr.UnknownField,
			"aggregate_and_proof.aggregate.signature"},
		{"singular contribution signature", rep(con, `"signatures":[`, `"signature":"`+sigHex(9)+`","signatures":[`), minimal,
			apierr.UnknownField, "contribution_and_proof.contribution.signature"},
		{"full block", rep(blk, `"version":"ZOND"`, `"version":"ZOND","block":{}`), minimal, apierr.UnknownField, "beacon_block.block"},
		{"V2 aggregate wrapper", rep(agg, `"aggregate_and_proof":{`, `"aggregate_and_proof":{"version":"ZOND","data":{},`), minimal,
			apierr.UnknownField, "aggregate_and_proof.version"},
		{"other payload key", rep(att, `{"type"`, `{"voluntary_exit":{},"type"`), minimal, apierr.UnknownField, "voluntary_exit"},
		{"fork_info on registration", rep(reg, `{"type"`, `{"fork_info":`+forkObj+`,"type"`), minimal, apierr.UnknownField, "fork_info"},
		{"case-folded key", rep(att, `"slot":"61"`, `"Slot":"61"`), minimal, apierr.UnknownField, "attestation.Slot"},
		{"case-folded alias", rep(att, `"signing_root"`, `"signingroot"`), minimal, apierr.UnknownField, "signingroot"},

		// Duplicate keys, also after unescaping.
		{"duplicate top", rep(att, `{"type":"ATTESTATION"`, `{"type":"ATTESTATION","type":"ATTESTATION"`), minimal, apierr.MalformedJSON, ""},
		{"duplicate nested", rep(att, `"slot":"61"`, `"slot":"61","slot":"62"`), minimal, apierr.MalformedJSON, ""},
		{"duplicate escaped", rep(att, `"slot":"61"`, `"slot":"61","slot":"61"`), minimal, apierr.MalformedJSON, ""},
		{"both roots", rep(att, `"signing_root"`, `"signingRoot":"`+rootHex+`","signing_root"`), minimal, apierr.MalformedJSON, ""},
		{"not JSON", att[:len(att)-1], minimal, apierr.MalformedJSON, ""},
		{"trailing data", att + `{}`, minimal, apierr.MalformedJSON, ""},

		// Wrong lengths and forms.
		{"short root", rep(att, `"beacon_block_root":"`+rootHex, `"beacon_block_root":"`+rootHex[:64]), minimal, apierr.BadField, "attestation.beacon_block_root"},
		{"long version", rep(att, `"previous_version":"0x000000fd"`, `"previous_version":"0x000000fd00"`), minimal, apierr.BadField,
			"fork_info.fork.previous_version"},
		{"short signature", rep(agg, `"`+sigHex(2)+`"`, `"`+sigHex(2)[:9254]+`"`), minimal, apierr.BadField, "aggregate_and_proof.aggregate.signatures[1]"},
		{"long selection proof", rep(agg, `"selection_proof":"`+sigHex(3), `"selection_proof":"`+sigHex(3)+`00`), minimal, apierr.BadField,
			"aggregate_and_proof.selection_proof"},
		{"short pubkey", rep(reg, `"pubkey":"0xa5a5`, `"pubkey":"0xa5`), minimal, apierr.BadField, "validator_registration.pubkey"},
		{"root without 0x", rep(att, `"signing_root":"0x`, `"signing_root":"`), minimal, apierr.BadField, "signing_root"},
		{"bad alias root", rep(att, `"signing_root":"`+rootHex, `"signingRoot":"0x12`), minimal, apierr.BadField, "signingRoot"},
		{"signatures not a list", rep(agg, `"signatures":[`, `"signatures":"x","sigs":[`), minimal, apierr.BadField, "aggregate_and_proof.aggregate.signatures"},
		{"bitlist without delimiter", rep(agg, `"aggregation_bits":"0x07"`, `"aggregation_bits":"0x00"`), minimal, apierr.BadField,
			"aggregate_and_proof.aggregate.aggregation_bits"},
		{"bitlist too long", rep(agg, `"aggregation_bits":"0x07"`, `"aggregation_bits":"0x0000000002"`), minimal, apierr.BadField,
			"aggregate_and_proof.aggregate.aggregation_bits"},
		{"mainnet bitvector on minimal", rep(con, `"0x0500"`, `"0x`+strings.Repeat("00", 15)+`05"`), minimal, apierr.BadField,
			"contribution_and_proof.contribution.aggregation_bits"},
		{"minimal bitvector on mainnet", con, mainnet, apierr.BadField, "contribution_and_proof.contribution.aggregation_bits"},

		// Addresses: Q only.
		{"0x address", rep(reg, `"Q`+q, `"0x`+q), minimal, apierr.BadField, "validator_registration.fee_recipient"},
		{"20-byte address", rep(reg, `"Q`+q, `"0x`+q[:40]), minimal, apierr.BadField, "validator_registration.fee_recipient"},
		{"lower-case q", rep(reg, `"Q`+q, `"q`+q), minimal, apierr.BadField, "validator_registration.fee_recipient"},

		// The type.
		{"lower-case type", rep(att, `"ATTESTATION"`, `"attestation"`), minimal, apierr.UnknownType, "type"},
		{"V2 type", rep(agg, `"AGGREGATE_AND_PROOF"`, `"AGGREGATE_AND_PROOF_V2"`), minimal, apierr.UnknownType, "type"},
		{"RANDAO type", rep(att, `"ATTESTATION"`, `"RANDAO_REVEAL"`), minimal, apierr.UnknownType, "type"},
		{"number type", rep(att, `"ATTESTATION"`, `7`), minimal, apierr.BadField, "type"},
		{"missing type", rep(att, `"type":"ATTESTATION",`, ``), minimal, apierr.BadField, "type"},
		{"block version", rep(blk, `"ZOND"`, `"PHASE0"`), minimal, apierr.BadField, "beacon_block.version"},

		// Envelope.
		{"missing fork_info", rep(sel, `"fork_info":`+forkObj+`,`, ``), minimal, apierr.MissingForkInfo, ""},
		{"null fork_info", rep(sel, `"fork_info":`+forkObj, `"fork_info":null`), minimal, apierr.BadField, "fork_info"},
		{"missing payload", rep(sel, `,"sync_aggregator_selection_data":{"slot":"61","subcommittee_index":"0"}`, ``), minimal,
			apierr.BadField, "sync_aggregator_selection_data"},
		{"missing payload field", rep(sel, `"slot":"61",`, ``), minimal, apierr.BadField, "sync_aggregator_selection_data.slot"},
		{"array body", `[` + att + `]`, minimal, apierr.BadField, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeSignRequest([]byte(tt.body), tt.p)
			var e *apierr.Error
			if !errors.As(err, &e) {
				t.Fatalf("want %s, got %v", tt.r, err)
			}
			if e.Reason != tt.r || e.Field != tt.field {
				t.Fatalf("got %s at %q, want %s at %q (%v)", e.Reason, e.Field, tt.r, tt.field, e)
			}
		})
	}
}

// A `signatures` array of tiny elements must not size the allocation by its
// count: a body near the 2 MiB sign-route limit holding a million zeros is
// refused at its first element after allocating a few MB, not 4.6 GB.
func TestSignaturesAllocationBound(t *testing.T) {
	const bodySize = 2 << 20
	bodies := validBodies()
	tests := []struct {
		name, body, list, field string
		p                       Params
	}{
		{"aggregate", bodies[signingroot.AggregateAndProof], `["` + sigHex(1) + `","` + sigHex(2) + `"]`,
			"aggregate_and_proof.aggregate.signatures[0]", minimal},
		{"contribution", bodies[signingroot.SyncCommitteeContributionAndProof], `["` + sigHex(5) + `","` + sigHex(6) + `"]`,
			"contribution_and_proof.contribution.signatures[0]", minimal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(tt.body, tt.list) {
				t.Fatal("signatures not in body")
			}
			n := (bodySize - len(tt.body)) / 2
			zeros := "[" + strings.Repeat("0,", n-1) + "0]"
			body := []byte(strings.Replace(tt.body, tt.list, zeros, 1))

			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			_, err := DecodeSignRequest(body, tt.p)
			runtime.ReadMemStats(&after)

			var e *apierr.Error
			if !errors.As(err, &e) || e.Reason != apierr.BadField || e.Field != tt.field {
				t.Fatalf("got %v, want BAD_FIELD at %s", err, tt.field)
			}
			if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 4<<20 {
				t.Errorf("decoding a %d-byte body of %d tiny signatures allocated %d bytes", len(body), n, alloc)
			}
		})
	}
}

func TestSigningRootAlias(t *testing.T) {
	body := strings.Replace(validBodies()[signingroot.Attestation], `"signing_root"`, `"signingRoot"`, 1)
	req, err := DecodeSignRequest([]byte(body), minimal)
	if err != nil {
		t.Fatal(err)
	}
	if req.SigningRoot == nil || hex.EncodeToString(req.SigningRoot[:]) != rootHex[2:] {
		t.Fatal("alias root not decoded")
	}
	// Encoding writes the canonical key.
	out, _ := json.Marshal(req)
	if !bytes.Contains(out, []byte(`"signing_root"`)) || bytes.Contains(out, []byte(`"signingRoot"`)) {
		t.Errorf("encoded %s", out[:120])
	}
	// The root is optional.
	noRoot := strings.Replace(validBodies()[signingroot.Attestation], `"signing_root":"`+rootHex+`",`, ``, 1)
	if req, err := DecodeSignRequest([]byte(noRoot), minimal); err != nil || req.SigningRoot != nil {
		t.Errorf("request without a root: %v", err)
	}
}

func TestDecodeErrors(t *testing.T) {
	if _, err := DecodeSignRequest([]byte(`{}`), Params{}); !errors.Is(err, ErrParams) {
		t.Errorf("zero params: %v", err)
	}
	if _, err := json.Marshal(SignRequest{}); err == nil {
		t.Error("a request without a payload encoded")
	}
}

func TestRandaoRevealDecoding(t *testing.T) {
	valid := `{"slot":"62","randao_commitment":"` + rootHex + `","fork_info":` + forkObj + `}`
	if _, err := DecodeRandaoRevealRequest([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		body  string
		r     apierr.Reason
		field string
	}{
		{strings.Replace(valid, `"62"`, `62`, 1), apierr.BadField, "slot"},
		{strings.Replace(valid, `,"fork_info":`+forkObj, ``, 1), apierr.MissingForkInfo, ""},
		{strings.Replace(valid, `{"slot"`, `{"epoch":"1","slot"`, 1), apierr.UnknownField, "epoch"},
		{strings.Replace(valid, `"randao_commitment":"`+rootHex, `"randao_commitment":"0x12`, 1), apierr.BadField, "randao_commitment"},
		{strings.Replace(valid, `"slot":"62",`, ``, 1), apierr.BadField, "slot"},
		{strings.Replace(valid, `"epoch":"0"`, `"epoch":"0","epoch":"0"`, 1), apierr.MalformedJSON, ""},
		{strings.Replace(valid, `"genesis_validators_root":"0x`, `"genesis_validators_root":"`, 1), apierr.BadField,
			"fork_info.genesis_validators_root"},
	}
	for _, tt := range tests {
		_, err := DecodeRandaoRevealRequest([]byte(tt.body))
		var e *apierr.Error
		if !errors.As(err, &e) || e.Reason != tt.r || e.Field != tt.field {
			t.Errorf("%.60s: got %v, want %s at %q", tt.body, err, tt.r, tt.field)
		}
	}
}

// The JSON field mapping reproduces the roots of ../testdata/containers.json,
// computed by an independent implementation: each fixture value is turned
// into the wire form of the request type that carries it and decoded.
func TestDecodedRootsMatchFixtures(t *testing.T) {
	raw, err := os.ReadFile("../testdata/containers.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			Type  string          `json:"type"`
			Name  string          `json:"name"`
			Value json.RawMessage `json:"value"`
			Root  string          `json:"root"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	wire := map[string]struct {
		typ, key string
		wrap     func(v string) string
	}{
		"BeaconBlockHeader":            {"BLOCK_V2", "beacon_block", func(v string) string { return `{"version":"ZOND","block_header":` + v + `}` }},
		"AttestationData":              {"ATTESTATION", "attestation", nil},
		"AggregateAttestationAndProof": {"AGGREGATE_AND_PROOF", "aggregate_and_proof", nil},
		"VoluntaryExit":                {"VOLUNTARY_EXIT", "voluntary_exit", nil},
		"SyncAggregatorSelectionData":  {"SYNC_COMMITTEE_SELECTION_PROOF", "sync_aggregator_selection_data", nil},
		"ContributionAndProof":         {"SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF", "contribution_and_proof", nil},
		"ValidatorRegistrationV1":      {"VALIDATOR_REGISTRATION", "validator_registration", nil},
		"Uint64":                       {"AGGREGATION_SLOT", "aggregation_slot", func(v string) string { return `{"slot":` + v + `}` }},
		"Bytes32": {"SYNC_COMMITTEE_MESSAGE", "sync_committee_message", func(v string) string {
			return `{"beacon_block_root":` + v + `,"slot":"0"}`
		}},
	}
	covered := map[string]bool{}
	for _, c := range doc.Cases {
		w, ok := wire[c.Type]
		if !ok {
			continue // nested-only containers
		}
		t.Run(c.Type+"/"+c.Name, func(t *testing.T) {
			v := wireValue(t, c.Value, "")
			if w.wrap != nil {
				v = w.wrap(v)
			}
			body := `{"type":"` + w.typ + `",`
			if w.typ != "VALIDATOR_REGISTRATION" {
				body += `"fork_info":` + forkObj + `,`
			}
			body += `"` + w.key + `":` + v + `}`
			// Contribution fixtures exist at both presets.
			req, err := DecodeSignRequest([]byte(body), minimal)
			if err != nil {
				req, err = DecodeSignRequest([]byte(body), mainnet)
			}
			if err != nil {
				t.Fatalf("%v\n%.400s", err, body)
			}
			got, err := req.Payload.ObjectRoot()
			if err != nil {
				t.Fatal(err)
			}
			if want := fxRoot(t, c.Root); got != want {
				t.Fatalf("root %x, want %x", got, want)
			}
			covered[c.Type] = true
		})
	}
	if len(covered) != len(wire) {
		t.Errorf("covered %d of %d payload types", len(covered), len(wire))
	}
}

// wireValue rewrites a fixture value into wire JSON: "pattern:<seed>"
// strings expand to hex of the field's length, and the 64-byte fee recipient
// takes the Q form.
func wireValue(t *testing.T, raw json.RawMessage, key string) string {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(rewrite(t, v, key))
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

var fieldLengths = map[string]int{
	"parent_root": 32, "state_root": 32, "body_root": 32, "root": 32, "beacon_block_root": 32, "": 32,
	"selection_proof": SignatureLength, "signatures": SignatureLength, "pubkey": PubkeyLength, "fee_recipient": AddressLength,
}

func rewrite(t *testing.T, v any, key string) any {
	switch v := v.(type) {
	case map[string]any:
		for k, e := range v {
			v[k] = rewrite(t, e, k)
		}
		return v
	case []any:
		for i, e := range v {
			v[i] = rewrite(t, e, key)
		}
		return v
	case string:
		n, ok := fieldLengths[key]
		if !ok || (!strings.HasPrefix(v, "pattern:") && !strings.HasPrefix(v, "0x")) {
			return v
		}
		if key == "" && !strings.HasPrefix(v, "pattern:") && len(v) != 66 {
			return v
		}
		b := fixtureBytes(t, v, n)
		if key == "fee_recipient" {
			return "Q" + hex.EncodeToString(b)
		}
		return "0x" + hex.EncodeToString(b)
	}
	return v
}

func TestArtifactTypes(t *testing.T) {
	got := ArtifactTypes()
	want := []signingroot.ArtifactType{
		signingroot.BlockV2, signingroot.Attestation, signingroot.AggregationSlot, signingroot.AggregateAndProof,
		signingroot.VoluntaryExit, signingroot.SyncCommitteeMessage, signingroot.SyncCommitteeSelectionProof,
		signingroot.SyncCommitteeContributionAndProof, signingroot.ValidatorRegistration,
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %v", got)
	}
	for _, typ := range got {
		if _, ok := signingroot.RuleFor(typ); !ok {
			t.Errorf("%s has no signing rule", typ)
		}
	}
}
