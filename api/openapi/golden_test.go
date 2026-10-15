// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package openapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/vectors"
)

// specExampleCases returns the golden spec_example cases by type.
func specExampleCases(t *testing.T) map[string]vectors.SignCase {
	t.Helper()
	out := map[string]vectors.SignCase{}
	for _, c := range vectors.Signing(t) {
		if c.Name == "spec_example" {
			out[c.Type] = c
		}
	}
	return out
}

// TestSignExamplesAreGoldenVectors checks that every sign request example is
// the spec_example golden vector of its type (testdata/vectors), so each
// example's signing root is qrysm's.
func TestSignExamplesAreGoldenVectors(t *testing.T) {
	golden := specExampleCases(t)
	types := enumStrings(t, schema(t, "ArtifactType"))
	if len(golden) != len(types) {
		t.Fatalf("%d spec_example vectors, want one per type (%d)", len(golden), len(types))
	}
	for _, typ := range types {
		t.Run(typ, func(t *testing.T) {
			c, ok := golden[typ]
			if !ok {
				t.Fatalf("no spec_example vector for %s", typ)
			}
			var want any
			if err := json.Unmarshal(c.RequestJSON, &want); err != nil {
				t.Fatal(err)
			}
			if got := any(signExample(t, typ)); !reflect.DeepEqual(got, want) {
				t.Errorf("example differs from the golden vector\n got %.400v\nwant %.400v", got, want)
			}
		})
	}
}

// TestOtherExamplesAreGolden checks the examples that go with the sign
// examples: the identifier is interop key 0, the signature is key 0's
// deterministic signature of the AGGREGATION_SLOT example, and the RANDAO
// example is key 0's V4 commitment and first reveal on the same network.
func TestOtherExamplesAreGolden(t *testing.T) {
	doc := loadSpec(t)
	golden := specExampleCases(t)
	key0 := vectors.Keys(t)[0]

	ids := doc.Components.Parameters["Identifier"].Value.Examples
	if got := ids["canonical"]; got == nil || got.Value.Value != key0.Pubkey {
		t.Errorf("Identifier example is not interop key 0's public key")
	}
	short := sha256.Sum256(vectors.Hex(t, key0.Pubkey))
	if got := ids["short"]; got == nil || got.Value.Value != "0x"+hex.EncodeToString(short[:]) {
		t.Errorf("short Identifier example is not sha256 of interop key 0's public key")
	}
	sign := doc.Paths.Value("/api/v1/consensus/sign/{identifier}").Post
	resp := sign.Responses.Status(200).Value.Content.Get("application/json").Example.(map[string]any)
	if want := golden["AGGREGATION_SLOT"].DeterministicSignature; resp["signature"] != want {
		t.Errorf("signature example is not the deterministic signature of the AGGREGATION_SLOT example")
	}

	gvr := golden["ATTESTATION"].Network.GVR
	randao := doc.Paths.Value("/api/v1/consensus/randao_reveal/{identifier}").Post
	req := randao.RequestBody.Value.Content.Get("application/json").Example.(map[string]any)
	if req["randao_commitment"] != key0.RandaoCommitment {
		t.Errorf("RANDAO example commitment %v, want key 0's %s", req["randao_commitment"], key0.RandaoCommitment)
	}
	if got := at(req, "fork_info")["genesis_validators_root"]; got != gvr {
		t.Errorf("RANDAO example GVR %v, want %s", got, gvr)
	}
	reveal := randao.Responses.Status(200).Value.Content.Get("application/json").Example.(map[string]any)
	if reveal["randao_reveal"] != key0.RandaoFirstReveal {
		t.Errorf("RANDAO example reveal %v, want key 0's first reveal %s", reveal["randao_reveal"], key0.RandaoFirstReveal)
	}

	caps := doc.Paths.Value("/api/v1/consensus/capabilities").Get.Responses.Status(200).Value.Content.Get("application/json")
	pinned := caps.Examples["pinned"].Value.Value.(map[string]any)
	if got := at(pinned, "network")["genesis_validators_root"]; got != gvr {
		t.Errorf("capabilities example GVR %v, want %s", got, gvr)
	}
}
