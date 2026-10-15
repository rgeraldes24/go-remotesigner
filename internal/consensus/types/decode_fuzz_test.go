// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
)

// FuzzDecodeSignRequest feeds arbitrary bodies to the decoder (G4 S9). It
// must never panic, must refuse with a 400-class reason, and anything it
// accepts must re-encode canonically, decode to the same request and hash
// without error unless a list is over its limit.
func FuzzDecodeSignRequest(f *testing.F) {
	for _, body := range validBodies() {
		f.Add([]byte(body), false)
	}
	f.Add([]byte(`{"type":"ATTESTATION","type":"ATTESTATION"}`), false)
	f.Add([]byte(`{"type":"SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF"}`), true)
	f.Fuzz(func(t *testing.T, body []byte, mainnetPreset bool) {
		p := minimal
		if mainnetPreset {
			p = mainnet
		}
		req, err := DecodeSignRequest(body, p)
		if err != nil {
			r, ok := apierr.ReasonOf(err)
			if !ok || r.Status() != 400 {
				t.Fatalf("refusal %v is not a 400 reason", err)
			}
			return
		}
		out, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		again, err := DecodeSignRequest(out, p)
		if err != nil {
			t.Fatalf("canonical form refused: %v", err)
		}
		out2, err := json.Marshal(again)
		if err != nil || !bytes.Equal(out, out2) {
			t.Fatalf("encoding is not stable: %v", err)
		}
		if _, err := req.Payload.ObjectRoot(); err != nil && !overLimit(req) {
			t.Fatalf("accepted request has no root: %v", err)
		}
	})
}

// overLimit reports a signature list longer than its SSZ limit, which the
// decoder accepts and the policy refuses as INVARIANT_VIOLATION.
func overLimit(req *SignRequest) bool {
	switch pl := req.Payload.(type) {
	case *AggregateAttestationAndProof:
		return len(pl.Aggregate.Signatures) > MaxAttestationSignatures
	case *ContributionAndProof:
		return len(pl.Contribution.Signatures) > MaxContributionSignatures
	}
	return false
}

// FuzzDecodeRandaoRevealRequest is the same property for RANDAO bodies.
func FuzzDecodeRandaoRevealRequest(f *testing.F) {
	f.Add([]byte(`{"slot":"62","randao_commitment":"` + rootHex + `","fork_info":` + forkObj + `}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		req, err := DecodeRandaoRevealRequest(body)
		if err != nil {
			if r, ok := apierr.ReasonOf(err); !ok || r.Status() != 400 {
				t.Fatalf("refusal %v is not a 400 reason", err)
			}
			return
		}
		out, _ := json.Marshal(req)
		again, err := DecodeRandaoRevealRequest(out)
		if err != nil || *again != *req {
			t.Fatalf("round trip: %v", err)
		}
	})
}
