// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/json"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/consensus/signingroot"
)

// Benchmarks B5 and B6 (docs/benchmarks.md).

// fullContribution is the largest valid sign request: a mainnet-preset
// contribution with all 128 bits set and 128 signatures, about 1.2 MB.
func fullContribution(b *testing.B) (*SignRequest, []byte) {
	b.Helper()
	g := newGen(make([]byte, 16))
	c := &ContributionAndProof{AggregatorIndex: 7}
	g.fill(c.SelectionProof[:])
	c.Contribution = SyncCommitteeContribution{Slot: 61, AggregationBits: make([]byte, 16),
		Signatures: make([]Signature, MaxContributionSignatures)}
	for i := range c.Contribution.AggregationBits {
		c.Contribution.AggregationBits[i] = 0xff
	}
	for i := range c.Contribution.Signatures {
		g.fill(c.Contribution.Signatures[i][:])
	}
	req := &SignRequest{ForkInfo: &ForkInfo{}, Payload: c}
	body, err := json.Marshal(req)
	if err != nil {
		b.Fatal(err)
	}
	return req, body
}

func fullAggregate() *SignRequest {
	g := newGen(make([]byte, 16))
	p := &AggregateAttestationAndProof{AggregatorIndex: 17}
	p.Aggregate.AggregationBits = []byte{0xff, 0xff, 0xff, 0xff, 0x01}
	p.Aggregate.Signatures = make([]Signature, MaxAttestationSignatures)
	for i := range p.Aggregate.Signatures {
		g.fill(p.Aggregate.Signatures[i][:])
	}
	g.fill(p.SelectionProof[:])
	return &SignRequest{ForkInfo: &ForkInfo{}, Payload: p}
}

func benchSigningRoot(b *testing.B, req *SignRequest) {
	chain, _ := signingroot.NewChain(signingroot.Version{0, 0, 0, 0xfd}, [32]byte{1}, 6)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := req.SigningRootFor(chain); err != nil {
			b.Fatal(err)
		}
	}
}

// B5: hash-tree-root plus signing root. Thresholds: ≤ 10 ms, ≤ 3 ms, ≤ 50 µs.
func BenchmarkSigningRootContributionAndProof(b *testing.B) {
	req, _ := fullContribution(b)
	benchSigningRoot(b, req)
}

func BenchmarkSigningRootAggregateAndProof(b *testing.B) {
	benchSigningRoot(b, fullAggregate())
}

func BenchmarkSigningRootAttestationData(b *testing.B) {
	benchSigningRoot(b, &SignRequest{ForkInfo: &ForkInfo{}, Payload: &AttestationData{Slot: 61}})
}

// B6: strict decode of the 1.2 MB contribution, including the pre-scan.
// Threshold: ≤ 20 ms and ≤ 6 MB allocated per request.
func BenchmarkDecodeContribution(b *testing.B) {
	_, body := fullContribution(b)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := DecodeSignRequest(body, mainnet); err != nil {
			b.Fatal(err)
		}
	}
}
