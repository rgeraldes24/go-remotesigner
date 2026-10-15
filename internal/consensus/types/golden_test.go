// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/signingroot"
	"github.com/rgeraldes24/go-remotesigner/internal/vectors"
)

// The golden vectors of testdata/vectors were computed by qrysm's own code
// (tools/vectorgen). These tests check the decoder, the hash-tree-roots and
// the canonical encoder against them.

// goldenChain is the signing chain of a fixture network.
func goldenChain(t *testing.T, n vectors.Network) signingroot.Chain {
	t.Helper()
	c, err := signingroot.NewChain(signingroot.Version(vectors.Hex(t, n.GenesisForkVersion)),
		vectors.Hex32(t, n.GVR), vectors.U64(t, n.SlotsPerEpoch))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// goldenParams are the decoder parameters of a fixture network.
func goldenParams(t *testing.T, n vectors.Network) Params {
	t.Helper()
	info := vectors.NetworkByConfigName(t, n.ConfigName)
	return Params{SyncSubcommitteeSize: vectors.U64(t, info.SyncCommitteeSize) / vectors.U64(t, info.SyncCommitteeSubnetCount)}
}

func compactJSON(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := json.Compact(&buf, b); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestGoldenSignRequests decodes every golden request_json and checks the
// object root, the signing root and the canonical encoding.
func TestGoldenSignRequests(t *testing.T) {
	cases := vectors.Signing(t)
	if len(cases) < 100 {
		t.Fatalf("only %d golden sign requests", len(cases))
	}
	seen := map[string]bool{}
	for i := range cases {
		c := &cases[i]
		seen[c.Preset+"/"+c.Type] = true
		t.Run(c.ID(), func(t *testing.T) {
			req, err := DecodeSignRequest(c.RequestJSON, goldenParams(t, c.Network))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got := string(req.Type()); got != c.Type {
				t.Fatalf("type %s, want %s", got, c.Type)
			}
			root, err := req.Payload.ObjectRoot()
			if err != nil {
				t.Fatal(err)
			}
			if root != vectors.Hex32(t, c.ObjectRoot) {
				t.Errorf("object root %#x, want %s", root, c.ObjectRoot)
			}
			sr, err := req.SigningRootFor(goldenChain(t, c.Network))
			if err != nil {
				t.Fatal(err)
			}
			if sr != vectors.Hex32(t, c.SigningRoot) {
				t.Errorf("signing root %#x, want %s", sr, c.SigningRoot)
			}
			if req.SigningRoot == nil || *req.SigningRoot != sr {
				t.Errorf("request signing_root %x differs from the recomputed root", req.SigningRoot)
			}
			out, err := req.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			if want := compactJSON(t, c.RequestJSON); !bytes.Equal(out, want) {
				t.Errorf("canonical encoding differs from the golden request_json\n got %.300s\nwant %.300s", out, want)
			}
			if c.Block != nil {
				if c.Block.FullRoot != c.ObjectRoot || c.Block.BlindedRoot != c.ObjectRoot {
					t.Errorf("full %s and blinded %s block roots differ from the header root %s",
						c.Block.FullRoot, c.Block.BlindedRoot, c.ObjectRoot)
				}
			}
		})
	}
	for _, p := range vectors.Presets {
		for _, typ := range ArtifactTypes() {
			if !seen[p+"/"+string(typ)] {
				t.Errorf("no golden %s request on the %s preset", typ, p)
			}
		}
	}
}

// expander rebuilds the seed-expanded random objects of roots/ from the
// description in testdata/vectors/README.md ("Seed expansion").
type expander struct {
	seed, counter uint64
	buf           []byte
}

const expansionTag = "qrl-remotesigner-vectors-v1"

func (e *expander) next(n int) []byte {
	for len(e.buf) < n {
		block := make([]byte, 0, len(expansionTag)+16)
		block = append(block, expansionTag...)
		block = binary.LittleEndian.AppendUint64(block, e.seed)
		block = binary.LittleEndian.AppendUint64(block, e.counter)
		e.counter++
		h := sha256.Sum256(block)
		e.buf = append(e.buf, h[:]...)
	}
	out := e.buf[:n:n]
	e.buf = e.buf[n:]
	return out
}

func (e *expander) u64() uint64        { return binary.LittleEndian.Uint64(e.next(8)) }
func (e *expander) root() (r [32]byte) { return [32]byte(e.next(32)) }
func (e *expander) bit() bool          { return e.next(1)[0]&1 == 1 }

func (e *expander) signatures(n int) []Signature {
	out := make([]Signature, n)
	for i := range out {
		out[i] = Signature(e.next(SignatureLength))
	}
	return out
}

// bits reads n bits into a little-endian bit array of size bytes and
// returns it with its popcount.
func (e *expander) bits(n, size int) ([]byte, int) {
	b := make([]byte, size)
	set := 0
	for i := range n {
		if e.bit() {
			b[i/8] |= 1 << (i % 8)
			set++
		}
	}
	return b, set
}

func (e *expander) attestationData() AttestationData {
	var d AttestationData
	d.Slot, d.Index, d.BeaconBlockRoot = e.u64(), e.u64(), e.root()
	d.Source.Epoch, d.Source.Root = e.u64(), e.root()
	d.Target.Epoch, d.Target.Root = e.u64(), e.root()
	return d
}

// expand returns the payload of type t for seed.
func expand(t signingroot.ArtifactType, seed uint64, subcommitteeBits int) Payload {
	e := &expander{seed: seed}
	switch t {
	case signingroot.BlockV2:
		var h BeaconBlockHeader
		h.Slot, h.ProposerIndex = e.u64(), e.u64()
		h.ParentRoot, h.StateRoot, h.BodyRoot = e.root(), e.root(), e.root()
		return &BlockV2{Header: h}
	case signingroot.Attestation:
		d := e.attestationData()
		return &d
	case signingroot.AggregationSlot:
		return &AggregationSlot{Slot: e.u64()}
	case signingroot.AggregateAndProof:
		p := &AggregateAttestationAndProof{AggregatorIndex: e.u64()}
		n := int(e.next(1)[0]) % 33
		bits, set := e.bits(n, n/8+1)
		bits[n/8] |= 1 << (n % 8) // delimiter
		p.Aggregate.AggregationBits = bits
		p.Aggregate.Data = e.attestationData()
		p.Aggregate.Signatures = e.signatures(set)
		p.SelectionProof = Signature(e.next(SignatureLength))
		return p
	case signingroot.VoluntaryExit:
		var x VoluntaryExit
		x.Epoch, x.ValidatorIndex = e.u64(), e.u64()
		return &x
	case signingroot.SyncCommitteeMessage:
		var m SyncCommitteeMessage
		m.BeaconBlockRoot, m.Slot = e.root(), e.u64()
		return &m
	case signingroot.SyncCommitteeSelectionProof:
		var s SyncAggregatorSelectionData
		s.Slot, s.SubcommitteeIndex = e.u64(), e.u64()
		return &s
	case signingroot.SyncCommitteeContributionAndProof:
		p := &ContributionAndProof{AggregatorIndex: e.u64()}
		c := &p.Contribution
		c.Slot, c.BeaconBlockRoot, c.SubcommitteeIndex = e.u64(), e.root(), e.u64()
		bits, set := e.bits(subcommitteeBits, subcommitteeBits/8)
		c.AggregationBits = bits
		c.Signatures = e.signatures(set)
		p.SelectionProof = Signature(e.next(SignatureLength))
		return p
	case signingroot.ValidatorRegistration:
		var r ValidatorRegistrationV1
		r.FeeRecipient = Address(e.next(AddressLength))
		r.GasLimit, r.Timestamp = e.u64(), e.u64()
		r.Pubkey = Pubkey(e.next(PubkeyLength))
		return &r
	}
	panic("unknown type " + string(t))
}

// TestGoldenRandomRoots rebuilds every seed-expanded object of roots/ with
// this package's types and compares its roots with qrysm's.
func TestGoldenRandomRoots(t *testing.T) {
	files := vectors.Roots(t)
	if len(files) != len(vectors.Presets)*len(ArtifactTypes()) {
		t.Fatalf("%d root files, want one per type and preset", len(files))
	}
	for _, f := range files {
		t.Run(f.Preset+"/"+f.Type, func(t *testing.T) {
			if len(f.Cases) < 500 {
				t.Fatalf("only %d seeds", len(f.Cases))
			}
			chain := goldenChain(t, f.Network)
			typ := signingroot.ArtifactType(f.Type)
			for _, c := range f.Cases {
				p := expand(typ, c.Seed, int(f.SyncSubcommitteeBits))
				root, err := p.ObjectRoot()
				if err != nil {
					t.Fatalf("seed %d: %v", c.Seed, err)
				}
				if root != vectors.Hex32(t, c.ObjectRoot) {
					t.Fatalf("seed %d: object root %#x, want %s", c.Seed, root, c.ObjectRoot)
				}
				d, err := chain.DomainFor(typ, p.DomainAt())
				if err != nil {
					t.Fatal(err)
				}
				if d != signingroot.Domain(vectors.Hex32(t, c.Domain)) {
					t.Fatalf("seed %d: domain %#x, want %s", c.Seed, d, c.Domain)
				}
				if sr := signingroot.ComputeSigningRoot(root, d); sr != vectors.Hex32(t, c.SigningRoot) {
					t.Fatalf("seed %d: signing root %#x, want %s", c.Seed, sr, c.SigningRoot)
				}
			}
		})
	}
}

// decodeReasons are the reasons the strict decoder gives; the other 400s
// come from the policy and need a decoded request.
var decodeReasons = map[apierr.Reason]bool{
	apierr.MalformedJSON:   true,
	apierr.UnknownField:    true,
	apierr.BadField:        true,
	apierr.UnknownType:     true,
	apierr.MissingForkInfo: true,
}

// TestGoldenNegativeDecode runs the negative fixtures through the decoder:
// decoder reasons must match, and policy-stage cases must decode.
func TestGoldenNegativeDecode(t *testing.T) {
	checked := 0
	for _, f := range vectors.Negative(t) {
		params := goldenParams(t, f.Network)
		for _, c := range f.Cases {
			if c.Identifier != "" {
				continue // BAD_IDENTIFIER is the server's path check
			}
			t.Run(f.Preset+"/"+c.Name, func(t *testing.T) {
				_, err := DecodeSignRequest([]byte(c.RequestBody), params)
				want := apierr.Reason(c.Expect.Reason)
				if !decodeReasons[want] {
					if err != nil {
						t.Fatalf("policy-stage case does not decode: %v", err)
					}
					return
				}
				var e *apierr.Error
				if !errors.As(err, &e) {
					t.Fatalf("got %v, want %s", err, want)
				}
				if e.Reason != want || e.Status() != c.Expect.Status {
					t.Errorf("got %d %s (%v), want %d %s", e.Status(), e.Reason, e, c.Expect.Status, want)
				}
			})
			checked++
		}
	}
	if checked < 60 {
		t.Fatalf("checked only %d negative fixtures", checked)
	}
}
