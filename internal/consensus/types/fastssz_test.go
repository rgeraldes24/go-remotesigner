// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/binary"
	"math/rand/v2"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/consensus/signingroot"
)

// The differential fuzz of PLAN S2b: every container, and ForkData and
// SigningData, is built from the fuzz input twice, once as ours and once as
// its fastssz mirror (fastssz_mirror_test.go), and the two hash-tree-roots
// must agree, including whether a list over its limit is refused. CI runs
//
//	go test -run '^$' -fuzz '^FuzzHashTreeRootDifferential$' -fuzztime 10s ./internal/consensus/types/

// gen draws values from fuzz input. Counts and fixed fields come from the
// input; bulk bytes (signatures, public keys) come from a PRNG seeded by
// it, so small inputs still reach the large containers.
type gen struct {
	in  []byte
	rng *rand.Rand
}

// newGen seeds the PRNG from the first 16 input bytes.
func newGen(in []byte) *gen {
	g := &gen{in: in}
	g.rng = rand.New(rand.NewPCG(g.raw64(), g.raw64()))
	return g
}

func (g *gen) raw64() uint64 {
	var b [8]byte
	for i := range b {
		b[i] = g.byte()
	}
	return binary.LittleEndian.Uint64(b[:])
}

func (g *gen) byte() byte {
	if len(g.in) == 0 {
		return 0
	}
	b := g.in[0]
	g.in = g.in[1:]
	return b
}

// u64 takes 8 input bytes (zero when exhausted). A leading 0xff or 0xfe
// selects an edge value, so the fuzzer finds them cheaply.
func (g *gen) u64() uint64 {
	switch g.byte() {
	case 0xff:
		return ^uint64(0)
	case 0xfe:
		return 0
	}
	return g.raw64()
}

func (g *gen) intn(n int) int { return int(g.byte()) % n }

func (g *gen) fill(b []byte) []byte {
	for i := range b {
		b[i] = byte(g.rng.Uint32())
	}
	return b
}

func (g *gen) root() [32]byte {
	var r [32]byte
	for i := range r {
		r[i] = g.byte()
	}
	return r
}

// bitlist returns a serialized Bitlist[32]: a bit length of 0-32, random
// bits and the delimiter.
func (g *gen) bitlist() []byte {
	n := g.intn(33)
	b := make([]byte, n/8+1)
	for i := 0; i < n; i++ {
		if g.rng.IntN(2) == 1 {
			b[i/8] |= 1 << (i % 8)
		}
	}
	b[n/8] |= 1 << (n % 8)
	return b
}

// signatures returns 0 to limit+1 signatures: one past the limit is refused
// by both sides.
func (g *gen) signatures(limit int) ([]Signature, [][]byte) {
	n := g.intn(limit + 2)
	ours := make([]Signature, n)
	theirs := make([][]byte, n)
	for i := range ours {
		g.fill(ours[i][:])
		theirs[i] = ours[i][:]
	}
	return ours, theirs
}

type rooter interface{ HashTreeRoot() ([32]byte, error) }

func (g *gen) header() (*BeaconBlockHeader, *mirrorHeader) {
	h := &BeaconBlockHeader{Slot: g.u64(), ProposerIndex: g.u64(), ParentRoot: g.root(), StateRoot: g.root(), BodyRoot: g.root()}
	return h, &mirrorHeader{h.Slot, h.ProposerIndex, h.ParentRoot[:], h.StateRoot[:], h.BodyRoot[:]}
}

func (g *gen) data() (*AttestationData, *mirrorAttestationData) {
	d := &AttestationData{Slot: g.u64(), Index: g.u64(), BeaconBlockRoot: g.root(),
		Source: Checkpoint{g.u64(), g.root()}, Target: Checkpoint{g.u64(), g.root()}}
	return d, &mirrorAttestationData{d.Slot, d.Index, d.BeaconBlockRoot[:],
		&mirrorCheckpoint{d.Source.Epoch, d.Source.Root[:]}, &mirrorCheckpoint{d.Target.Epoch, d.Target.Root[:]}}
}

func (g *gen) attestation() (*Attestation, *mirrorAttestation) {
	bits := g.bitlist()
	d, md := g.data()
	sigs, msigs := g.signatures(MaxAttestationSignatures)
	return &Attestation{bits, *d, sigs}, &mirrorAttestation{bits, md, msigs}
}

func (g *gen) contribution(mainnetPreset bool) (*SyncCommitteeContribution, any) {
	c := &SyncCommitteeContribution{Slot: g.u64(), BeaconBlockRoot: g.root(), SubcommitteeIndex: g.u64()}
	if mainnetPreset {
		c.AggregationBits = g.fill(make([]byte, 16))
	} else {
		c.AggregationBits = g.fill(make([]byte, 2))
	}
	var msigs [][]byte
	c.Signatures, msigs = g.signatures(MaxContributionSignatures)
	if mainnetPreset {
		return c, &mirrorContributionMainnet{c.Slot, c.BeaconBlockRoot[:], c.SubcommitteeIndex, c.AggregationBits, msigs}
	}
	return c, &mirrorContributionMinimal{c.Slot, c.BeaconBlockRoot[:], c.SubcommitteeIndex, c.AggregationBits, msigs}
}

// pair builds one container of the kind the first input byte selects.
func (g *gen) pair() (name string, ours, theirs rooter) {
	switch g.intn(13) {
	case 0:
		o, m := g.header()
		return "BeaconBlockHeader", o, m
	case 1:
		o, m := g.data()
		return "AttestationData", o, m
	case 2:
		o, m := g.attestation()
		return "Attestation", o, m
	case 3:
		idx := g.u64()
		a, ma := g.attestation()
		o := &AggregateAttestationAndProof{AggregatorIndex: idx, Aggregate: *a}
		g.fill(o.SelectionProof[:])
		return "AggregateAttestationAndProof", o, &mirrorAggregateAndProof{idx, ma, o.SelectionProof[:]}
	case 4:
		o := VoluntaryExit{g.u64(), g.u64()}
		return "VoluntaryExit", o, &mirrorVoluntaryExit{o.Epoch, o.ValidatorIndex}
	case 5:
		o := SyncAggregatorSelectionData{g.u64(), g.u64()}
		return "SyncAggregatorSelectionData", o, &mirrorSelectionData{o.Slot, o.SubcommitteeIndex}
	case 6, 7:
		mainnetPreset := g.byte()%2 == 1
		c, mc := g.contribution(mainnetPreset)
		return "SyncCommitteeContribution", c, mc.(rooter)
	case 8, 9:
		mainnetPreset := g.byte()%2 == 1
		idx := g.u64()
		c, mc := g.contribution(mainnetPreset)
		o := &ContributionAndProof{AggregatorIndex: idx, Contribution: *c}
		g.fill(o.SelectionProof[:])
		if mainnetPreset {
			return "ContributionAndProof", o, &mirrorContributionAndProofMainnet{idx, mc.(*mirrorContributionMainnet), o.SelectionProof[:]}
		}
		return "ContributionAndProof", o, &mirrorContributionAndProofMinimal{idx, mc.(*mirrorContributionMinimal), o.SelectionProof[:]}
	case 10:
		o := &ValidatorRegistrationV1{GasLimit: g.u64(), Timestamp: g.u64()}
		g.fill(o.FeeRecipient[:])
		g.fill(o.Pubkey[:])
		return "ValidatorRegistrationV1", o, &mirrorRegistration{o.FeeRecipient[:], o.GasLimit, o.Timestamp, o.Pubkey[:]}
	case 11:
		v := signingroot.Version{g.byte(), g.byte(), g.byte(), g.byte()}
		gvr := g.root()
		return "ForkData", forkData{v, gvr}, &mirrorForkData{v[:], gvr[:]}
	default:
		obj, dom := g.root(), signingroot.Domain(g.root())
		return "SigningData", signingData{obj, dom}, &mirrorSigningData{obj[:], dom[:]}
	}
}

type forkData struct {
	v   signingroot.Version
	gvr [32]byte
}

func (f forkData) HashTreeRoot() ([32]byte, error) {
	return signingroot.ComputeForkDataRoot(f.v, f.gvr), nil
}

type signingData struct {
	obj [32]byte
	dom signingroot.Domain
}

func (s signingData) HashTreeRoot() ([32]byte, error) {
	return signingroot.ComputeSigningRoot(s.obj, s.dom), nil
}

func checkDifferential(t *testing.T, in []byte) {
	name, ours, theirs := newGen(in).pair()
	a, errA := ours.HashTreeRoot()
	b, errB := theirs.HashTreeRoot()
	if (errA == nil) != (errB == nil) {
		t.Fatalf("%s: ours err=%v, fastssz err=%v", name, errA, errB)
	}
	if errA == nil && a != b {
		t.Fatalf("%s: root %x, fastssz %x", name, a, b)
	}
}

func FuzzHashTreeRootDifferential(f *testing.F) {
	for kind := range 13 {
		f.Add(append(make([]byte, 16), byte(kind)))
		f.Add(append(make([]byte, 16), byte(kind), 0xff, 0xff, 0xff, 32, 33, 128, 129))
	}
	f.Fuzz(checkDifferential)
}

// TestHashTreeRootDifferential runs the fuzz body on fixed random inputs, so
// that plain `go test` covers every kind.
func TestHashTreeRootDifferential(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	n := 600
	if testing.Short() {
		n = 100
	}
	for range n {
		in := make([]byte, 64+rng.IntN(64))
		for i := range in {
			in[i] = byte(rng.Uint32())
		}
		checkDifferential(t, in)
	}
}
