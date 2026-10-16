// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/consensus/signingroot"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/types"
	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/metrics"
)

// value reads a counter or gauge.
func value(t *testing.T, c prometheus.Metric) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatal(err)
	}
	if g := m.GetGauge(); g != nil {
		return g.GetValue()
	}
	return m.GetCounter().GetValue()
}

func newKey(t *testing.T, b byte) *mldsa87.Key {
	t.Helper()
	var seed [mldsa87.SeedSize]byte
	seed[0] = b
	k, err := mldsa87.FromSeed48(&seed)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// faulty corrupts every signature of the key it wraps, as a fault in the
// signing computation would.
type faulty struct {
	*mldsa87.Key
}

func (f *faulty) Sign(m []byte, mode mldsa87.Mode) (Signature, error) {
	sig, err := f.Key.Sign(m, mode)
	sig[100] ^= 0x01
	return sig, err
}

// keyset is a mutable lookup.
type keyset struct {
	mu   sync.Mutex
	keys map[ID]Key
}

func (s *keyset) get(id ID) (Key, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	return k, ok
}

func (s *keyset) set(id ID, k Key) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[id] = k
}

func newSigner(t *testing.T, mode mldsa87.Mode) (*Signer, *keyset, *metrics.Metrics) {
	t.Helper()
	m, err := metrics.New(metrics.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ks := &keyset{keys: map[ID]Key{}}
	l := logrus.New()
	l.SetOutput(io.Discard)
	return New(Config{Lookup: ks.get, SelectionProofMode: mode, Metrics: m, Log: l}), ks, m
}

func TestModeFor(t *testing.T) {
	for _, sel := range []mldsa87.Mode{mldsa87.Deterministic, mldsa87.Hedged} {
		s, _, _ := newSigner(t, sel)
		for _, ty := range types.ArtifactTypes() {
			want := mldsa87.Hedged
			if ty == signingroot.AggregationSlot || ty == signingroot.SyncCommitteeSelectionProof {
				want = sel
			}
			if got := s.ModeFor(ty); got != want {
				t.Errorf("selection %v: ModeFor(%s) = %v, want %v", sel, ty, got, want)
			}
		}
	}
}

// Signatures verify; deterministic types repeat byte for byte and hedged
// ones do not.
func TestSignModes(t *testing.T) {
	s, ks, _ := newSigner(t, mldsa87.Deterministic)
	k := newKey(t, 1)
	ks.set(k.ID(), k)
	root := [32]byte{7}
	sign := func(ty signingroot.ArtifactType) Signature {
		t.Helper()
		key, err := s.Lookup(k.ID())
		if err != nil {
			t.Fatal(err)
		}
		sig, err := s.Sign(k.ID(), key, ty, root)
		if err != nil {
			t.Fatal(err)
		}
		if !k.Verify(root[:], sig[:]) {
			t.Fatal("released signature does not verify")
		}
		return sig
	}
	if first, second := sign(signingroot.AggregationSlot), sign(signingroot.AggregationSlot); first != second {
		t.Error("deterministic selection proofs differ")
	}
	if first, second := sign(signingroot.Attestation), sign(signingroot.Attestation); first == second {
		t.Error("hedged attestations are identical")
	}
}

// A corrupted signature is never released; the key is quarantined
// until a key load replaces it.
func TestSignatureFaultQuarantines(t *testing.T) {
	s, ks, m := newSigner(t, mldsa87.Deterministic)
	k := newKey(t, 2)
	bad := &faulty{k}
	ks.set(k.ID(), bad)

	sig, err := s.Sign(k.ID(), bad, signingroot.BlockV2, [32]byte{1})
	if !errors.Is(err, ErrSignatureFault) || sig != (Signature{}) {
		t.Fatalf("Sign = %x…, %v; want zero bytes and ErrSignatureFault", sig[:8], err)
	}
	if got := value(t, m.VerifyFailures); got != 1 {
		t.Errorf("signing_verify_failures_total = %v", got)
	}
	if got := value(t, m.KeysQuarantined); got != 1 {
		t.Errorf("signing_keys_quarantined = %v", got)
	}
	if _, err := s.Lookup(k.ID()); !errors.Is(err, ErrQuarantined) {
		t.Fatalf("Lookup of a quarantined key = %v", err)
	}
	if _, err := s.Sign(k.ID(), bad, signingroot.BlockV2, [32]byte{1}); !errors.Is(err, ErrQuarantined) {
		t.Fatalf("Sign with a quarantined key = %v", err)
	}

	// A load that keeps the faulty object keeps the quarantine.
	if n := s.Release(); n != 1 {
		t.Fatalf("Release kept %d keys quarantined, want 1", n)
	}
	// A load that renews the key lifts it.
	fresh := newKey(t, 2)
	ks.set(k.ID(), fresh)
	if n := s.Release(); n != 0 || s.Quarantined(k.ID()) {
		t.Fatalf("Release after renewal: %d quarantined", n)
	}
	if got := value(t, m.KeysQuarantined); got != 0 {
		t.Errorf("signing_keys_quarantined = %v after release", got)
	}
	key, err := s.Lookup(k.ID())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign(k.ID(), key, signingroot.BlockV2, [32]byte{1}); err != nil {
		t.Fatalf("Sign after renewal = %v", err)
	}
}

func TestSignRemovedKey(t *testing.T) {
	s, ks, _ := newSigner(t, mldsa87.Deterministic)
	if _, err := s.Lookup(ID{1}); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("Lookup of an unknown key = %v", err)
	}
	k := newKey(t, 3)
	ks.set(k.ID(), k)
	key, err := s.Lookup(k.ID())
	if err != nil {
		t.Fatal(err)
	}
	k.Zeroize() // removed between lookup and signing
	if _, err := s.Sign(k.ID(), key, signingroot.Attestation, [32]byte{}); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("Sign with a zeroized key = %v", err)
	}
}
