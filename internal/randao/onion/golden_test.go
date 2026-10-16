// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package onion

import (
	"cmp"
	"fmt"
	"slices"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/vectors"
)

// The golden RANDAO vectors (testdata/vectors/randao) were computed by
// qrysm's crypto/randao. These tests check the package, which was written
// from docs/spec/randao-onion.md only, against them.

// walk checks that the layers of seed at the given indices have the given
// values, stepping once from layer 0 to the highest index.
func walk(t *testing.T, seed []byte, layers []vectors.Layer) {
	t.Helper()
	layers = slices.Clone(layers)
	slices.SortFunc(layers, func(a, b vectors.Layer) int { return cmp.Compare(a.Index, b.Index) })
	x, at := Base(seed), uint64(0)
	for _, l := range layers {
		x = Advance(x, l.Index-at)
		at = l.Index
		if x != vectors.Hex32(t, l.Value) {
			t.Fatalf("layer %d = %x, want %s", l.Index, x, l.Value)
		}
	}
}

// TestGoldenOnionVectors checks V1-V3: layer values, Top, and Find's index
// and reveal for the commitment.
func TestGoldenOnionVectors(t *testing.T) {
	var f struct {
		Tag   string                `json:"tag"`
		Cases []vectors.OnionVector `json:"cases"`
	}
	vectors.Load(t, "randao/onion.json", &f)
	if f.Tag != onionTag {
		t.Fatalf("tag %q, want %q", f.Tag, onionTag)
	}
	if len(f.Cases) != 3 {
		t.Fatalf("%d onion vectors, want V1-V3", len(f.Cases))
	}
	for _, v := range f.Cases {
		t.Run(v.ID, func(t *testing.T) {
			seed := vectors.Hex(t, v.Seed)
			walk(t, seed, v.Values)
			c := vectors.Hex32(t, v.Commitment)
			if got := Top(seed, v.Layers); got != c {
				t.Fatalf("Top = %x, want %s", got, v.Commitment)
			}
			j, reveal, ok := Find(seed, c, v.Layers)
			if !ok || j != v.Layers || reveal != vectors.Hex32(t, v.Reveal) {
				t.Errorf("Find = %d, %x, %v; want %d, %s", j, reveal, ok, v.Layers, v.Reveal)
			}
			if Step(reveal) != c {
				t.Error("the reveal does not hash to the commitment")
			}
		})
	}
}

// TestGoldenInteropCommitments checks V4: the commitment and first reveal of
// interop keys of the e2e genesis. Each costs 2^20 hashes, so it checks keys
// 0-7 and every 32nd key in parallel (-short: keys 0-3); tools/vectorgen
// already checks all 256 against qrysm's genesis.
func TestGoldenInteropCommitments(t *testing.T) {
	var f vectors.InteropCommitments
	vectors.Load(t, "randao/interop.json", &f)
	if f.Layers != DefaultLength || len(f.Keys) != 256 {
		t.Fatalf("%d keys of %d layers, want 256 of %d", len(f.Keys), f.Layers, DefaultLength)
	}
	for i, k := range f.Keys {
		if i >= 8 && i%32 != 0 || testing.Short() && i >= 4 {
			continue
		}
		t.Run(fmt.Sprint(k.Index), func(t *testing.T) {
			t.Parallel()
			seed := vectors.Hex(t, k.Seed)
			if len(seed) != 48 {
				t.Fatalf("seed of %d bytes", len(seed))
			}
			x := Advance(Base(seed), f.Layers-1)
			if x != vectors.Hex32(t, k.FirstReveal) {
				t.Fatalf("first reveal %x, want %s", x, k.FirstReveal)
			}
			if Step(x) != vectors.Hex32(t, k.Commitment) {
				t.Fatalf("commitment %x, want %s", Step(x), k.Commitment)
			}
		})
	}
}

// TestGoldenFrontierLayers checks every layer value the V6 frontier scripts
// use, and that each 200 step's reveal hashes to its commitment.
func TestGoldenFrontierLayers(t *testing.T) {
	var f vectors.Frontier
	vectors.Load(t, "randao/frontier.json", &f)
	seed := vectors.Hex(t, vectors.Keys(t)[f.KeyIndex].Seed)
	walk(t, seed, f.Layers)
	if len(f.Scripts) < 15 {
		t.Fatalf("%d scripts, want at least 15", len(f.Scripts))
	}
	for _, s := range f.Scripts {
		for i, st := range s.Steps {
			if st.Expect.Status != 200 {
				continue
			}
			if Step(vectors.Hex32(t, st.Expect.RandaoReveal)) != vectors.Hex32(t, st.RandaoCommitment) {
				t.Errorf("%s step %d: the reveal does not hash to the commitment", s.Name, i)
			}
		}
	}
}

// TestGoldenRandaoRequests checks the commitments of the V5 refusals with
// Find: x_0 is found at index 0 (exhausted), and the unknown ones are not
// found within the default maximum.
func TestGoldenRandaoRequests(t *testing.T) {
	var f struct {
		Cases []vectors.RandaoRequest `json:"cases"`
	}
	vectors.Load(t, "randao/requests.json", &f)
	keys := vectors.Keys(t)
	unknown := 0
	for _, c := range f.Cases {
		if c.Preset != "minimal" || c.Expect.Status != 422 {
			continue
		}
		seed := vectors.Hex(t, keys[c.KeyIndex].Seed)
		cm := vectors.Hex32(t, c.RandaoCommitment)
		switch c.Expect.Reason {
		case "RANDAO_ONION_EXHAUSTED":
			if j, _, ok := Find(seed, cm, DefaultLength); !ok || j != 0 {
				t.Errorf("%s: Find = %d, %v; want x_0", c.Name, j, ok)
			}
		case "RANDAO_UNKNOWN_COMMITMENT":
			if testing.Short() && unknown > 0 {
				continue // each costs a full 2^20 scan
			}
			if _, _, ok := Find(seed, cm, DefaultLength); ok {
				t.Errorf("%s: found within the default length", c.Name)
			}
			unknown++
		default:
			t.Errorf("%s: unexpected reason %s", c.Name, c.Expect.Reason)
		}
	}
	if unknown == 0 {
		t.Fatal("no unknown-commitment vectors")
	}
}
