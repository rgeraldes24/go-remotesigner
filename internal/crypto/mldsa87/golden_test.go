// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package mldsa87

import (
	"bytes"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/vectors"
)

// goldenKeys builds the interop keys of testdata/vectors from their seeds.
func goldenKeys(t *testing.T) []*Key {
	t.Helper()
	var keys []*Key
	for _, k := range vectors.Keys(t) {
		seed := [SeedSize]byte(vectors.Hex(t, k.Seed))
		key, err := FromSeed48(&seed)
		if err != nil {
			t.Fatal(err)
		}
		Wipe(seed[:])
		if pk := key.PublicKey(); !bytes.Equal(pk[:], vectors.Hex(t, k.Pubkey)) {
			t.Fatalf("key %d: public key differs from qrysm's interop key", k.Index)
		}
		keys = append(keys, key)
	}
	return keys
}

// TestGoldenDeterministicSignatures reproduces qrysm's deterministic
// selection-proof signatures byte for byte, and checks that they verify
// under the consensus context.
func TestGoldenDeterministicSignatures(t *testing.T) {
	keys := goldenKeys(t)
	checked := 0
	for _, c := range vectors.Signing(t) {
		if c.DeterministicSignature == "" {
			continue
		}
		t.Run(c.ID(), func(t *testing.T) {
			k := keys[c.KeyIndex]
			root := vectors.Hex32(t, c.SigningRoot)
			want := vectors.Hex(t, c.DeterministicSignature)
			if !k.Verify(root[:], want) {
				t.Fatal("qrysm's signature does not verify")
			}
			got, err := k.Sign(root[:], Deterministic)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got[:], want) {
				t.Error("deterministic signature differs from qrysm's")
			}
		})
		checked++
	}
	if checked < 20 {
		t.Fatalf("only %d deterministic signatures", checked)
	}
}
