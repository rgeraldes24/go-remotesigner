// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	fieldparams "github.com/theQRL/qrysm/config/fieldparams"
	"github.com/theQRL/qrysm/crypto/ml_dsa_87"
	"github.com/theQRL/qrysm/crypto/randao"
	"github.com/theQRL/qrysm/runtime/interop"
)

// fixtureKeys is how many interop keys the signing fixtures use and
// keys/interop.json lists in full.
const fixtureKeys = 8

// interopKey is one of qrysm's deterministic interop keys.
type interopKey struct {
	index       int
	seed        []byte // the 48-byte wallet seed
	key         ml_dsa_87.MLDSA87Key
	pub         []byte
	commitment  [32]byte // x_L of the default-length onion, as interop genesis stores it
	firstReveal [32]byte // x_{L-1}
}

// loadKeys returns interop keys 0..n-1 with their RANDAO commitments.
func loadKeys(n int) ([]interopKey, error) {
	prv, pub, err := interop.DeterministicallyGenerateKeys(0, uint64(n))
	if err != nil {
		return nil, err
	}
	out := make([]interopKey, n)
	for i := range out {
		seed := prv[i].Marshal()
		if len(seed) != fieldparams.MLDSA87SeedLength {
			return nil, fmt.Errorf("interop key %d: seed of %d bytes", i, len(seed))
		}
		onion, err := randao.NewOnion(seed, randao.DefaultLayers)
		if err != nil {
			return nil, err
		}
		c := onion.Commitment()
		r, err := onion.Reveal(c)
		if err != nil {
			return nil, err
		}
		if !randao.Verify(r, c) {
			return nil, fmt.Errorf("interop key %d: first reveal does not verify", i)
		}
		out[i] = interopKey{index: i, seed: seed, key: prv[i], pub: pub[i].Marshal(), commitment: c, firstReveal: r}
	}
	return out, nil
}

// signDeterministic signs root with qrysm's deterministic mode, as its local
// keymanager signs selection proofs, and checks the result with qrysm's
// verifier.
func (k *interopKey) signDeterministic(root [32]byte) ([]byte, error) {
	sig, err := k.key.SignDeterministic(root[:])
	if err != nil {
		return nil, err
	}
	ok, err := ml_dsa_87.VerifySignature(sig.Marshal(), root, k.key.PublicKey())
	if err != nil || !ok {
		return nil, fmt.Errorf("key %d: deterministic signature does not verify: %v", k.index, err)
	}
	return sig.Marshal(), nil
}

// genKeys writes keys/interop.json.
func genKeys(g *generator) error {
	var list []obj
	for _, k := range g.keys[:fixtureKeys] {
		list = append(list, obj{}.
			set("index", k.index).
			set("seed", hx(k.seed)).
			set("pubkey", hx(k.pub)).
			set("randao_commitment", hx(k.commitment[:])).
			set("randao_first_reveal", hx(k.firstReveal[:])))
	}
	return writeJSON(g.vectors, "keys/interop.json", obj{}.
		set("description", g.description("qrysm's deterministic interop keys (runtime/interop "+
			"DeterministicallyGenerateKeys): the 48-byte wallet seed is SHA-256(le32(index) ‖ 0^28) ‖ 0^16. "+
			"randao_commitment is x_L of the default 2^20-layer onion, as interop genesis stores it; "+
			"randao_first_reveal is x_{L-1}. These are test keys: never use them on a live network.")).
		set("generator", g.info).
		set("keys", list))
}
