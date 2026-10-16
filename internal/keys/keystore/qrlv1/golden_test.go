// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package qrlv1

import (
	"bytes"
	"errors"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/vectors"
)

// TestGoldenKeystores decrypts every keystore vector of testdata/vectors
// (qrysm's keystore v1 and the deposit CLI's, light and standard KDF, and a
// non-ASCII password) and checks the seed and public key it yields.
func TestGoldenKeystores(t *testing.T) {
	cases := vectors.Keystores(t)
	flavours := map[string]bool{}
	for _, c := range cases {
		flavours[c.Flavour] = true
		t.Run(c.File, func(t *testing.T) {
			t.Parallel()
			ks, err := Parse(vectors.Raw(t, "keystores/"+c.File))
			if err != nil {
				t.Fatal(err)
			}
			if ks.Flavour.String() != c.Flavour {
				t.Errorf("flavour %s, want %s", ks.Flavour, c.Flavour)
			}
			if c.KDF.Function != algoArgon2id || ks.KDF != (KDF{T: c.KDF.T, M: c.KDF.M, P: c.KDF.P}) {
				t.Errorf("KDF %+v, index records %+v", ks.KDF, c.KDF)
			}
			wantPK := vectors.Hex(t, c.Pubkey)
			if declared, ok := ks.PublicKey(); !ok || !bytes.Equal(declared[:], wantPK) {
				t.Errorf("declared pubkey does not match index.json (present %t)", ok)
			}

			key, err := ks.Decrypt(NewPassword([]byte(c.Password)))
			if err != nil {
				t.Fatal(err)
			}
			defer key.Zeroize()
			if pk := key.PublicKey(); !bytes.Equal(pk[:], wantPK) {
				t.Error("derived public key differs from the vector's")
			}
			wantSeed := vectors.Hex(t, c.Seed)
			if err := key.WithSeed(func(seed *[mldsa87.SeedSize]byte) error {
				if !bytes.Equal(seed[:], wantSeed) {
					t.Error("decrypted seed differs from the vector's")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}

			if ks.KDF.M > MinM {
				return // one more 256 MiB run adds nothing the light vectors do not show
			}
			if _, err := ks.Decrypt(NewPassword([]byte(c.Password + "x"))); !errors.Is(err, ErrPassword) {
				t.Errorf("wrong password: %v, want ErrPassword", err)
			}
		})
	}
	if !flavours["qrl-v1"] || !flavours["deposit-cli"] {
		t.Fatalf("index.json covers flavours %v, want qrl-v1 and deposit-cli", flavours)
	}
}

// TestGoldenUnicodePassword checks that the non-ASCII vector needs its
// normalised form: the raw password alone does not open it.
func TestGoldenUnicodePassword(t *testing.T) {
	for _, c := range vectors.Keystores(t) {
		if c.File != "qrl-v1-light-unicode.json" {
			continue
		}
		pw := NewPassword([]byte(c.Password))
		if bytes.Equal(pw.norm, pw.raw) {
			t.Fatal("the unicode vector's password normalises to itself")
		}
		ks, err := Parse(vectors.Raw(t, "keystores/"+c.File))
		if err != nil {
			t.Fatal(err)
		}
		rawOnly := &Password{norm: pw.raw, alt: pw.raw, raw: pw.raw}
		if _, err := ks.Decrypt(rawOnly); !errors.Is(err, ErrPassword) {
			t.Fatalf("raw password: %v, want ErrPassword", err)
		}
		return
	}
	t.Fatal("no qrl-v1-light-unicode.json in index.json")
}
