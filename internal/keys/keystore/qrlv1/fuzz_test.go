// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package qrlv1

import (
	"errors"
	"strings"
	"testing"
	"unicode"

	"github.com/rgeraldes24/go-remotesigner/internal/vectors"
)

// fuzzKDFWork bounds the KDF work FuzzDecrypt spends on one input (t·m, in
// KiB): the light vectors' t=8, m=4096. Inputs above it are only parsed, so
// that the fuzzer stays fast; the policy alone caps their memory at MaxM.
const fuzzKDFWork = 8 * MinM

// FuzzDecrypt checks that arbitrary keystore JSON never panics, that every
// refusal is typed, that whatever Parse accepts is within the policy and
// keeps only printable metadata, and that decrypting allocates no more than
// the keystore's own Argon2id block.
func FuzzDecrypt(f *testing.F) {
	base, password := lightVector(f)
	for _, c := range vectors.Keystores(f) {
		if c.KDF.M == MinM {
			f.Add(vectors.Raw(f, "keystores/"+c.File))
		}
	}
	hexOf := func(n int) string { return strings.Repeat("ab", n) }
	for _, e := range []struct {
		path string
		v    any
	}{
		{"crypto.kdf.params", nil},
		{"crypto.cipher.params", nil},
		{"crypto.cipher.params.iv", ""},
		{"crypto.cipher.params.iv", hexOf(11)},
		{"crypto.cipher.params.iv", hexOf(13)},
		{"crypto.kdf.params.t", 0},
		{"crypto.kdf.params.p", 0},
		{"crypto.kdf.params.p", 256},
		{"crypto.kdf.params.m", 1<<32 - 1},
		{"crypto.kdf.params.dklen", 0},
		{"crypto.kdf.params.dklen", 1 << 31},
		{"crypto.kdf", deleteField},
		{"crypto.kdf.params.salt", 7},
		{"pubkey", "0123"},
		{"path", "m/12381\x1b[1A\nkeystore-0.json: OK"},
		{"description", "\u202e\x1b[2J"},
	} {
		f.Add(edit(f, base, e.path, e.v))
	}
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"version":1,"crypto":{"kdf":null,"cipher":null}}`))

	pw := NewPassword([]byte(password))
	f.Fuzz(func(t *testing.T, data []byte) {
		ks, err := Parse(data)
		if err != nil {
			if !errors.Is(err, ErrFormat) && !errors.Is(err, ErrPolicy) {
				t.Fatalf("untyped or internal refusal: %v", err)
			}
			return
		}
		k := ks.KDF
		if k.T < MinT || k.T > MaxT || k.M < MinM || k.M > MaxM || k.P < MinP || k.P > MaxP {
			t.Fatalf("Parse accepted KDF %+v", k)
		}
		if len(ks.sealed.salt) < minSaltSize || len(ks.sealed.salt) > maxSaltSize {
			t.Fatalf("Parse accepted a salt of %d bytes", len(ks.sealed.salt))
		}
		if ks.Path != "" && !derivationPathRE.MatchString(ks.Path) {
			t.Fatalf("Parse kept path %q, which is not a derivation path", ks.Path)
		}
		for _, v := range []string{ks.UUID, ks.Description} {
			if strings.IndexFunc(v, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
				t.Fatalf("Parse kept %q, which holds a non-printable character", v)
			}
		}
		if k.T*k.M > fuzzKDFWork {
			return
		}
		var key interface{ Zeroize() }
		n := allocated(func() {
			got, e := ks.Decrypt(pw)
			if got != nil {
				key = got
			}
			err = e
		})
		if key != nil {
			key.Zeroize()
		}
		switch {
		case err == nil:
		case errors.Is(err, ErrInternal):
			t.Fatalf("decrypt panicked: %v", err)
		case !errors.Is(err, ErrPassword) && !errors.Is(err, ErrPubkeyMismatch) && !errors.Is(err, ErrFormat):
			t.Fatalf("untyped decrypt error: %v", err)
		}
		// One Argon2id block per candidate run, freed between runs, plus
		// key derivation; a garbage collection may not have run in between.
		if limit := uint64(len(pw.candidates(ks.Flavour)))*(uint64(k.M)<<10) + 2<<20; n > limit {
			t.Fatalf("decrypt allocated %d bytes, limit %d", n, limit)
		}
	})
}
