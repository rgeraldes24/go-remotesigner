// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package qrlv1

import "testing"

// TestNormalisation pins the two passphrase normalisations of the keystore
// v1 decryptor, which norm.go keeps unchanged so that keystores qrysm
// encrypted keep opening: NFKD with the C0 and DEL control characters
// removed, and the alternative form, which keeps only the first rune of
// each NFKD segment. Both only strip single-byte characters, so C1 controls
// (U+0080 to U+009F, two bytes in UTF-8) stay, unlike EIP-2335's rule.
func TestNormalisation(t *testing.T) {
	for _, c := range []struct {
		in, norm, alt string
	}{
		{"testpassword", "testpassword", "testpassword"},
		{"", "", ""},
		{"pass\x00word\x1f\x7f", "password", "password"},
		{"tab\there\u0085", "tabhere\u0085", "tabhere\u0085"},
		{"𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑", "testpassword🔑", "testpassword🔑"},
		{"Ⅳ", "IV", "IV"},
		{"ü", "ü", "u"},
		{"ü", "ü", "u"},
		{"Å", "Å", "A"},
	} {
		if got := normPassphrase(c.in); got != c.norm {
			t.Errorf("normPassphrase(%+q) = %+q, want %+q", c.in, got, c.norm)
		}
		if got := altNormPassphrase(c.in); got != c.alt {
			t.Errorf("altNormPassphrase(%+q) = %+q, want %+q", c.in, got, c.alt)
		}
	}
}
