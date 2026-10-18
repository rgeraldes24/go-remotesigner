// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func hexOf(b byte, n int) string { return strings.Repeat(hex.EncodeToString([]byte{b}), n) }

func TestParseSeed(t *testing.T) {
	seed := hexOf(0x11, 48)
	ext := "010000" + seed
	tests := []struct {
		name  string
		value string
		mode  Mode
		want  string // hex of the result; "" for an error
		err   string
	}{
		{"consensus", "0x" + seed, Consensus, seed, ""},
		{"consensus bare", seed, Consensus, seed, ""},
		{"consensus trailing newline", "0x" + seed + "\r\n", Consensus, seed, ""},
		{"consensus surrounding space", "  " + seed + "\t", Consensus, seed, ""},
		{"consensus upper case", strings.ToUpper(seed), Consensus, seed, ""},
		{"consensus 51 bytes", "0x" + ext, Consensus, "", "51-byte extended seed belongs to execution mode"},
		{"consensus 32 bytes", "0x" + hexOf(1, 32), Consensus, "", "32 bytes"},
		{"consensus 4896 bytes", "0x" + hexOf(1, 4896), Consensus, "", "4,896-byte"},
		{"consensus other", "0x" + hexOf(1, 47), Consensus, "", "want a 48-byte seed"},
		{"consensus not hex", "0x" + hexOf(1, 47) + "zz", Consensus, "", "not hex"},
		{"consensus empty", "", Consensus, "", "want a 48-byte seed"},
		{"consensus two seeds", seed + "\n" + seed, Consensus, "", "want a 48-byte seed"},
		{"execution", "0x" + ext, Execution, ext, ""},
		{"execution 48 bytes", "0x" + seed, Execution, "", "48-byte seed belongs to consensus mode"},
		{"execution descriptor", "0x020000" + seed, Execution, "", "descriptor"},
		{"execution 32 bytes", "0x" + hexOf(1, 32), Execution, "", "32 bytes"},
		{"execution other", "0x" + hexOf(1, 50), Execution, "", "want a 51-byte extended seed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSeed([]byte(tt.value), tt.mode)
			if tt.err != "" {
				if !errors.Is(err, ErrSeed) || !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("error = %v, want ErrSeed with %q", err, tt.err)
				}
				if strings.Contains(err.Error(), "1111") || strings.Contains(err.Error(), "0101") {
					t.Fatalf("error quotes the value: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if h := hex.EncodeToString(got); h != tt.want {
				t.Fatalf("seed = %s, want %s", h, tt.want)
			}
		})
	}
}

func TestParseSeeds(t *testing.T) {
	a, b := "0x"+hexOf(1, 48), hexOf(2, 48)
	got, err := ParseSeeds([]byte(a+"\r\n\n"+b+"\n"), Consensus)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !bytes.Equal(got[0], bytes.Repeat([]byte{1}, 48)) || !bytes.Equal(got[1], bytes.Repeat([]byte{2}, 48)) {
		t.Fatalf("seeds = %x", got)
	}
	for _, tt := range []struct{ value, err string }{
		{a + "\n" + hexOf(3, 32) + "\n", "line 2: invalid seed: 32 bytes"},
		{"\n \n", "holds no seed"},
		{a + "\n0x010000" + hexOf(4, 48), "line 2: invalid seed: a 51-byte"},
	} {
		if _, err := ParseSeeds([]byte(tt.value), Consensus); err == nil || !strings.Contains(err.Error(), tt.err) {
			t.Errorf("ParseSeeds error = %v, want %q", err, tt.err)
		}
	}
}

func TestKeys(t *testing.T) {
	one := "0x" + hexOf(1, 48)
	keys, err := Keys([]byte(one+"\n"), true)
	if err != nil || len(keys) != 1 {
		t.Fatalf("Keys(one) = %d keys, %v", len(keys), err)
	}
	keys[0].Zeroize()
	if _, err := Keys([]byte(one+"\n"+one), true); err == nil {
		t.Fatal("two lines accepted as one seed")
	}
	keys, err = Keys([]byte(one+"\n"+hexOf(2, 48)), false)
	if err != nil || len(keys) != 2 || keys[0].ID() == keys[1].ID() {
		t.Fatalf("Keys(lines) = %d keys, %v", len(keys), err)
	}
	for _, k := range keys {
		k.Zeroize()
	}
}
