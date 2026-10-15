// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/types"
)

func qAddr(b byte) string {
	return "Q" + strings.Repeat(hex.EncodeToString([]byte{b}), types.AddressLength)
}

var (
	canonicalID = "0x" + hex.EncodeToString(testPubkey[:])
	aliasID     = "0x" + hex.EncodeToString(testKeyID[:])
)

// entry renders one pin-file entry.
func entry(id, addr string) string { return "- key: " + id + "\n  fee_recipient: " + addr + "\n" }

func TestParseFeeRecipientPins(t *testing.T) {
	zeroID := "0x" + strings.Repeat("00", 32)
	tests := []struct {
		name string
		file string
		ok   bool
	}{
		{"alias", entry(aliasID, qAddr(1)), true},
		{"canonical", entry(canonicalID, qAddr(1)), true},
		{"upper-case hex digits", entry("0x"+strings.ToUpper(aliasID[2:]), qAddr(1)), true},
		{"upper-case prefix", entry("0X"+aliasID[2:], qAddr(1)), false},
		{"json", `[{"key": "` + canonicalID + `", "fee_recipient": "` + qAddr(1) + `"}]`, true},
		{"two keys", entry(aliasID, qAddr(1)) + entry(zeroID, qAddr(2)), true},
		{"same key in both forms", entry(aliasID, qAddr(1)) + entry(canonicalID, qAddr(1)), false},
		{"same key twice", entry(aliasID, qAddr(1)) + entry(aliasID, qAddr(2)), false},
		{"0x address", entry(aliasID, "0x"+strings.Repeat("01", 64)), false},
		{"short address", entry(aliasID, qAddr(1)[:100]), false},
		{"no 0x on identifier", entry(aliasID[2:], qAddr(1)), false},
		{"short identifier", entry(aliasID[:40], qAddr(1)), false},
		{"non-hex identifier", entry("0x"+strings.Repeat("zz", 32), qAddr(1)), false},
		{"missing fee_recipient", "- key: " + aliasID + "\n", false},
		{"unknown key", entry(aliasID, qAddr(1)) + "  builder: true\n", false},
		{"repeated key", entry(aliasID, qAddr(1)) + "  key: " + aliasID + "\n", false},
		{"nested value", "- key: " + aliasID + "\n  fee_recipient: [" + qAddr(1) + "]\n", false},
		{"entry not a mapping", "- " + aliasID + "\n", false},
		{"mapping instead of list", aliasID + ": " + qAddr(1), false},
		{"empty", "", false},
		{"empty list", "[]", false},
		{"not YAML", "- key: [", false},
	}
	for _, tt := range tests {
		pins, err := ParseFeeRecipientPins([]byte(tt.file))
		if (err == nil) != tt.ok {
			t.Errorf("%s: err = %v", tt.name, err)
			continue
		}
		if err != nil {
			if !errors.Is(err, ErrPinFile) {
				t.Errorf("%s: error does not wrap ErrPinFile: %v", tt.name, err)
			}
			continue
		}
		if a, ok := pins.Lookup(testKeyID); !ok || a[0] != 1 {
			t.Errorf("%s: lookup %x, %v", tt.name, a[:2], ok)
		}
	}
}

func TestLoadFeeRecipientPins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pins.yaml")
	if err := os.WriteFile(path, []byte(entry(aliasID, qAddr(7))), 0o600); err != nil {
		t.Fatal(err)
	}
	pins, err := LoadFeeRecipientPins(path)
	if err != nil || pins.Len() != 1 {
		t.Fatalf("load: %v", err)
	}
	if _, err := LoadFeeRecipientPins(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("a missing file loaded")
	}
}

// Fee-recipient pinning (G4 C13): a registration whose fee_recipient
// differs from the key's pin is refused; a matching one and one for an
// unpinned key pass.
func TestFeeRecipientPin(t *testing.T) {
	pins, err := ParseFeeRecipientPins([]byte(entry(canonicalID, qAddr(1))))
	if err != nil {
		t.Fatal(err)
	}
	p := newPolicy(t, Config{FeeRecipients: pins})
	if err := checkErr(p, registration(1, genesis)); err != nil {
		t.Errorf("pinned address refused: %v", err)
	}
	if err := checkErr(p, registration(2, genesis)); reason(t, err) != apierr.ArtifactTypeDisabled {
		t.Errorf("other address: %v", err)
	}
	unpinned := newPolicy(t, Config{})
	if err := checkErr(unpinned, registration(2, genesis)); err != nil {
		t.Errorf("no pin file: %v", err)
	}
	other, _ := ParseFeeRecipientPins([]byte(entry("0x"+strings.Repeat("00", 32), qAddr(9))))
	if err := checkErr(newPolicy(t, Config{FeeRecipients: other}), registration(2, genesis)); err != nil {
		t.Errorf("key without a pin: %v", err)
	}
}
