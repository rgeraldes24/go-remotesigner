// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/theQRL/qrysm/validator/slashing-protection-history/format"
)

// editedFixture writes the committed qrysm export after edit to a file.
func editedFixture(t *testing.T, edit func(*format.EIPSlashingProtectionFormat)) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectorsDir(t), filepath.FromSlash(interchangeExport)))
	if err != nil {
		t.Fatal(err)
	}
	var f format.EIPSlashingProtectionFormat
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	edit(&f)
	if b, err = json.Marshal(&f); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "edited.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestInterchangeCheck(t *testing.T) {
	ctx := context.Background()
	vectors := vectorsDir(t)
	// The fixture is a fixed point of qrysm's import and export, whatever the layout of the file it is given.
	same := editedFixture(t, func(*format.EIPSlashingProtectionFormat) {})
	if err := interchangeCheck(ctx, same, vectors, io.Discard); err != nil {
		t.Fatalf("the fixture itself: %v", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*format.EIPSlashingProtectionFormat)
		want string
	}{
		{"a lost attestation", func(f *format.EIPSlashingProtectionFormat) {
			for _, d := range f.Data {
				if len(d.SignedAttestations) > 1 {
					d.SignedAttestations = d.SignedAttestations[1:]
					return
				}
			}
		}, "differs"},
		{"a lost validator", func(f *format.EIPSlashingProtectionFormat) { f.Data = f.Data[1:] }, "differs"},
		{"a double vote", func(f *format.EIPSlashingProtectionFormat) {
			for _, d := range f.Data {
				if len(d.SignedAttestations) > 0 {
					a := *d.SignedAttestations[0]
					a.SigningRoot = "0x" + strings.Repeat("ab", 32)
					d.SignedAttestations = append(d.SignedAttestations, &a)
					return
				}
			}
		}, "slashable"},
		{"another network", func(f *format.EIPSlashingProtectionFormat) {
			f.Metadata.GenesisValidatorsRoot = "0x" + strings.Repeat("11", 32)
		}, "differs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := interchangeCheck(ctx, editedFixture(t, tc.edit), vectors, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("check: %v, want an error saying %q", err, tc.want)
			}
		})
	}
}
