// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package keyconfig

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/argon"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystore/qrlv1"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystoretest"
)

// extHex is an extended seed of descriptor 01 00 00 and the seed b, b, ...
func extHex(b byte) string {
	return "010000" + strings.Repeat(hex.EncodeToString([]byte{b}), mldsa87.SeedSize)
}

// Execution mode takes 51-byte extended seeds and refuses 48-byte seeds,
// the mirror of the consensus rule ("51 bytes" in TestParse).
func TestParseExecution(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		key  byte // seed byte of the expected key; 0 means none
		err  error
		hint string
	}{
		{"extended seed", "type: file-raw\nkeyType: ML_DSA_87\nprivateKey: \"0x" + extHex(1) + "\"\n", 1, nil, ""},
		{"no 0x, as go-qrl's seed files", "type: file-raw\nprivateKey: " + extHex(2) + "\n", 2, nil, ""},
		{"48-byte seed", "type: file-raw\nprivateKey: " + seedHex(3) + "\n", 0, ErrPrivateKey, "consensus validator key"},
		{"descriptor 02 00 00", "type: file-raw\nprivateKey: 0x02" + extHex(4)[2:] + "\n", 0, ErrPrivateKey, "01 00 00"},
		{"descriptor 01 00 01", "type: file-raw\nprivateKey: 0x0100" + "01" + extHex(4)[6:] + "\n", 0, ErrPrivateKey, "01 00 00"},
		{"32 bytes", "type: file-raw\nprivateKey: 0x" + strings.Repeat("ab", 32) + "\n", 0, ErrPrivateKey, "51-byte"},
		{"not hex", "type: file-raw\nprivateKey: 0x" + strings.Repeat("zz", 51) + "\n", 0, ErrPrivateKey, "not hex"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			p := writeFile(t, dir, "k.yaml", tt.yaml, 0o600)
			keys, err := Config{Dir: dir, Policy: strict, Execution: true}.LoadFile(context.Background(), p)
			if !errors.Is(err, tt.err) {
				t.Fatalf("LoadFile error = %v, want %v", err, tt.err)
			}
			if err != nil {
				if !strings.Contains(err.Error(), tt.hint) {
					t.Errorf("error %q lacks %q", err, tt.hint)
				}
				if strings.Contains(err.Error(), "abab") || strings.Contains(err.Error(), "0303") {
					t.Fatalf("error leaks key material: %v", err)
				}
				return
			}
			if len(keys) != 1 || keys[0].PublicKey() != pubkeyOf(t, tt.key) {
				t.Fatalf("keys %v: not the key of seed %#x", keys, tt.key)
			}
			keys[0].Zeroize()
		})
	}
}

// A file-raw document with an extended seed is a secret file in execution
// mode too.
func TestExecutionSeedFilePermissions(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "k.yaml", "type: file-raw\nprivateKey: "+extHex(5)+"\n", 0o644)
	if _, err := (Config{Dir: dir, Policy: strict, Execution: true}).LoadFile(context.Background(), p); err == nil {
		t.Fatal("a group-readable extended seed loaded under the strict policy")
	}
}

// file-keystore loads a go-qrl account keystore in execution mode and
// refuses a validator keystore; consensus mode does the reverse.
func TestFileKeystoreExecution(t *testing.T) {
	dir := t.TempDir()
	s, err := keystoretest.NewSealer("pw", keystoretest.Cheapest)
	if err != nil {
		t.Fatal(err)
	}
	ext := keystoretest.ExtendedSeed("keyconfig", 0)
	addr, err := keystoretest.Address(ext)
	if err != nil {
		t.Fatal(err)
	}
	account, err := s.Account(ext, addr)
	if err != nil {
		t.Fatal(err)
	}
	validator, err := s.QRLV1(keystoretest.Seed("keyconfig", 1), true)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "account.json", string(account), 0o600)
	writeFile(t, dir, "validator.json", string(validator), 0o600)
	writeFile(t, dir, "pw.txt", "pw\n", 0o600)
	acc := writeFile(t, dir, "account.yaml", "type: file-keystore\nkeystoreFile: account.json\nkeystorePasswordFile: pw.txt\n", 0o600)
	val := writeFile(t, dir, "validator.yaml", "type: file-keystore\nkeystoreFile: validator.json\nkeystorePasswordFile: pw.txt\n", 0o600)

	sem := argon.New(1, 1<<30)
	exec := Config{Dir: dir, Policy: strict, Decrypt: sem.Decrypt, Execution: true}
	keys, err := exec.LoadFile(context.Background(), acc)
	if err != nil {
		t.Fatal(err)
	}
	want, err := mldsa87.FromExtendedSeed51(ext)
	if err != nil {
		t.Fatal(err)
	}
	defer want.Zeroize()
	if len(keys) != 1 || keys[0].PublicKey() != want.PublicKey() {
		t.Fatal("the account keystore did not load its key")
	}
	keys[0].Zeroize()
	if _, err := exec.LoadFile(context.Background(), val); !errors.Is(err, qrlv1.ErrFormat) {
		t.Fatalf("execution mode loaded a validator keystore: %v", err)
	}
	cons := Config{Dir: dir, Policy: strict, Decrypt: sem.Decrypt}
	if _, err := cons.LoadFile(context.Background(), acc); !errors.Is(err, qrlv1.ErrFormat) {
		t.Fatalf("consensus mode loaded an account keystore: %v", err)
	}
}
