// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package keystores

import (
	"context"
	"errors"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/argon"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystore/qrlv1"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystoretest"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secretfile"
)

// In execution mode the directory holds go-qrl account keystores, each with
// its <name>.txt; a validator keystore among them fails alone, and an
// account keystore whose address belongs to another key is refused.
func TestLoadExecution(t *testing.T) {
	ksDir, pwDir := t.TempDir(), t.TempDir()
	s, err := keystoretest.NewSealer("pw", keystoretest.Cheapest)
	if err != nil {
		t.Fatal(err)
	}
	account := func(i int, address string) *[mldsa87.ExtendedSeedSize]byte {
		ext := keystoretest.ExtendedSeed(t.Name(), i)
		if address == "" {
			if address, err = keystoretest.Address(ext); err != nil {
				t.Fatal(err)
			}
		}
		data, err := s.Account(ext, address)
		if err != nil {
			t.Fatal(err)
		}
		name := "UTC--account-" + string(rune('a'+i))
		writeSecret(t, ksDir, name+".json", string(data))
		writeSecret(t, pwDir, name+".txt", "pw\n")
		return ext
	}
	good := account(0, "")
	other, err := keystoretest.Address(keystoretest.ExtendedSeed(t.Name(), 9))
	if err != nil {
		t.Fatal(err)
	}
	account(1, other)
	validator, err := s.QRLV1(keystoretest.Seed(t.Name(), 2), true)
	if err != nil {
		t.Fatal(err)
	}
	writeSecret(t, ksDir, "UTC--account-c.json", string(validator))
	writeSecret(t, pwDir, "UTC--account-c.txt", "pw\n")

	sem := argon.New(1, 1<<30)
	c := Config{Dir: ksDir, PasswordsDir: pwDir, Policy: secretfile.Policy{Strict: true}, Decrypt: sem.Decrypt,
		Execution: true}
	res, err := c.Load(context.Background(), 2, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 3 {
		t.Fatalf("%d batches", len(res))
	}
	want, err := mldsa87.FromExtendedSeed51(good)
	if err != nil {
		t.Fatal(err)
	}
	defer want.Zeroize()
	if res[0].Err != nil || len(res[0].Keys) != 1 || res[0].Keys[0].PublicKey() != want.PublicKey() {
		t.Fatalf("the account keystore did not load: %+v", res[0])
	}
	res[0].Keys[0].Zeroize()
	if !errors.Is(res[1].Err, qrlv1.ErrAddressMismatch) {
		t.Errorf("mislabelled account keystore: %v", res[1].Err)
	}
	if !errors.Is(res[2].Err, qrlv1.ErrFormat) {
		t.Errorf("validator keystore in execution mode: %v", res[2].Err)
	}

	// Consensus mode refuses the account keystores.
	c.Execution = false
	res, err = c.Load(context.Background(), 2, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(res[0].Err, qrlv1.ErrFormat) {
		t.Errorf("account keystore in consensus mode: %v", res[0].Err)
	}
	for _, b := range res {
		for _, k := range b.Keys {
			k.Zeroize()
		}
	}
}
