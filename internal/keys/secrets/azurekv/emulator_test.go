// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package azurekv

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets/secretstest"
)

// The client against Lowkey Vault with system-assigned managed-identity
// authentication, its token from the emulator's token endpoint: a secret's
// latest version, a missing secret, and the bulk loader's listing by tags
// and its load.
func TestLowkeyVault(t *testing.T) {
	vaultURL, identity, certFile := secretstest.LowkeyVault(t)
	t.Setenv("IDENTITY_ENDPOINT", identity)
	t.Setenv("IDENTITY_HEADER", "header")
	var rnd [4]byte
	_, _ = rand.Read(rnd[:])
	prefix := "remotesigner-" + hex.EncodeToString(rnd[:]) + "-"
	seed2 := strings.Repeat("e2", 48)
	secretstest.PutLowkeySecret(t, vaultURL, certFile, prefix+"one", "not a seed", map[string]string{"role": "single"})
	secretstest.PutLowkeySecret(t, vaultURL, certFile, prefix+"one", seed+"\n", map[string]string{"role": "single"})
	secretstest.PutLowkeySecret(t, vaultURL, certFile, prefix+"bulk-a", seed+"\n"+seed2+"\n", map[string]string{"role": "validator",
		"run": prefix})
	secretstest.PutLowkeySecret(t, vaultURL, certFile, prefix+"bulk-b", seed2, map[string]string{"role": "validator", "run": prefix})
	secretstest.PutLowkeySecret(t, vaultURL, certFile, prefix+"other", seed2, map[string]string{"role": "other", "run": prefix})

	v := secrets.AzureVault{AuthMode: secrets.AzureSystemAssignedIdentity, VaultName: "ignored", Timeout: 30 * time.Second,
		EndpointOverride: vaultURL, TrustCertificateOverride: certFile}
	ctx := context.Background()
	got, err := New().Fetch(ctx, &secrets.Azure{AzureVault: v, SecretName: prefix + "one"})
	if err != nil || string(got) != seed+"\n" {
		t.Fatalf("Fetch = %q, %v", got, err)
	}
	if _, err := New().Fetch(ctx, &secrets.Azure{AzureVault: v, SecretName: prefix + "none"}); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("missing secret: %v", err)
	}

	b, err := NewBulk(secrets.AzureBulk{AzureVault: v, Tags: []secrets.Tag{{Key: "role", Value: "validator"},
		{Key: "run", Value: prefix}}})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	names, err := b.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(names)
	if want := []string{prefix + "bulk-a", prefix + "bulk-b"}; !slices.Equal(names, want) {
		t.Fatalf("List = %v, want %v", names, want)
	}
	batches, err := secrets.Bulk{Kind: secrets.KindAzure, Store: b}.Load(ctx, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	keys := 0
	for _, x := range batches {
		if x.Err != nil {
			t.Errorf("%s: %v", x.Source, x.Err)
		}
		keys += len(x.Keys)
		for _, k := range x.Keys {
			k.Zeroize()
		}
	}
	if len(batches) != 2 || keys != 3 {
		t.Fatalf("%d batches with %d keys, want 2 with 3", len(batches), keys)
	}
}
