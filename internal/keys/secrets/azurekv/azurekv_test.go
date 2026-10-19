// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package azurekv

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets/secretstest"
)

var seed = "0x" + strings.Repeat("e1", 48)

// vaultOf is a CLIENT_SECRET connection to the fake through Web3Signer's
// three overrides.
func vaultOf(f *secretstest.Azure) secrets.AzureVault {
	return secrets.AzureVault{AuthMode: secrets.AzureClientSecret, VaultName: "ignored", ClientID: f.ClientID,
		TenantID: secretstest.AzureTenant, ClientSecret: []byte(f.ClientSecret), Timeout: 10 * time.Second,
		EndpointOverride: f.URL, AuthorityHostOverride: f.URL, TrustCertificateOverride: f.CertFile}
}

func TestFetch(t *testing.T) {
	f := secretstest.NewAzure(t)
	f.Put("validator-1", seed, nil)
	f.Put("too-large", strings.Repeat("0", secrets.MaxValueSize+1), nil)
	c := New()
	ctx := context.Background()
	got, err := c.Fetch(ctx, &secrets.Azure{AzureVault: vaultOf(f), SecretName: "validator-1"})
	if err != nil || string(got) != seed {
		t.Fatalf("Fetch = %q, %v", got, err)
	}
	for name, want := range map[string]error{"missing": secrets.ErrNotFound, "too-large": secrets.ErrTooLarge} {
		if _, err := c.Fetch(ctx, &secrets.Azure{AzureVault: vaultOf(f), SecretName: name}); !errors.Is(err, want) {
			t.Errorf("%s: error = %v, want %v", name, err, want)
		}
	}
	if f.TokenRequests != 1 || c.clients.Len() != 1 {
		t.Errorf("%d token requests, %d clients: the client and its token are not reused", f.TokenRequests, c.clients.Len())
	}

	bad := vaultOf(f)
	bad.ClientSecret = []byte("wrong-secret")
	_, err = New().Fetch(ctx, &secrets.Azure{AzureVault: bad, SecretName: "validator-1"})
	if err == nil || strings.Contains(err.Error(), "wrong-secret") || strings.Contains(err.Error(), "\n") {
		t.Fatalf("wrong client secret: %v", err)
	}
}

func TestTrustCertificateOverride(t *testing.T) {
	f := secretstest.NewAzure(t)
	f.Put("validator-1", seed, nil)
	v := vaultOf(f)
	v.TrustCertificateOverride, v.Timeout = "", 2*time.Second
	if _, err := New().Fetch(context.Background(), &secrets.Azure{AzureVault: v, SecretName: "validator-1"}); err == nil {
		t.Fatal("the fake's certificate was trusted without the override")
	}
	der := filepath.Join(t.TempDir(), "cert.der")
	if err := os.WriteFile(der, f.Certificate().Raw, 0o600); err != nil {
		t.Fatal(err)
	}
	v.TrustCertificateOverride = der
	if _, err := New().Fetch(context.Background(), &secrets.Azure{AzureVault: v, SecretName: "validator-1"}); err != nil {
		t.Fatalf("DER certificate: %v", err)
	}
	empty := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(empty, []byte("-----BEGIN NOTHING-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	v.TrustCertificateOverride = empty
	if _, err := New().Fetch(context.Background(), &secrets.Azure{AzureVault: v, SecretName: "validator-1"}); err == nil {
		t.Fatal("a file without a certificate was accepted")
	}
}

func TestManagedIdentity(t *testing.T) {
	f := secretstest.NewAzure(t)
	f.Put("validator-1", seed, nil)
	t.Setenv("IDENTITY_ENDPOINT", f.IdentityEndpoint())
	t.Setenv("IDENTITY_HEADER", f.IdentityHeader)
	for _, tt := range []struct {
		mode, clientID string
	}{
		{secrets.AzureSystemAssignedIdentity, ""},
		{secrets.AzureUserAssignedIdentity, "user-assigned-id"},
	} {
		v := vaultOf(f)
		v.AuthMode, v.ClientID, v.ClientSecret, v.TenantID, v.AuthorityHostOverride = tt.mode, tt.clientID, nil, "", ""
		got, err := New().Fetch(context.Background(), &secrets.Azure{AzureVault: v, SecretName: "validator-1"})
		if err != nil || string(got) != seed {
			t.Fatalf("%s: Fetch = %q, %v", tt.mode, got, err)
		}
		if ids := f.ManagedIdentityClientIDs; ids[len(ids)-1] != tt.clientID {
			t.Errorf("%s: asked for client id %q", tt.mode, ids[len(ids)-1])
		}
	}
	v := vaultOf(f)
	v.AuthMode, v.ClientID = secrets.AzureUserAssignedIdentity, ""
	if _, err := New().Fetch(context.Background(), &secrets.Azure{AzureVault: v, SecretName: "x"}); !errors.Is(err, secrets.ErrConfig) {
		t.Fatalf("user-assigned without a client id: %v", err)
	}
}

func TestVaultName(t *testing.T) {
	v := secrets.AzureVault{AuthMode: secrets.AzureClientSecret, VaultName: "evil.example/x?", ClientID: "c",
		TenantID: "t", ClientSecret: []byte("s"), Timeout: time.Second}
	if _, err := New().Fetch(context.Background(), &secrets.Azure{AzureVault: v, SecretName: "x"}); !errors.Is(err, secrets.ErrConfig) {
		t.Fatalf("a vault name that is not a name: %v", err)
	}
	if got := (&secrets.AzureVault{VaultName: "my-vault"}).VaultURL(); got != "https://my-vault.vault.azure.net" {
		t.Fatalf("VaultURL = %s", got)
	}
}

func TestBulk(t *testing.T) {
	f := secretstest.NewAzure(t)
	f.Put("a", seed, map[string]string{"role": "validator", "team": "blue"})
	f.Put("b", seed+"\n0x"+strings.Repeat("e2", 48), map[string]string{"role": "validator"})
	f.Put("c", seed, map[string]string{"role": "other"})
	f.Put("d", seed, nil)
	f.Put("e", seed, map[string]string{"role": ""})
	for _, tt := range []struct {
		tags []secrets.Tag
		want []string
	}{
		{nil, []string{"a", "b", "c", "d", "e"}},
		{[]secrets.Tag{{Key: "role", Value: "validator"}}, []string{"a", "b"}},
		{[]secrets.Tag{{Key: "role", Value: "validator"}, {Key: "team", Value: "blue"}}, []string{"a"}},
		{[]secrets.Tag{{Key: "role"}}, []string{"e"}},
	} {
		b, err := NewBulk(secrets.AzureBulk{AzureVault: vaultOf(f), Tags: tt.tags})
		if err != nil {
			t.Fatal(err)
		}
		names, err := b.List(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(names, tt.want) {
			t.Errorf("tags %v: List = %v, want %v", tt.tags, names, tt.want)
		}
	}
	b, err := NewBulk(secrets.AzureBulk{AzureVault: vaultOf(f), Tags: []secrets.Tag{{Key: "role", Value: "validator"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	batches, err := secrets.Bulk{Kind: secrets.KindAzure, Store: b}.Load(context.Background(), 2, nil)
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
	if len(batches) != 2 || keys != 3 || batches[0].Source != "azure-bulk:a" {
		t.Fatalf("%d batches with %d keys", len(batches), keys)
	}
}
