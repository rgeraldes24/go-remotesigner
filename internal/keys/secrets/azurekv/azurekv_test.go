// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package azurekv

import (
	"context"
	"errors"
	"fmt"
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
	// A file over the limit is refused from its size, and anything but a
	// regular file without reading it.
	huge := filepath.Join(t.TempDir(), "huge.pem")
	if err := os.WriteFile(huge, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(huge, maxCertFile+1); err != nil {
		t.Fatal(err)
	}
	v.TrustCertificateOverride = huge
	if _, err := New().Fetch(context.Background(), &secrets.Azure{AzureVault: v, SecretName: "validator-1"}); !errors.Is(err, secrets.ErrTooLarge) {
		t.Fatalf("a file over %d bytes: %v, want ErrTooLarge", maxCertFile, err)
	}
	v.TrustCertificateOverride = t.TempDir()
	if _, err := New().Fetch(context.Background(), &secrets.Azure{AzureVault: v, SecretName: "validator-1"}); err == nil {
		t.Fatal("a directory was accepted as the certificate file")
	}
}

// managedIdentityRuns counts the runs of TestManagedIdentity in this
// process (go test -count).
var managedIdentityRuns int

func TestManagedIdentity(t *testing.T) {
	f := secretstest.NewAzure(t)
	f.Put("validator-1", seed, nil)
	t.Setenv("IDENTITY_ENDPOINT", f.IdentityEndpoint())
	t.Setenv("IDENTITY_HEADER", f.IdentityHeader)
	// MSAL caches managed-identity tokens for the whole process, so a later
	// run of this test may get the system-assigned token from the cache;
	// the user-assigned identity has a new client id in each run, so that
	// its token is always requested.
	managedIdentityRuns++
	for _, tt := range []struct {
		mode, clientID string
	}{
		{secrets.AzureSystemAssignedIdentity, ""},
		{secrets.AzureUserAssignedIdentity, fmt.Sprintf("user-assigned-id-%d", managedIdentityRuns)},
	} {
		v := vaultOf(f)
		v.AuthMode, v.ClientID, v.ClientSecret, v.TenantID, v.AuthorityHostOverride = tt.mode, tt.clientID, nil, "", ""
		before := len(f.ManagedIdentityClientIDs)
		got, err := New().Fetch(context.Background(), &secrets.Azure{AzureVault: v, SecretName: "validator-1"})
		if err != nil || string(got) != seed {
			t.Fatalf("%s: Fetch = %q, %v", tt.mode, got, err)
		}
		ids := f.ManagedIdentityClientIDs
		switch {
		case len(ids) > before:
			if ids[len(ids)-1] != tt.clientID {
				t.Errorf("%s: asked for client id %q, want %q", tt.mode, ids[len(ids)-1], tt.clientID)
			}
		case tt.clientID != "" || managedIdentityRuns == 1:
			t.Errorf("%s: no managed-identity token request", tt.mode)
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

// TestLimits checks the bounds of every call: a vault that does not answer
// fails the fetch and the listing once the configured timeout passes,
// retries included, and a response larger than secrets.MaxResponseSize
// fails without being read whole.
func TestLimits(t *testing.T) {
	f := secretstest.NewAzure(t)
	f.Put("validator-1", seed, nil)
	f.Put("huge", strings.Repeat("0", secrets.MaxResponseSize), nil)
	ctx := context.Background()
	v := vaultOf(f)
	v.Timeout = 30 * time.Second
	stderr := secretstest.CaptureStderr(t)
	defer func() {
		if out := stderr(); out != "" {
			t.Errorf("the SDK wrote to stderr: %q", out)
		}
	}()

	if _, err := New().Fetch(ctx, &secrets.Azure{AzureVault: v, SecretName: "huge"}); !errors.Is(err, secrets.ErrTooLarge) {
		t.Errorf("a response larger than %d bytes: error = %v, want ErrTooLarge", secrets.MaxResponseSize, err)
	}
	if n := f.Reads("huge"); n != 1 {
		t.Errorf("a response larger than the limit was requested %d times: it was retried", n)
	}

	v.Timeout = 300 * time.Millisecond
	f.SetHang(true)
	defer f.SetHang(false)
	bounded := func(what string, call func() error) {
		t.Helper()
		start := time.Now()
		if err := call(); err == nil {
			t.Errorf("%s against a vault that does not answer succeeded", what)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s took %v with a %v timeout", what, d, v.Timeout)
		}
	}
	bounded("Fetch", func() error {
		_, err := New().Fetch(ctx, &secrets.Azure{AzureVault: v, SecretName: "validator-1"})
		return err
	})
	b, err := NewBulk(secrets.AzureBulk{AzureVault: v})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	bounded("List", func() error { _, err := b.List(ctx); return err })
	bounded("Get", func() error { _, err := b.Get(ctx, "validator-1"); return err })
}
