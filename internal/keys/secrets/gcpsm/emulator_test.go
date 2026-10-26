// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package gcpsm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets/secretstest"
)

// The client against a Secret Manager emulator: a single secret's latest
// version, a missing secret, and the bulk loader's listing of a project and
// its load. floci-gcp 0.11.0 ignores ListSecrets' filter, so the label
// filters are tested against the in-process fake only (TestBulk).
func TestGCPEmulator(t *testing.T) {
	endpoint := secretstest.GCPEmulator(t)
	ctx := context.Background()
	var rnd [6]byte
	_, _ = rand.Read(rnd[:])
	project := "remotesigner-" + hex.EncodeToString(rnd[:])
	parent := "projects/" + project
	seed1, seed2 := "0x"+strings.Repeat("e1", 48), strings.Repeat("e2", 48)
	put := func(name string, labels map[string]string, versions ...string) {
		t.Helper()
		secretstest.PutGCPSecret(t, endpoint, project, name, labels, versions...)
	}
	// The latest version is read: "one" was rotated from a bad value.
	put("one", map[string]string{"role": "single"}, "not a seed", seed1+"\n")
	put("bulk-a", map[string]string{"role": "validator", "team": "blue"}, seed1+"\n"+seed2+"\n")
	put("bulk-b", map[string]string{"role": "validator"}, seed2)

	got, err := New().Fetch(ctx, &secrets.GCP{ProjectID: project, SecretName: "one", EndpointOverride: endpoint})
	if err != nil || string(got) != seed1+"\n" {
		t.Fatalf("Fetch = %q, %v", got, err)
	}
	if _, err := New().Fetch(ctx, &secrets.GCP{ProjectID: project, SecretName: "none", EndpointOverride: endpoint}); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("missing secret: %v", err)
	}

	b, err := NewBulk(ctx, secrets.GCPBulk{ProjectID: project, EndpointOverride: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	names, err := b.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(names)
	if want := []string{parent + "/secrets/bulk-a", parent + "/secrets/bulk-b", parent + "/secrets/one"}; !slices.Equal(names, want) {
		t.Fatalf("List = %v, want %v", names, want)
	}
	batches, err := secrets.Bulk{Kind: secrets.KindGCP, Store: b}.Load(ctx, 2, nil)
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
	if len(batches) != 3 || keys != 4 {
		t.Fatalf("%d batches with %d keys, want 3 with 4", len(batches), keys)
	}
}
