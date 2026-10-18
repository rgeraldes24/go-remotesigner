// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package gcpsm

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets/secretstest"
)

var seed = "0x" + strings.Repeat("d1", 48)

func TestFetch(t *testing.T) {
	f := secretstest.NewGCP(t)
	f.Put("p", "validator-1", []byte(seed+"\n"), nil)
	f.Put("p", "no-version", nil, nil)
	f.Put("p", "too-large", []byte(strings.Repeat("0", secrets.MaxValueSize+1)), nil)
	c := New()
	defer c.Close()
	ctx := context.Background()
	got, err := c.Fetch(ctx, &secrets.GCP{ProjectID: "p", SecretName: "validator-1", EndpointOverride: f.Endpoint})
	if err != nil || string(got) != seed+"\n" {
		t.Fatalf("Fetch = %q, %v", got, err)
	}
	for name, want := range map[string]error{"missing": secrets.ErrNotFound, "no-version": secrets.ErrNotFound,
		"too-large": secrets.ErrTooLarge} {
		_, err := c.Fetch(ctx, &secrets.GCP{ProjectID: "p", SecretName: name, EndpointOverride: f.Endpoint})
		if !errors.Is(err, want) {
			t.Errorf("%s: error = %v, want %v", name, err, want)
		}
	}
	if c.clients.Len() != 1 {
		t.Errorf("%d clients for one endpoint", c.clients.Len())
	}
}

func TestBulk(t *testing.T) {
	f := secretstest.NewGCP(t)
	f.Put("p", "a", []byte(seed), map[string]string{"role": "validator", "team": "blue"})
	f.Put("p", "b", []byte(seed+"\n"+"0x"+strings.Repeat("d2", 48)), map[string]string{"role": "validator"})
	f.Put("p", "c", []byte(seed), map[string]string{"role": "other"})
	f.Put("p", "d", []byte(seed), nil)
	f.Put("q", "e", []byte(seed), nil)
	ctx := context.Background()
	for _, tt := range []struct {
		filter string
		want   []string
	}{
		{"", []string{"projects/p/secrets/a", "projects/p/secrets/b", "projects/p/secrets/c", "projects/p/secrets/d"}},
		{"labels.role=validator", []string{"projects/p/secrets/a", "projects/p/secrets/b"}},
		{"labels.role=validator AND labels.team=blue", []string{"projects/p/secrets/a"}},
	} {
		b, err := NewBulk(ctx, secrets.GCPBulk{ProjectID: "p", Filter: tt.filter, EndpointOverride: f.Endpoint})
		if err != nil {
			t.Fatal(err)
		}
		names, err := b.List(ctx)
		_ = b.Close()
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(names, tt.want) {
			t.Errorf("filter %q: List = %v, want %v", tt.filter, names, tt.want)
		}
	}
	if f.Filters[len(f.Filters)-1] != "labels.role=validator AND labels.team=blue" {
		t.Errorf("filters sent: %q", f.Filters)
	}

	b, err := NewBulk(ctx, secrets.GCPBulk{ProjectID: "p", Filter: "labels.role=validator", EndpointOverride: f.Endpoint})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
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
	if len(batches) != 2 || keys != 3 || batches[0].Source != "gcp-bulk:projects/p/secrets/a" {
		t.Fatalf("%d batches (%s first) with %d keys", len(batches), batches[0].Source, keys)
	}

	bad, err := NewBulk(ctx, secrets.GCPBulk{ProjectID: "p", Filter: "name:x", EndpointOverride: f.Endpoint})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = bad.Close() }()
	if _, err := bad.List(ctx); err == nil || !strings.Contains(err.Error(), "list-secrets") {
		t.Fatalf("rejected filter: %v", err)
	}
	if _, err := NewBulk(ctx, secrets.GCPBulk{}); !errors.Is(err, secrets.ErrConfig) {
		t.Fatalf("no project: %v", err)
	}
}

// A cached client keeps working after the fetch that built it is done and
// its context cancelled, as the next reload's fetches use it.
func TestCachedClientOutlivesItsFetch(t *testing.T) {
	f := secretstest.NewGCP(t)
	f.Put("p", "validator-1", []byte(seed), nil)
	c := New()
	defer c.Close()
	spec := &secrets.GCP{ProjectID: "p", SecretName: "validator-1", EndpointOverride: f.Endpoint}
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := c.Fetch(ctx, spec); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := c.Fetch(context.Background(), spec); err != nil {
		t.Fatalf("a later fetch with the cached client: %v", err)
	}
}
