// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package awssm

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets/secretstest"
)

const seed = "0x" + "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"

// isolate keeps the SDK away from the developer's AWS configuration and
// the instance metadata service.
func isolate(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	for _, v := range []string{"AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_SECRETS_MANAGER"} {
		t.Setenv(v, "")
	}
}

func specified(endpoint, id string) secrets.AWSConn {
	return secrets.AWSConn{AuthMode: secrets.AWSSpecified, Region: "us-east-1", AccessKeyID: id,
		SecretAccessKey: []byte("secret-" + id), EndpointOverride: endpoint}
}

func TestFetch(t *testing.T) {
	isolate(t)
	f := secretstest.NewAWS(t)
	f.Put("validator-1", seed, nil)
	f.PutBinary("binary", []byte{1, 2, 3})
	f.Put("too-large", strings.Repeat("0", secrets.MaxValueSize+1), nil)
	c := New(1)
	ctx := context.Background()
	got, err := c.Fetch(ctx, &secrets.AWS{AWSConn: specified(f.URL, "AKID1"), SecretName: "validator-1"})
	if err != nil || string(got) != seed {
		t.Fatalf("Fetch = %q, %v", got, err)
	}
	if f.AccessKeys[len(f.AccessKeys)-1] != "AKID1" {
		t.Errorf("signed with %v", f.AccessKeys)
	}
	for name, want := range map[string]error{"missing": secrets.ErrNotFound, "too-large": secrets.ErrTooLarge} {
		_, err := c.Fetch(ctx, &secrets.AWS{AWSConn: specified(f.URL, "AKID1"), SecretName: name})
		if !errors.Is(err, want) {
			t.Errorf("%s: error = %v, want %v", name, err, want)
		}
	}
	_, err = c.Fetch(ctx, &secrets.AWS{AWSConn: specified(f.URL, "AKID1"), SecretName: "binary"})
	if err == nil || !strings.Contains(err.Error(), "no string value") {
		t.Errorf("binary secret: %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "secret-AKID1") {
		t.Fatalf("error quotes the secret access key: %v", err)
	}

	// A second access key gets its own client; the cache keeps one.
	if _, err := c.Fetch(ctx, &secrets.AWS{AWSConn: specified(f.URL, "AKID2"), SecretName: "validator-1"}); err != nil {
		t.Fatal(err)
	}
	if f.AccessKeys[len(f.AccessKeys)-1] != "AKID2" || c.clients.Len() != 1 {
		t.Errorf("signed with %v, %d cached clients", f.AccessKeys, c.clients.Len())
	}
}

func TestEnvironmentCredentials(t *testing.T) {
	isolate(t)
	f := secretstest.NewAWS(t)
	f.Put("validator-1", seed, nil)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDENV")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "env-secret")
	conn := secrets.AWSConn{AuthMode: secrets.AWSEnvironment, EndpointOverride: f.URL}
	if _, err := New(1).Fetch(context.Background(), &secrets.AWS{AWSConn: conn, SecretName: "validator-1"}); err == nil ||
		!strings.Contains(err.Error(), "no AWS region") {
		t.Fatalf("no region: %v", err)
	}
	t.Setenv("AWS_REGION", "eu-west-1")
	got, err := New(1).Fetch(context.Background(), &secrets.AWS{AWSConn: conn, SecretName: "validator-1"})
	if err != nil || string(got) != seed || f.AccessKeys[len(f.AccessKeys)-1] != "AKIDENV" {
		t.Fatalf("Fetch = %q, %v, signed with %v", got, err, f.AccessKeys)
	}
}

func TestBulk(t *testing.T) {
	isolate(t)
	f := secretstest.NewAWS(t)
	f.Put("validators/a", seed, map[string]string{"team": "blue", "env": "prod"})
	f.Put("validators/b", seed, map[string]string{"team": "red"})
	f.Put("validators/c", seed, map[string]string{"team": "blue"})
	f.Put("other/d", seed, map[string]string{"team": "blue"})
	tests := []struct {
		name     string
		prefixes []string
		tags     []secrets.Tag
		want     []string
	}{
		{"all", nil, nil, []string{"validators/a", "validators/b", "validators/c", "other/d"}},
		{"prefix", []string{"validators/"}, nil, []string{"validators/a", "validators/b", "validators/c"}},
		{"two prefixes", []string{"validators/b", "other/"}, nil, []string{"validators/b", "other/d"}},
		{"tag key", nil, []secrets.Tag{{Key: "env"}}, []string{"validators/a"}},
		{"tag value", []string{"validators/"}, []secrets.Tag{{Key: "team", Value: "blue"}}, []string{"validators/a", "validators/c"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := NewBulk(context.Background(), secrets.AWSBulk{AWSConn: specified(f.URL, "AKID"),
				PrefixesFilter: tt.prefixes, Tags: tt.tags})
			if err != nil {
				t.Fatal(err)
			}
			got, err := b.List(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("List = %v, want %v", got, tt.want)
			}
		})
	}
	b, err := NewBulk(context.Background(), secrets.AWSBulk{AWSConn: specified(f.URL, "AKID")})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	batches, err := secrets.Bulk{Kind: secrets.KindAWS, Store: b}.Load(context.Background(), 2, nil)
	if err != nil || len(batches) != 4 {
		t.Fatalf("Load = %d batches, %v", len(batches), err)
	}
	for _, x := range batches {
		if x.Err != nil || len(x.Keys) != 1 {
			t.Errorf("%s: %d keys, %v", x.Source, len(x.Keys), x.Err)
		}
		for _, k := range x.Keys {
			k.Zeroize()
		}
	}
}
