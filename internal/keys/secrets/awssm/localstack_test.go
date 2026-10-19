// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package awssm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets"
)

// EnvLocalStack is the endpoint of a LocalStack with Secrets Manager for
// the tests against it. make test-cloud starts one in Docker; the CI job
// cloud-secrets runs one as a service container. LocalStack accepts any
// access key.
const EnvLocalStack = "REMOTESIGNER_TEST_AWS_ENDPOINT"

func TestLocalStack(t *testing.T) {
	endpoint := os.Getenv(EnvLocalStack)
	if endpoint == "" {
		t.Skipf("set %s to run against LocalStack (make test-cloud)", EnvLocalStack)
	}
	isolate(t)
	ctx := context.Background()
	conn := secrets.AWSConn{AuthMode: secrets.AWSSpecified, Region: "us-east-1", AccessKeyID: "test",
		SecretAccessKey: []byte("test"), EndpointOverride: endpoint}
	admin, err := newClient(ctx, conn, storeHTTPClient())
	if err != nil {
		t.Fatal(err)
	}
	var rnd [6]byte
	_, _ = rand.Read(rnd[:])
	prefix := "remotesigner-" + hex.EncodeToString(rnd[:]) + "/"
	seed1, seed2 := "0x"+strings.Repeat("c1", 48), strings.Repeat("c2", 48)
	put := func(name, value string, tags ...types.Tag) {
		t.Helper()
		if _, err := admin.CreateSecret(ctx, &secretsmanager.CreateSecretInput{Name: aws.String(prefix + name),
			SecretString: aws.String(value), Tags: tags}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = admin.DeleteSecret(context.Background(), &secretsmanager.DeleteSecretInput{SecretId: aws.String(prefix + name),
				ForceDeleteWithoutRecovery: aws.Bool(true)})
		})
	}
	tag := func(k, v string) types.Tag { return types.Tag{Key: aws.String(k), Value: aws.String(v)} }
	put("one", seed1+"\n", tag("role", "single"))
	put("bulk-a", seed1+"\n"+seed2+"\n", tag("role", "bulk"), tag("team", "blue"))
	put("bulk-b", seed2, tag("role", "bulk"), tag("team", "red"))

	got, err := New(1).Fetch(ctx, &secrets.AWS{AWSConn: conn, SecretName: prefix + "one"})
	if err != nil || string(got) != seed1+"\n" {
		t.Fatalf("Fetch = %q, %v", got, err)
	}
	if _, err := New(1).Fetch(ctx, &secrets.AWS{AWSConn: conn, SecretName: prefix + "none"}); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("missing secret: %v", err)
	}

	for _, tt := range []struct {
		name string
		tags []secrets.Tag
		want []string
	}{
		{"prefix", nil, []string{prefix + "bulk-a", prefix + "bulk-b", prefix + "one"}},
		{"tag", []secrets.Tag{{Key: "role", Value: "bulk"}}, []string{prefix + "bulk-a", prefix + "bulk-b"}},
		// Any of the names with any of the values: one has role=single and
		// bulk-b team=red; bulk-a has neither value.
		{"two tags", []secrets.Tag{{Key: "role", Value: "single"}, {Key: "team", Value: "red"}},
			[]string{prefix + "bulk-b", prefix + "one"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b, err := NewBulk(ctx, secrets.AWSBulk{AWSConn: conn, PrefixesFilter: []string{prefix}, Tags: tt.tags})
			if err != nil {
				t.Fatal(err)
			}
			names, err := b.List(ctx)
			if err != nil {
				t.Fatal(err)
			}
			slices.Sort(names)
			if !slices.Equal(names, tt.want) {
				t.Fatalf("List = %v, want %v", names, tt.want)
			}
		})
	}

	b, err := NewBulk(ctx, secrets.AWSBulk{AWSConn: conn, PrefixesFilter: []string{prefix + "bulk-"}})
	if err != nil {
		t.Fatal(err)
	}
	batches, err := secrets.Bulk{Kind: secrets.KindAWS, Store: b}.Load(ctx, 2, nil)
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
