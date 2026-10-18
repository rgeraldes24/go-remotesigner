// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets"
)

func TestSecretStoreFlags(t *testing.T) {
	cfg, code, stderr := capture(t, "consensus", "--network=e2e")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if st := cfg.Consensus.SecretStores; st.AWS != nil || st.Azure != nil || st.GCP != nil || st.AWSClientCacheSize != 1 {
		t.Fatalf("defaults: %+v", st)
	}

	refusals := []struct {
		args []string
		want string
	}{
		{[]string{"--aws-connection-cache-size=0"}, "--aws-connection-cache-size must be at least 1"},
	}
	if !cloudSecretStores {
		// remotesigner-consensus links no cloud SDK.
		for _, f := range []string{"--aws-secrets-enabled", "--azure-vault-enabled", "--gcp-secrets-enabled"} {
			refusals = append(refusals, struct {
				args []string
				want string
			}{[]string{f}, f + ": remotesigner-consensus has no cloud secret stores; use the remotesigner flavour"})
		}
	} else {
		refusals = append(refusals, []struct {
			args []string
			want string
		}{
			{[]string{"--aws-secrets-enabled"}, "--aws-secrets-auth-mode=SPECIFIED, but the following parameters were " +
				"missing [--aws-secrets-access-key-id, --aws-secrets-secret-access-key, --aws-secrets-region]"},
			{[]string{"--aws-secrets-enabled", "--aws-secrets-auth-mode=IAM"}, "--aws-secrets-auth-mode"},
			{[]string{"--aws-secrets-enabled", "--aws-secrets-auth-mode=ENVIRONMENT", "--aws-endpoint-override=localhost:4566"},
				"--aws-endpoint-override: want an http:// or https:// URL"},
			{[]string{"--aws-secrets-enabled", "--aws-secrets-auth-mode=ENVIRONMENT", "--aws-secrets-tag==v"}, "--aws-secrets-tag"},
			{[]string{"--gcp-secrets-enabled"}, "--gcp-secrets-enabled=true, but the following parameters were missing [--gcp-project-id]"},
			{[]string{"--azure-vault-enabled"}, "--azure-vault-enabled=true, but the following parameters were missing " +
				"[--azure-vault-name, --azure-client-id, --azure-client-secret, --azure-tenant-id]"},
			{[]string{"--azure-vault-enabled", "--azure-vault-auth-mode=USER_ASSIGNED_MANAGED_IDENTITY", "--azure-vault-name=v"},
				"missing [--azure-client-id]"},
			{[]string{"--azure-vault-enabled", "--azure-vault-auth-mode=SYSTEM_ASSIGNED_MANAGED_IDENTITY", "--azure-vault-name=v",
				"--azure-response-timeout=0"}, "--azure-response-timeout must be 1"},
		}...)
	}
	for _, tc := range refusals {
		args := append([]string{"consensus", "--network=e2e"}, tc.args...)
		if _, code, stderr := capture(t, args...); code != exitUsage || !strings.Contains(stderr, tc.want) {
			t.Errorf("%v: exit %d %q, want a usage error mentioning %q", tc.args, code, stderr, tc.want)
		}
	}
	if !cloudSecretStores {
		return
	}

	cfg, code, stderr = capture(t, "consensus", "--network=e2e", "--aws-secrets-enabled",
		"--aws-secrets-access-key-id=AKID", "--aws-secrets-secret-access-key=shh", "--aws-secrets-region=us-east-1",
		"--aws-endpoint-override=http://localhost:4566", "--aws-secrets-prefixes-filter=a/,b/",
		"--aws-secrets-tag=team=blue|env=prod", "--aws-secrets-tag=role", "--aws-connection-cache-size=3",
		"--gcp-secrets-enabled", "--gcp-project-id=p", "--gcp-secrets-filter=labels.role=validator",
		"--Xgcp-endpoint-override=http://127.0.0.1:9090",
		"--azure-vault-enabled", "--azure-vault-name=v", "--azure-client-id=c", "--azure-tenant-id=t",
		"--azure-client-secret=az-shh", "--azure-response-timeout=5", "--azure-tags=role=validator",
		"--Xazure-endpoint-override=https://127.0.0.1:8443", "--Xazure-authority-host-override=https://127.0.0.1:8444",
		"--Xazure-trust-certificate-override=/ca.pem")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	st := cfg.Consensus.SecretStores
	aws, az, gcp := st.AWS, st.Azure, st.GCP
	if st.AWSClientCacheSize != 3 || aws == nil || aws.AuthMode != secrets.AWSSpecified || aws.AccessKeyID != "AKID" ||
		string(aws.SecretAccessKey) != "shh" || aws.Region != "us-east-1" || aws.EndpointOverride != "http://localhost:4566" ||
		!slices.Equal(aws.PrefixesFilter, []string{"a/", "b/"}) ||
		!slices.Equal(aws.Tags, []secrets.Tag{{Key: "team", Value: "blue"}, {Key: "env", Value: "prod"}, {Key: "role"}}) {
		t.Errorf("AWS: %+v", aws)
	}
	if gcp == nil || *gcp != (secrets.GCPBulk{ProjectID: "p", Filter: "labels.role=validator", EndpointOverride: "http://127.0.0.1:9090"}) {
		t.Errorf("GCP: %+v", gcp)
	}
	if az == nil || az.AuthMode != secrets.AzureClientSecret || az.VaultName != "v" || az.ClientID != "c" ||
		az.TenantID != "t" || string(az.ClientSecret) != "az-shh" || az.Timeout != 5*time.Second ||
		az.EndpointOverride != "https://127.0.0.1:8443" || az.AuthorityHostOverride != "https://127.0.0.1:8444" ||
		az.TrustCertificateOverride != "/ca.pem" || !slices.Equal(az.Tags, []secrets.Tag{{Key: "role", Value: "validator"}}) {
		t.Errorf("Azure: %+v", az)
	}
	if s := fmt.Sprintf("%+v %+v", aws, az); strings.Contains(s, "shh") {
		t.Errorf("a configuration prints a credential: %s", s)
	}

	t.Run("environment", func(t *testing.T) {
		t.Setenv("REMOTESIGNER_CONSENSUS_AWS_SECRETS_ENABLED", "true")
		t.Setenv("REMOTESIGNER_CONSENSUS_AWS_SECRETS_AUTH_MODE", "environment")
		t.Setenv("REMOTESIGNER_CONSENSUS_AWS_SECRETS_SECRET_ACCESS_KEY", "env-shh")
		cfg, code, stderr := capture(t, "consensus", "--network=e2e")
		if code != exitOK || cfg.Consensus.SecretStores.AWS == nil ||
			cfg.Consensus.SecretStores.AWS.AuthMode != secrets.AWSEnvironment ||
			string(cfg.Consensus.SecretStores.AWS.SecretAccessKey) != "env-shh" {
			t.Fatalf("exit %d %s: %+v", code, stderr, cfg)
		}
	})
}
