// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets"
	"github.com/rgeraldes24/go-remotesigner/internal/runner"
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
		{[]string{"--aws-secrets-secret-access-key=shh", "--aws-secrets-secret-access-key-file=/k"},
			"only one of --aws-secrets-secret-access-key-file or --aws-secrets-secret-access-key can be specified"},
		{[]string{"--azure-client-secret=shh", "--azure-client-secret-file=/k"},
			"only one of --azure-client-secret-file or --azure-client-secret can be specified"},
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
				"missing [--aws-secrets-access-key-id, --aws-secrets-secret-access-key-file, --aws-secrets-region]"},
			{[]string{"--aws-secrets-enabled", "--aws-secrets-auth-mode=IAM"}, "--aws-secrets-auth-mode"},
			{[]string{"--aws-secrets-enabled", "--aws-secrets-auth-mode=ENVIRONMENT", "--aws-endpoint-override=localhost:4566"},
				"--aws-endpoint-override: want an http:// or https:// URL"},
			{[]string{"--aws-secrets-enabled", "--aws-secrets-auth-mode=ENVIRONMENT", "--aws-secrets-tag==v"}, "--aws-secrets-tag"},
			{[]string{"--gcp-secrets-enabled"}, "--gcp-secrets-enabled=true, but the following parameters were missing [--gcp-project-id]"},
			{[]string{"--azure-vault-enabled"}, "--azure-vault-enabled=true, but the following parameters were missing " +
				"[--azure-vault-name, --azure-client-id, --azure-client-secret-file, --azure-tenant-id]"},
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
	wantPlain := []config.PlainSecret{
		{Flag: "aws-secrets-secret-access-key", FileFlag: "aws-secrets-secret-access-key-file", Source: config.FromCommandLine},
		{Flag: "azure-client-secret", FileFlag: "azure-client-secret-file", Source: config.FromCommandLine},
	}
	if !slices.Equal(st.Plain, wantPlain) || st.AWSSecretAccessKeyFile != "" || st.AzureClientSecretFile != "" {
		t.Errorf("plain secrets %+v, files %q %q", st.Plain, st.AWSSecretAccessKeyFile, st.AzureClientSecretFile)
	}

	// The -file flags satisfy the required-parameter checks; the run reads
	// them.
	cfg, code, stderr = capture(t, "consensus", "--network=e2e", "--aws-secrets-enabled",
		"--aws-secrets-access-key-id=AKID", "--aws-secrets-secret-access-key-file=/aws-key", "--aws-secrets-region=r",
		"--azure-vault-enabled", "--azure-vault-name=v", "--azure-client-id=c", "--azure-tenant-id=t",
		"--azure-client-secret-file=/azure-secret")
	if code != exitOK {
		t.Fatalf("-file flags: exit %d: %s", code, stderr)
	}
	st = cfg.Consensus.SecretStores
	if st.AWSSecretAccessKeyFile != "/aws-key" || st.AzureClientSecretFile != "/azure-secret" || len(st.Plain) != 0 ||
		len(st.AWS.SecretAccessKey) != 0 || len(st.Azure.ClientSecret) != 0 {
		t.Errorf("-file flags: %+v", st)
	}
	// Without their loaders the -file flags are not read.
	if cfg, _, _ = capture(t, "consensus", "--network=e2e", "--aws-secrets-secret-access-key-file=/aws-key"); cfg.Consensus.SecretStores.AWSSecretAccessKeyFile != "" {
		t.Errorf("a -file flag without its loader: %+v", cfg.Consensus.SecretStores)
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
		if p := cfg.Consensus.SecretStores.Plain; len(p) != 1 || p[0].Source != config.FromEnvironment {
			t.Fatalf("plain secrets %+v", p)
		}
		t.Setenv("REMOTESIGNER_CONSENSUS_AWS_SECRETS_SECRET_ACCESS_KEY_FILE", "/aws-key")
		if _, code, stderr := capture(t, "consensus", "--network=e2e"); code != exitUsage || !strings.Contains(stderr, "only one of") {
			t.Fatalf("plain and -file variables: exit %d %s", code, stderr)
		}
	})
}

// The run warns about a plain secret flag by the source of its value: the
// command line, which every local user can read, wins over the
// environment, which wins over the config file. A value on the command line
// is reported as such even when the environment sets the flag too.
func TestPlainSecretSources(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(file, []byte("consensus:\n  azure-client-secret: from-file\n  aws-secrets-secret-access-key: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sources := func(args ...string) map[string]config.PlainSecret {
		t.Helper()
		cfg, code, stderr := capture(t, append([]string{"--config-file=" + file, "consensus", "--network=e2e"}, args...)...)
		if code != exitOK {
			t.Fatalf("%v: exit %d %s", args, code, stderr)
		}
		out := map[string]config.PlainSecret{}
		for _, p := range cfg.Consensus.SecretStores.Plain {
			out[p.Flag] = p
		}
		return out
	}
	got := sources()
	if got["azure-client-secret"] != (config.PlainSecret{Flag: "azure-client-secret", FileFlag: "azure-client-secret-file",
		Source: config.FromConfigFile, File: file}) || got["aws-secrets-secret-access-key"].Source != config.FromConfigFile {
		t.Errorf("config file: %+v", got)
	}
	// The config file holds the secret, and so stays a secret file, when
	// the environment or the command line wins.
	t.Setenv("REMOTESIGNER_CONSENSUS_AZURE_CLIENT_SECRET", "from-env")
	if got = sources(); got["azure-client-secret"].Source != config.FromEnvironment || got["azure-client-secret"].File != file {
		t.Errorf("environment over the config file: %+v", got)
	}
	for _, arg := range []string{"--azure-client-secret=x", "-azure-client-secret=x"} {
		if got = sources(arg); got["azure-client-secret"].Source != config.FromCommandLine ||
			got["azure-client-secret"].File != file || got["aws-secrets-secret-access-key"].Source != config.FromConfigFile {
			t.Errorf("%s: %+v", arg, got)
		}
	}
	// Without the file, no file is named.
	cfg, code, stderr := capture(t, "consensus", "--network=e2e", "--azure-client-secret=x")
	if p := cfg.Consensus.SecretStores.Plain; code != exitOK || len(p) != 1 || p[0].File != "" || p[0].Source != config.FromCommandLine {
		t.Errorf("no config file: exit %d %s, %+v", code, stderr, p)
	}
	if got = sources("--azure-client-secret", "x"); got["azure-client-secret"].Source != config.FromCommandLine {
		t.Errorf("value as the next argument: %+v", got)
	}
}

// An empty value on the command line or in the environment overrides the
// config file's secret but leaves it in the file, which stays a secret
// file: under --strict-file-permissions one its group can read refuses the
// start, and the plain flag still conflicts with its -file flag. Without a
// config file that holds it, an empty value holds no secret.
func TestPlainSecretEmptyOverride(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(file, []byte("consensus:\n  azure-client-secret: from-file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(file, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want := []config.PlainSecret{{Flag: "azure-client-secret", FileFlag: "azure-client-secret-file",
		Source: config.FromConfigFile, File: file}}
	overrides := []struct {
		name string
		env  bool
		args []string
	}{
		{"none", false, nil},
		{"empty variable", true, nil},
		{"empty flag", false, []string{"--azure-client-secret="}},
		{"empty flag and variable", true, []string{"--azure-client-secret="}},
	}
	for _, tt := range overrides {
		t.Run(tt.name, func(t *testing.T) {
			if tt.env {
				t.Setenv("REMOTESIGNER_CONSENSUS_AZURE_CLIENT_SECRET", "")
			}
			cfg, code, stderr := capture(t, append([]string{"--config-file=" + file, "consensus", "--network=e2e"},
				tt.args...)...)
			if code != exitOK {
				t.Fatalf("exit %d %s", code, stderr)
			}
			if p := cfg.Consensus.SecretStores.Plain; !slices.Equal(p, want) {
				t.Fatalf("plain secrets %+v, want %+v", p, want)
			}
			if runtime.GOOS == "windows" {
				return
			}
			cfg.StrictFilePermissions = true
			if err := runner.StoreCredentials(cfg, logrus.New()); err == nil ||
				!strings.Contains(err.Error(), "--config-file holds --azure-client-secret, so it is a secret file") {
				t.Fatalf("a group-readable config file that holds the secret: %v", err)
			}
		})
		t.Run(tt.name+" with the -file flag", func(t *testing.T) {
			if tt.env {
				t.Setenv("REMOTESIGNER_CONSENSUS_AZURE_CLIENT_SECRET", "")
			}
			args := append([]string{"--config-file=" + file, "consensus", "--network=e2e",
				"--azure-client-secret-file=/x"}, tt.args...)
			if _, code, stderr := capture(t, args...); code != exitUsage || !strings.Contains(stderr,
				"only one of --azure-client-secret-file or --azure-client-secret can be specified") {
				t.Fatalf("exit %d %s", code, stderr)
			}
		})
	}
	// No config file: an empty value is no secret, and no conflict.
	t.Setenv("REMOTESIGNER_CONSENSUS_AZURE_CLIENT_SECRET", "")
	cfg, code, stderr := capture(t, "consensus", "--network=e2e", "--azure-client-secret=", "--azure-client-secret-file=/x")
	if code != exitOK || len(cfg.Consensus.SecretStores.Plain) != 0 {
		t.Fatalf("exit %d %s, %+v", code, stderr, cfg)
	}
}

func TestOnCommandLine(t *testing.T) {
	const name = "azure-client-secret"
	for _, tt := range []struct {
		args []string
		want bool
	}{
		{[]string{"remotesigner", "consensus", "--azure-client-secret=s"}, true},
		{[]string{"remotesigner", "consensus", "--azure-client-secret", "s"}, true},
		{[]string{"remotesigner", "consensus", "-azure-client-secret=s"}, true},
		{[]string{"remotesigner", "consensus", "--azure-client-secret-file=/f"}, false},
		{[]string{"remotesigner", "consensus", "--azure-client-secrets=s"}, false},
		{[]string{"remotesigner", "consensus", "azure-client-secret=s"}, false},
		{[]string{"remotesigner", "consensus", "--", "--azure-client-secret=s"}, false},
		{nil, false},
	} {
		if got := onCommandLine(tt.args, name); got != tt.want {
			t.Errorf("%v: %v, want %v", tt.args, got, tt.want)
		}
	}
}
