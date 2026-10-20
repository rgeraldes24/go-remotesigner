// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/urfave/cli/v2"

	"github.com/rgeraldes24/go-remotesigner/cmd/remotesigner/flags"
)

// docs/reference/flags.md must be what flagdoc renders: a flag change without
// `make docs` fails CI here.
func TestFlagsReferenceIsCurrent(t *testing.T) {
	got, err := os.ReadFile("../../docs/reference/flags.md")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, render()) {
		t.Fatal("docs/reference/flags.md is stale; run `make docs`")
	}
}

func TestRender(t *testing.T) {
	doc := string(render())
	for _, want := range []string{
		"| `--key-config-path`, `--key-store-path` | `REMOTESIGNER_KEY_CONFIG_PATH`, `REMOTESIGNER_KEY_STORE_PATH` | `key-config-path` or `key-store-path` | unset |",
		"| `--logging`, `-l` | `REMOTESIGNER_LOGGING`, `REMOTESIGNER_L` | `logging` or `l` |",
		"| `--logging-format`, `--log-format` | `REMOTESIGNER_LOGGING_FORMAT`, `REMOTESIGNER_LOG_FORMAT` | `logging-format` or `log-format` |",
		"| `--network` | `REMOTESIGNER_CONSENSUS_NETWORK` | `network` or `consensus.network` | unset |",
		"| `--http-host-allowlist` | `REMOTESIGNER_HTTP_HOST_ALLOWLIST` | `http-host-allowlist` | `localhost,127.0.0.1,::1` |",
		"| `--slashing-protection-enabled` | `REMOTESIGNER_CONSENSUS_SLASHING_PROTECTION_ENABLED` | `slashing-protection-enabled` or `consensus.slashing-protection-enabled` | `true` |",
		"| `--config-file` | none | none | unset |",
		"| `--logging`, `-l` |",
		"`--Xallow-plaintext-token-auth`",
		"| `--downstream-http-port` | `REMOTESIGNER_EXECUTION_DOWNSTREAM_HTTP_PORT` | `downstream-http-port` or `execution.downstream-http-port` | `8545` |",
		"| `--execution-proxy-allowed-methods` | `REMOTESIGNER_EXECUTION_EXECUTION_PROXY_ALLOWED_METHODS` | `execution-proxy-allowed-methods` or `execution.execution-proxy-allowed-methods` | `qrl_*,net_*,web3_*` |",
		"| `--keystores-path` | `REMOTESIGNER_EXECUTION_KEYSTORES_PATH` |",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("rendered reference lacks %q", want)
		}
	}
	if i, j := strings.Index(doc, "## Override flags"), strings.Index(doc, "--Xallow-gvr-tofu"); j < i {
		t.Error("a hidden flag is listed outside the override section")
	}
}

// Every --Xallow-* override is explained in the reference: what it lifts,
// the risk it accepts and what to configure instead. An override added
// without its explanation, or an explanation left behind by a removed flag,
// fails here. The other hidden flags are the secret-store overrides
// (--Xazure-*, --Xgcp-*), which lift no refusal: the override section names
// them, and their store pages explain them.
func TestEveryOverrideIsExplained(t *testing.T) {
	doc := string(render())
	explained := flags.Overrides()
	var hidden []string
	for _, fs := range [][]cli.Flag{flags.Global(), flags.Consensus()} {
		for _, f := range fs {
			if isHidden(f) {
				hidden = append(hidden, f.Names()[0])
			}
		}
	}
	// Subcommand flags are rendered without an override section.
	for _, fs := range [][]cli.Flag{flags.Migrate(), flags.Import(), flags.Export(), flags.WatermarkRepair(),
		flags.SetHighWatermark(), flags.RandaoStateReset(), flags.KeystoreVerify(), flags.DisableValidatorFlags()} {
		for _, f := range fs {
			if isHidden(f) {
				t.Errorf("--%s: a hidden subcommand flag is not rendered", f.Names()[0])
			}
		}
	}
	if len(hidden) == 0 {
		t.Fatal("no hidden flags")
	}
	for _, name := range hidden {
		if !strings.HasPrefix(name, "X") {
			t.Errorf("--%s is hidden but not an --X override", name)
		}
		if !isFailSafeOverride(name) {
			family, ok := storeOverride(name)
			if !ok {
				t.Errorf("--%s is hidden but neither an --Xallow-* nor a secret-store override", name)
			} else if !strings.Contains(doc, "`--"+family+"-*`") {
				t.Errorf("--%s: the override section does not name `--%s-*`", name, family)
			}
			if _, ok := explained[name]; ok || strings.Contains(doc, "\n#### `--"+name+"`\n") {
				t.Errorf("--%s lifts no refusal, but the reference explains it as one", name)
			}
			continue
		}
		o, ok := explained[name]
		if !ok || o.Refused == "" || o.Risk == "" || o.Instead == "" {
			t.Errorf("--%s: explanation %+v, want what it lifts, its risk and what to do instead", name, o)
		}
		if !strings.Contains(doc, "\n#### `--"+name+"`\n") {
			t.Errorf("--%s has no explanation heading in the reference", name)
		}
	}
	for name := range explained {
		if !slices.Contains(hidden, name) {
			t.Errorf("flags.Overrides explains --%s, which is no hidden flag", name)
		}
	}
}

// storeOverride returns the family of a secret-store override's name: Xazure
// or Xgcp.
func storeOverride(name string) (string, bool) {
	for _, family := range []string{"Xazure", "Xgcp"} {
		if strings.HasPrefix(name, family+"-") {
			return family, true
		}
	}
	return "", false
}

func TestConfigKeys(t *testing.T) {
	for _, tt := range []struct {
		names   []string
		command string
		want    string
	}{
		{[]string{"data-path"}, "", "`data-path`"},
		{[]string{"key-config-path", "key-store-path"}, "", "`key-config-path` or `key-store-path`"},
		{[]string{"network"}, "consensus", "`network` or `consensus.network`"},
		{[]string{"a", "b"}, "consensus", "`a`, `b`, `consensus.a` or `consensus.b`"},
	} {
		if got := configKeys(tt.names, tt.command); got != tt.want {
			t.Errorf("configKeys(%q, %q) = %s, want %s", tt.names, tt.command, got, tt.want)
		}
	}
}

func TestMarkup(t *testing.T) {
	got := markup("with --http-auth-mode=token and no --tls-cert-file (re-read on SIGHUP)")
	want := "with `--http-auth-mode=token` and no `--tls-cert-file` (re-read on SIGHUP)"
	if got != want {
		t.Errorf("markup = %q, want %q", got, want)
	}
}
