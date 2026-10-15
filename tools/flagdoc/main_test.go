// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
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
		"| `--key-config-path`, `--key-store-path` | `REMOTESIGNER_KEY_CONFIG_PATH`, `REMOTESIGNER_KEY_STORE_PATH` | `key-config-path` | unset |",
		"| `--network` | `REMOTESIGNER_CONSENSUS_NETWORK` | `network` or `consensus.network` | unset |",
		"| `--http-host-allowlist` | `REMOTESIGNER_HTTP_HOST_ALLOWLIST` | `http-host-allowlist` | `localhost,127.0.0.1,::1` |",
		"| `--slashing-protection-enabled` | `REMOTESIGNER_CONSENSUS_SLASHING_PROTECTION_ENABLED` | `slashing-protection-enabled` or `consensus.slashing-protection-enabled` | `true` |",
		"| `--config-file` | none | none | unset |",
		"| `--logging`, `-l` |",
		"`--Xallow-plaintext-token-auth`",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("rendered reference lacks %q", want)
		}
	}
	if i, j := strings.Index(doc, "## Override flags"), strings.Index(doc, "--Xallow-gvr-tofu"); j < i {
		t.Error("a hidden flag is listed outside the override section")
	}
}
