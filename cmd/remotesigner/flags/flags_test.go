// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package flags

import (
	"slices"
	"strings"
	"testing"

	"github.com/urfave/cli/v2"
)

func TestFlags(t *testing.T) {
	seen := map[string]string{}
	for cmd, fs := range map[string][]cli.Flag{"": Global(), ConsensusCommand: Consensus()} {
		for _, f := range fs {
			d, ok := f.(cli.DocGenerationFlag)
			if !ok {
				t.Fatalf("%v cannot be documented", f.Names())
			}
			if d.GetUsage() == "" {
				t.Errorf("--%s has no usage text", f.Names()[0])
			}
			for _, n := range f.Names() {
				if prev, dup := seen[n]; dup {
					t.Errorf("--%s is defined for %q and %q; config-file keys would be ambiguous", n, prev, cmd)
				}
				seen[n] = cmd
			}
			env := d.GetEnvVars()
			if f.Names()[0] == ConfigFile {
				if len(env) != 0 {
					t.Errorf("--config-file has environment variables %v", env)
				}
				continue
			}
			if len(env) != len(f.Names()) {
				t.Errorf("--%s: env %v for names %v", f.Names()[0], env, f.Names())
			}
			for _, e := range env {
				prefix := "REMOTESIGNER_"
				if cmd != "" {
					prefix += "CONSENSUS_"
				}
				if !strings.HasPrefix(e, prefix) {
					t.Errorf("--%s: env %s lacks prefix %s", f.Names()[0], e, prefix)
				}
			}
		}
	}
	for _, name := range []string{KeyStorePath, DataPath, HTTPListenPort, Logging, Network, SlashingProtectionEnabled, KeyManagerAPIEnabled} {
		if _, ok := seen[name]; !ok {
			t.Errorf("e2e flag --%s is missing", name)
		}
	}
	// Each call returns fresh flags: urfave flags hold parse state.
	if Global()[0] == Global()[0] {
		t.Error("Global returns shared flag values")
	}
	if !slices.Contains(Global()[2].Names(), KeyStorePath) {
		t.Error("--key-store-path is not an alias of --key-config-path")
	}
}
