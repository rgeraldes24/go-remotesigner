// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package flags

import (
	"slices"
	"strings"
	"testing"

	"github.com/urfave/cli/v2"
)

// The commands may share flag names (one process runs one command, so a
// top-level config-file key applies to that one), but none may reuse a
// global flag's name.
func TestFlags(t *testing.T) {
	global := map[string]bool{}
	for _, f := range Global() {
		for _, n := range f.Names() {
			global[n] = true
		}
	}
	all := map[string]string{}
	for cmd, fs := range map[string][]cli.Flag{"": Global(), ConsensusCommand: Consensus(), ExecutionCommand: Execution()} {
		seen := map[string]string{}
		for _, f := range fs {
			d, ok := f.(cli.DocGenerationFlag)
			if !ok {
				t.Fatalf("%v cannot be documented", f.Names())
			}
			if d.GetUsage() == "" {
				t.Errorf("--%s has no usage text", f.Names()[0])
			}
			for _, n := range f.Names() {
				if _, dup := seen[n]; dup || (cmd != "" && global[n]) {
					t.Errorf("--%s of %q is defined twice; config-file keys would be ambiguous", n, cmd)
				}
				seen[n], all[n] = cmd, cmd
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
					prefix += strings.ToUpper(cmd) + "_"
				}
				if !strings.HasPrefix(e, prefix) {
					t.Errorf("--%s: env %s lacks prefix %s", f.Names()[0], e, prefix)
				}
			}
		}
	}
	for _, name := range []string{KeyStorePath, DataPath, HTTPListenPort, Logging, Network, SlashingProtectionEnabled, KeyManagerAPIEnabled} {
		if _, ok := all[name]; !ok {
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
