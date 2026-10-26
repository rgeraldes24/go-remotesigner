// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package flags

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/urfave/cli/v2"

	"github.com/rgeraldes24/go-remotesigner/internal/config"
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
	// A variable names one flag across the commands too: a global
	// --execution-x and execution's --x would both read
	// REMOTESIGNER_EXECUTION_X.
	seenEnv := map[string]bool{}
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
			// One variable per long name: a one-letter alias (-l) has none.
			if long := config.LongNames(f.Names()); len(env) != len(long) {
				t.Errorf("--%s: env %v for long names %v", f.Names()[0], env, long)
			}
			for _, e := range env {
				prefix := "REMOTESIGNER_"
				if cmd != "" {
					prefix += strings.ToUpper(cmd) + "_"
				}
				if !strings.HasPrefix(e, prefix) {
					t.Errorf("--%s: env %s lacks prefix %s", f.Names()[0], e, prefix)
				}
				if cmd != "" && strings.HasPrefix(e, prefix+strings.ToUpper(cmd)+"_") {
					t.Errorf("--%s: env %s repeats the command", f.Names()[0], e)
				}
				if seenEnv[e] {
					t.Errorf("--%s: env %s is another flag's too", f.Names()[0], e)
				}
				seenEnv[e] = true
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

// Every secret has a -file flag. A flag that takes a secret itself exists
// only where Web3Signer has it, and is listed in PlainSecrets with the
// -file flag that replaces it, which the signer's startup warning names.
func TestSecretsHaveFileFlags(t *testing.T) {
	secret := regexp.MustCompile(`(secret|password|token|access-key|credentials?)$`)
	byName := map[string]cli.Flag{}
	for _, fs := range [][]cli.Flag{Global(), Consensus(), Execution(), Migrate(), Import(), Export(), WatermarkRepair(),
		SetHighWatermark(), RandaoStateReset(), KeystoreVerify(), DisableValidatorFlags()} {
		for _, f := range fs {
			byName[f.Names()[0]] = f
		}
	}
	pairs := PlainSecrets()
	for name := range byName {
		if _, plain := pairs[name]; secret.MatchString(name) && !plain {
			t.Errorf("--%s takes a secret on the command line and has no -file flag", name)
		}
	}
	for plain, file := range pairs {
		p, f := byName[plain], byName[file]
		if p == nil || f == nil {
			t.Fatalf("--%s or --%s is not a flag", plain, file)
		}
		if file != plain+"-file" || !f.(*cli.StringFlag).TakesFile {
			t.Errorf("--%s is not the file flag of --%s", file, plain)
		}
		if usage := p.(*cli.StringFlag).Usage; !strings.HasPrefix(usage, "Deprecated: use --"+file+".") {
			t.Errorf("--%s: usage %q does not say it is deprecated", plain, usage)
		}
	}
}
