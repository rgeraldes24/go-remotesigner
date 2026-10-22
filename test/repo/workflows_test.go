// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// jobStep is a workflow step with its condition and environment.
type jobStep struct {
	workflowStep `yaml:",inline"`
	If           string            `yaml:"if"`
	Env          map[string]string `yaml:"env"`
}

// workflowJob is the part of a workflow job these tests read.
type workflowJob struct {
	Env      map[string]string `yaml:"env"`
	Strategy struct {
		Matrix struct {
			Include []map[string]string `yaml:"include"`
		} `yaml:"matrix"`
	} `yaml:"strategy"`
	Steps []jobStep `yaml:"steps"`
}

// workflow is a workflow file's triggers and jobs.
type workflow struct {
	On struct {
		Schedule []struct {
			Cron string `yaml:"cron"`
		} `yaml:"schedule"`
		Dispatch *struct{} `yaml:"workflow_dispatch"`
	} `yaml:"on"`
	Jobs map[string]workflowJob `yaml:"jobs"`
}

func readWorkflow(t *testing.T, name string) workflow {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, ".github/workflows", name))
	if err != nil {
		t.Fatal(err)
	}
	var w workflow
	if err := yaml.Unmarshal(data, &w); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return w
}

// runs reports whether a step of job runs a command containing want.
func (j workflowJob) runs(want string) bool {
	return slices.ContainsFunc(j.Steps, func(s jobStep) bool { return strings.Contains(s.Run, want) })
}

// The nightly workflow fuzzes the request decoders, the hash-tree-root
// differential and the network parser for 30 minutes each, every target of
// `make fuzz` but the keystore and interchange ones, which have jobs of their
// own.
func TestNightlyFuzzesTheDecodersAndTheNetworkParser(t *testing.T) {
	w := readWorkflow(t, "nightly.yml")
	job, ok := w.Jobs["fuzz-decoders"]
	if !ok {
		t.Fatal("no fuzz-decoders job")
	}
	got := map[string]string{}
	for _, m := range job.Strategy.Matrix.Include {
		got[m["target"]] = m["package"]
	}
	want := map[string]string{
		"FuzzDecodeSignRequest":         "./internal/consensus/types/",
		"FuzzHashTreeRootDifferential":  "./internal/consensus/types/",
		"FuzzDecodeRandaoRevealRequest": "./internal/consensus/types/",
		"FuzzParseConfig":               "./internal/network/",
	}
	for target, pkg := range want {
		if got[target] != pkg {
			t.Errorf("fuzz-decoders runs %s in %q, want %q", target, got[target], pkg)
		}
	}
	if !job.runs("make fuzz-target") || !job.runs("FUZZTIME=30m") {
		t.Error("fuzz-decoders does not run make fuzz-target with FUZZTIME=30m")
	}
	makefile, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	for target, pkg := range want {
		if !strings.Contains(string(makefile), "-fuzz '^"+target+"$$' -fuzztime $(FUZZTIME) "+pkg) {
			t.Errorf("make fuzz does not run %s on %s", target, pkg)
		}
	}
}

// The nightly qrysm end-to-end job runs qrysm's remote-signer scenario
// against the consensus flavour built from the commit under test, from the
// qrysm ref a repository variable names, says so when the variable is unset,
// and keeps the signer's and the validator clients' logs and a metrics scrape
// of a failed run.
func TestNightlyQrysmEndToEnd(t *testing.T) {
	w := readWorkflow(t, "nightly.yml")
	job, ok := w.Jobs["qrysm-e2e"]
	if !ok {
		t.Fatal("no qrysm-e2e job")
	}
	if !strings.Contains(job.Env["QRYSM_E2E_REF"], "vars.QRYSM_E2E_REF") {
		t.Errorf("QRYSM_E2E_REF is %q, want the repository variable", job.Env["QRYSM_E2E_REF"])
	}
	var notice, build, run, upload bool
	for _, s := range job.Steps {
		switch {
		case s.If == "env.QRYSM_E2E_REF == ''" && strings.Contains(s.Run, "::notice"):
			notice = true
		case s.If == "env.QRYSM_E2E_REF == ''":
			t.Errorf("step %q runs only without a qrysm ref", s.Name)
		case !strings.Contains(s.If, "env.QRYSM_E2E_REF != ''"):
			t.Errorf("step %q runs without a qrysm ref", s.Name)
		}
		build = build || strings.Contains(s.Run, "make build-consensus")
		run = run || strings.Contains(s.Run, "go run ./build/e2e web3signer")
		if strings.HasPrefix(s.Uses, "actions/upload-artifact@") && strings.Contains(s.If, "failure()") {
			path, _ := s.With["path"].(string)
			upload = strings.Contains(path, "signer-metrics.txt") && strings.Contains(path, "*.log")
		}
	}
	if !notice || !build || !run || !upload {
		t.Errorf("qrysm-e2e: notice %v, consensus build %v, scenario run %v, failure artefacts %v", notice, build, run,
			upload)
	}
}

// CI checks both flavours against qrysm: vectorgen verify and the contract
// mode run against the consensus flavour, which qrysm's end-to-end test
// builds, as well as against the default one.
func TestCIVerifiesBothFlavours(t *testing.T) {
	w := readWorkflow(t, "ci.yml")
	for name, target := range map[string]string{"vectors-verify": "make vectors-verify-binary",
		"vectors-contract": "make vectors-contract"} {
		job, ok := w.Jobs[name]
		if !ok {
			t.Errorf("ci.yml has no job %s", name)
			continue
		}
		if !job.runs("build-consensus") {
			t.Errorf("%s does not build the consensus flavour", name)
		}
		seen := map[string]bool{}
		for _, s := range job.Steps {
			if strings.Contains(s.Run, target) {
				seen[s.Env["REMOTESIGNER_BINARY"]] = true
			}
		}
		for _, bin := range []string{"/bin/remotesigner", "/bin/remotesigner-consensus"} {
			if !slices.ContainsFunc(slices.Collect(maps.Keys(seen)), func(b string) bool { return strings.HasSuffix(b, bin) }) {
				t.Errorf("%s does not run %s against %s", name, target, bin)
			}
		}
	}
}
