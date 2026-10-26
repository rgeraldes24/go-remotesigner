// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"cmp"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// jobStep is a workflow step with its condition, environment and shell.
type jobStep struct {
	workflowStep     `yaml:",inline"`
	ID               string `yaml:"id"`
	If               string `yaml:"if"`
	WorkingDirectory string `yaml:"working-directory"`
	Shell            string `yaml:"shell"`
}

// runDefaults is the defaults.run of a workflow or a job.
type runDefaults struct {
	Run struct {
		Shell string `yaml:"shell"`
	} `yaml:"run"`
}

// workflowJob is the part of a workflow job these tests read.
type workflowJob struct {
	RunsOn   string            `yaml:"runs-on"`
	Env      map[string]string `yaml:"env"`
	Defaults runDefaults       `yaml:"defaults"`
	Strategy struct {
		Matrix struct {
			Include []map[string]string `yaml:"include"`
		} `yaml:"matrix"`
	} `yaml:"strategy"`
	Steps []jobStep `yaml:"steps"`
}

// workflow is a workflow file's triggers, defaults and jobs.
type workflow struct {
	On struct {
		Schedule []struct {
			Cron string `yaml:"cron"`
		} `yaml:"schedule"`
		Dispatch *struct{} `yaml:"workflow_dispatch"`
	} `yaml:"on"`
	Defaults runDefaults            `yaml:"defaults"`
	Jobs     map[string]workflowJob `yaml:"jobs"`
}

// pipefail reports whether step s of job j runs with pipefail set, so that
// a pipeline fails when any of its commands does. GitHub runs a step with
// no shell as `bash -e {0}`, without pipefail; only `shell: bash` (the
// step's own, or the job's or the workflow's default) runs
// `bash --noprofile --norc -eo pipefail {0}`.
func (w workflow) pipefail(j workflowJob, s jobStep) bool {
	shell := cmp.Or(s.Shell, j.Defaults.Run.Shell, w.Defaults.Run.Shell)
	return shell == "bash" || setPipefail.MatchString(s.Run)
}

// setPipefail is a `set` line of a script that turns pipefail on.
var setPipefail = regexp.MustCompile(`(?m)^\s*set\s+(-\w*o\s+pipefail|-o\s+pipefail)`)

// quoted is a single- or double-quoted shell word, whose `|` is no pipe.
var quoted = regexp.MustCompile(`'[^']*'|"(?:[^"\\]|\\.)*"`)

// pipes reports whether script has a pipeline: a `|` outside quotes that
// is not part of `||` or a comment.
func pipes(script string) bool {
	for line := range strings.SplitSeq(script, "\n") {
		line = quoted.ReplaceAllString(line, "")
		if i := strings.Index(line, "#"); i >= 0 && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
			line = line[:i]
		}
		line = strings.ReplaceAll(line, "||", "")
		if strings.Contains(line, "|") {
			return true
		}
	}
	return false
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

// The nightly workflow fuzzes every target of `make fuzz` for 30 minutes:
// the keystore and interchange ones in jobs of their own, every other one
// (the request decoders, the hash-tree-root differential and the network
// parser) in the fuzz-decoders matrix.
func TestNightlyFuzzesEveryTargetOfMakeFuzz(t *testing.T) {
	w := readWorkflow(t, "nightly.yml")
	job, ok := w.Jobs["fuzz-decoders"]
	if !ok {
		t.Fatal("no fuzz-decoders job")
	}
	got := map[string]string{}
	for _, m := range job.Strategy.Matrix.Include {
		got[m["target"]] = m["package"]
	}
	if !job.runs("make fuzz-target") || !job.runs("FUZZTIME=30m") {
		t.Error("fuzz-decoders does not run make fuzz-target with FUZZTIME=30m")
	}
	makefile, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	recipe := makeRecipe(string(makefile), "fuzz")
	want := map[string]string{}
	for _, m := range fuzzLine.FindAllStringSubmatch(recipe, -1) {
		want[m[1]] = m[2]
	}
	for _, target := range []string{"FuzzDecodeSignRequest", "FuzzHashTreeRootDifferential",
		"FuzzDecodeRandaoRevealRequest", "FuzzParseConfig"} {
		if _, ok := want[target]; !ok {
			t.Errorf("make fuzz does not run %s", target)
		}
	}
	for target, pkg := range want {
		if got[target] != pkg {
			t.Errorf("fuzz-decoders runs %s in %q, want %q, as make fuzz does", target, got[target], pkg)
		}
	}
	for _, own := range []string{"fuzz-keystore", "fuzz-interchange"} {
		if !strings.Contains(firstLine(recipe), " "+own) {
			t.Errorf("make fuzz does not run make %s", own)
		}
		j, ok := w.Jobs[own]
		if !ok || !j.runs("make "+own+" FUZZTIME=30m") {
			t.Errorf("no nightly job runs make %s FUZZTIME=30m", own)
		}
	}
}

// fuzzLine is a `go test -fuzz` line of a make recipe: its target and package.
var fuzzLine = regexp.MustCompile(`-fuzz '\^(Fuzz\w+)\$\$' -fuzztime \$\(FUZZTIME\) (\./\S+/)`)

// makeRecipe returns target's rule in a Makefile: its line and its recipe.
func makeRecipe(makefile, target string) string {
	i := strings.Index(makefile, "\n"+target+":")
	if i < 0 {
		return ""
	}
	rule := makefile[i+1:]
	if end := strings.Index(rule, "\n\n"); end >= 0 {
		rule = rule[:end]
	}
	return rule
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

// The nightly lane job runs qrl-tests' consensus-remote-signer lane: it
// builds the consensus flavour's image from the commit under test with
// qrl-tests' script, the qrysm images from the qrysm ref a repository
// variable names, starts the devnet from the qrl-package ref another names
// and runs the lane from the qrl-tests ref a third names. It says so, and
// does nothing else, while any of the three is unset, and keeps the lane's
// reports and the devnet's service logs of a failed run.
func TestNightlyRemoteSignerLane(t *testing.T) {
	w := readWorkflow(t, "nightly.yml")
	if _, ok := w.Jobs["qrysm-e2e"]; ok {
		t.Error("nightly.yml still has the qrysm-e2e job, whose scenario is no longer the end-to-end test")
	}
	job, ok := w.Jobs["remote-signer-lane"]
	if !ok {
		t.Fatal("no remote-signer-lane job")
	}
	refs := map[string]string{"E2E_QRL_TESTS_REF": "qrl-tests", "E2E_QRL_PACKAGE_REF": "qrl-package",
		"E2E_QRYSM_REF": "qrysm"}
	for v := range refs {
		if job.Env[v] != "${{ vars."+v+" }}" {
			t.Errorf("%s is %q, want the repository variable with no default", v, job.Env[v])
		}
	}
	const configured = "steps.refs.outputs.run == 'true'"
	var notice, signer, signerImage, qrysmImages, network, lane, upload bool
	checkouts := map[string]string{} // path → ref
	signerPath := ""
	for i, s := range job.Steps {
		if i == 0 {
			notice = s.ID == "refs" && s.If == "" && strings.Contains(s.Run, "::notice") &&
				strings.Contains(s.Run, "run=false") && strings.Contains(s.Run, "run=true") &&
				!slices.ContainsFunc(slices.Collect(maps.Keys(refs)), func(v string) bool { return !strings.Contains(s.Run, v) })
			continue
		}
		if !strings.Contains(s.If, configured) {
			t.Errorf("step %q runs while the lane's refs are not configured", cmp.Or(s.Name, s.Uses))
		}
		if strings.HasPrefix(s.Uses, "actions/checkout@") {
			path, _ := s.With["path"].(string)
			repo, _ := s.With["repository"].(string)
			ref, _ := s.With["ref"].(string)
			if repo == "" && ref == "" {
				signer, signerPath = true, path
				continue
			}
			checkouts[path] = ref
		}
		switch {
		case strings.TrimSpace(s.Run) == "make remote-signer-image":
			signerImage = s.WorkingDirectory == "qrl-tests" && signerPath != "" &&
				strings.HasSuffix(s.Env["REMOTESIGNER_SOURCE_DIR"], "/"+signerPath)
		case strings.TrimSpace(s.Run) == "make qrysm-images":
			qrysmImages = s.WorkingDirectory == "qrl-tests" && strings.HasSuffix(s.Env["QRYSM_SOURCE_DIR"], "/qrysm")
		case strings.Contains(s.Run, "kurtosis run"):
			network = s.WorkingDirectory == "qrl-tests" && strings.Contains(s.Run, "--profile remote-signer") &&
				strings.Contains(s.Run, "../qrl-package")
		case strings.TrimSpace(s.Run) == "make e2e":
			lane = s.WorkingDirectory == "qrl-tests" && s.Env["E2E_LANE"] == "consensus-remote-signer" &&
				s.Env["E2E_SOURCE_REMOTESIGNER"] == "${{ github.sha }}"
		case strings.HasPrefix(s.Uses, "actions/upload-artifact@") && strings.Contains(s.If, "failure()"):
			path, _ := s.With["path"].(string)
			upload = strings.Contains(path, "qrl-tests/reports/") && strings.Contains(path, "e2e-out")
		}
	}
	for v, path := range refs {
		if want := "${{ env." + v + " }}"; checkouts[path] != want {
			t.Errorf("the %s checkout is at ref %q, want %q", path, checkouts[path], want)
		}
	}
	if !job.runs("kurtosis enclave dump") {
		t.Error("remote-signer-lane does not dump the devnet's service logs")
	}
	if !notice || !signer || !signerImage || !qrysmImages || !network || !lane || !upload {
		t.Errorf("remote-signer-lane: notice %v, signer checkout %v, signer image %v, qrysm images %v, network %v, "+
			"lane %v, failure artefacts %v", notice, signer, signerImage, qrysmImages, network, lane, upload)
	}
}

// No file still names the variable or the qrysm scenario of the end-to-end
// job the lane replaced, or says that qrysm's end-to-end test builds the
// signer, reads its metrics or fetches it in qrysm CI.
func TestNoQrysmScenarioJob(t *testing.T) {
	for _, f := range repoFiles(t) {
		if ownFile(f.path) {
			continue
		}
		for _, old := range []string{"QRYSM_E2E_REF", "QRYSM_E2E_REPO", "TestEndToEnd_MinimalConfig_Web3Signer",
			"`qrysm-e2e`", "qrysm's end-to-end test", "qrysm end-to-end test", "qrysm CI", "qrysm's e2e build"} {
			if strings.Contains(f.text, old) {
				t.Errorf("%s names %s, which the end-to-end job no longer uses", f.path, old)
			}
		}
	}
}

// CI checks both flavours against qrysm: vectorgen verify and the contract
// mode run against the consensus flavour, which qrl-tests'
// consensus-remote-signer lane builds, as well as against the default one.
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

// Every leg of CI's test matrix runs on a runner of its own architecture,
// so that the arm64 legs build, vet, run the race tests and fuzz on arm64,
// and no step is skipped on any leg.
func TestCITestLegsRunNatively(t *testing.T) {
	w := readWorkflow(t, "ci.yml")
	job, ok := w.Jobs["test"]
	if !ok {
		t.Fatal("ci.yml has no test job")
	}
	if job.RunsOn != "${{ matrix.runner }}" {
		t.Errorf("the test job runs on %q, want each leg's own runner", job.RunsOn)
	}
	runners := map[string]string{}
	for _, m := range job.Strategy.Matrix.Include {
		runners[m["arch"]] = m["runner"]
	}
	if want := map[string]string{"amd64": "ubuntu-24.04", "arm64": "ubuntu-24.04-arm"}; !maps.Equal(runners, want) {
		t.Errorf("the test legs run on %v, want %v", runners, want)
	}
	for _, s := range job.Steps {
		if s.If != "" {
			t.Errorf("step %q runs only if %s; every leg runs every step", cmp.Or(s.Name, s.Uses), s.If)
		}
	}
	for _, want := range []string{"make test", "make fuzz"} {
		if !job.runs(want) {
			t.Errorf("the test job does not run %s", want)
		}
	}
}

// The benchmarks are re-run every week, and on demand, by the Benchmarks
// workflow: every make target of a benchmark that fits a hosted runner. B19
// runs nightly instead, and B16 for at most a few hours (a hosted job stops
// at 6 h).
func TestBenchmarkWorkflow(t *testing.T) {
	w := readWorkflow(t, "bench.yml")
	if len(w.On.Schedule) != 1 || len(strings.Fields(w.On.Schedule[0].Cron)) != 5 ||
		strings.Fields(w.On.Schedule[0].Cron)[4] == "*" {
		t.Errorf("schedule %+v, want one weekly cron", w.On.Schedule)
	}
	if w.On.Dispatch == nil {
		t.Error("the Benchmarks workflow cannot be dispatched")
	}
	targets := map[string]bool{}
	for _, job := range w.Jobs {
		for _, s := range job.Steps {
			if rest, ok := strings.CutPrefix(strings.TrimSpace(s.Run), "make "); ok {
				targets[firstField(rest)] = true
			}
		}
	}
	for _, want := range []string{"bench-micro", "bench-e2e", "bench-loading", "bench-keymanager", "bench-b14",
		"bench-postgres", "b16"} {
		if !targets[want] {
			t.Errorf("no job of bench.yml runs make %s", want)
		}
	}
	// Each step keeps its output with tee, and fails when its benchmark
	// does, not with tee's status.
	for name, job := range w.Jobs {
		for _, s := range job.Steps {
			if strings.HasPrefix(strings.TrimSpace(s.Run), "make ") && (!pipes(s.Run) || !w.pipefail(job, s)) {
				t.Errorf("%s step %q: %q does not keep its output with tee under pipefail", name, s.Name, s.Run)
			}
		}
	}
}

// A step that pipes a command into another runs with pipefail, so that
// the step fails when the command does and not only when the last one of
// the pipeline does: `make bench-micro | tee out.txt` would otherwise pass
// whatever make's status.
func TestPipedStepsRunWithPipefail(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(root, ".github/workflows/*.yml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no workflows: %v", err)
	}
	for _, f := range files {
		name := filepath.Base(f)
		w := readWorkflow(t, name)
		for jobName, job := range w.Jobs {
			for _, s := range job.Steps {
				if pipes(s.Run) && !w.pipefail(job, s) {
					t.Errorf("%s: job %s, step %q pipes without pipefail; give it `shell: bash`", name, jobName,
						cmp.Or(s.Name, firstLine(s.Run)))
				}
			}
		}
	}
}

// pipes and pipefail tell a pipeline from a quoted `|` or `||`, and
// GitHub's default shell from `shell: bash`.
func TestPipesAndPipefail(t *testing.T) {
	for script, want := range map[string]bool{
		"make bench-micro 2>&1 | tee bench-micro.txt":                          true,
		`echo "$SUM  f" | sha256sum -c -`:                                      true,
		"if grep -nEi 'LGPL|Lesser General Public' NOTICE; then\n  exit 1\nfi": false,
		"test -f x || exit 1":                                                  false,
		`echo "a|b" # and | in a comment`:                                      false,
		"make test":                                                            false,
	} {
		if got := pipes(script); got != want {
			t.Errorf("pipes(%q) = %v, want %v", script, got, want)
		}
	}
	step := func(shell, run string) jobStep { return jobStep{workflowStep: workflowStep{Run: run}, Shell: shell} }
	var bashJob workflowJob
	bashJob.Defaults.Run.Shell = "bash"
	var bashWorkflow workflow
	bashWorkflow.Defaults.Run.Shell = "bash"
	for _, c := range []struct {
		w    workflow
		j    workflowJob
		s    jobStep
		want bool
	}{
		{workflow{}, workflowJob{}, step("", "make x | tee x.txt"), false},
		{workflow{}, workflowJob{}, step("sh", "make x | tee x.txt"), false},
		{workflow{}, workflowJob{}, step("bash", "make x | tee x.txt"), true},
		{workflow{}, bashJob, step("", "make x | tee x.txt"), true},
		{bashWorkflow, workflowJob{}, step("", "make x | tee x.txt"), true},
		{bashWorkflow, workflowJob{}, step("sh", "make x | tee x.txt"), false},
		{workflow{}, workflowJob{}, step("", "set -o pipefail\nmake x | tee x.txt"), true},
		{workflow{}, workflowJob{}, step("", "set -euo pipefail\nmake x | tee x.txt"), true},
	} {
		if got := c.w.pipefail(c.j, c.s); got != c.want {
			t.Errorf("pipefail(workflow %q, job %q, step %q, %q) = %v, want %v", c.w.Defaults.Run.Shell,
				c.j.Defaults.Run.Shell, c.s.Shell, c.s.Run, got, c.want)
		}
	}
}

// CI's compliance job runs govulncheck with the Go the release builds
// with, go.mod's toolchain line, as the release workflow does.
func TestComplianceUsesTheReleaseToolchain(t *testing.T) {
	job, ok := readWorkflow(t, "ci.yml").Jobs["compliance"]
	if !ok {
		t.Fatal("ci.yml has no compliance job")
	}
	steps := make([]workflowStep, len(job.Steps))
	for i, s := range job.Steps {
		steps[i] = s.workflowStep
	}
	for _, p := range setupGoProblems(steps) {
		t.Errorf("compliance: %s", p)
	}
	if !job.runs("make vuln") {
		t.Error("the compliance job does not run make vuln")
	}
}
