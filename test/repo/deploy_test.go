// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// plaintextOverride matches the plaintext-token override in any spelling:
// the flag (--Xallow-plaintext-token-auth), its environment variable
// (REMOTESIGNER_XALLOW_PLAINTEXT_TOKEN_AUTH) and its config-file key.
var plaintextOverride = regexp.MustCompile(`(?i)allow[-_]plaintext[-_]token[-_]auth`)

// TestDeployNeverAllowsPlaintextTokens fails if the image's Dockerfile and
// entrypoint, or any other file under deploy/ (the compose example, the
// systemd unit, the example configs), sets the plaintext-token override: the
// shipped image and examples serve tokens over TLS only.
func TestDeployNeverAllowsPlaintextTokens(t *testing.T) {
	n := 0
	for _, f := range repoFiles(t) {
		if !strings.HasPrefix(f.path, "deploy/") {
			continue
		}
		n++
		for i, line := range strings.Split(f.text, "\n") {
			if plaintextOverride.MatchString(line) {
				t.Errorf("%s:%d: %q sets the plaintext-token override", f.path, i+1, strings.TrimSpace(line))
			}
		}
	}
	if n == 0 {
		t.Fatal("no files under deploy/")
	}
}

// dockerfile is the parsed part of deploy/docker/Dockerfile the tests read.
type dockerfile struct {
	from       []string          // every FROM image reference
	user       string            // the last USER
	entrypoint []string          // the last ENTRYPOINT (exec form)
	cmd        []string          // the last CMD (exec form)
	labels     map[string]string // every LABEL key="value" pair
}

// labelPair is one key="value" pair of a LABEL instruction.
var labelPair = regexp.MustCompile(`([A-Za-z0-9._-]+)="([^"]*)"`)

func parseDockerfile(t *testing.T, text string) dockerfile {
	t.Helper()
	d := dockerfile{labels: map[string]string{}}
	// Join continuation lines.
	text = strings.ReplaceAll(text, "\\\n", " ")
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), f[0]))
		switch strings.ToUpper(f[0]) {
		case "FROM":
			d.from = append(d.from, f[1])
		case "USER":
			d.user = f[1]
		case "ENTRYPOINT":
			d.entrypoint = execForm(t, rest)
		case "CMD":
			d.cmd = execForm(t, rest)
		case "LABEL":
			for _, m := range labelPair.FindAllStringSubmatch(rest, -1) {
				d.labels[m[1]] = m[2]
			}
		}
	}
	return d
}

// execForm parses the JSON exec form of ENTRYPOINT or CMD.
func execForm(t *testing.T, s string) []string {
	t.Helper()
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		t.Fatalf("%q: want the exec form (a JSON array): %v", s, err)
	}
	return out
}

var (
	// pinnedImage is an image reference pinned by digest.
	pinnedImage = regexp.MustCompile(`^[a-z0-9./-]+(?::[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$`)
	// stageName is a reference to an earlier build stage.
	stageName = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
)

// The image is distroless static, pinned by digest, runs as the nonroot
// user, and its entrypoint binds every interface with a generated TLS
// certificate and tokens in /data while leaving --network and
// --http-host-allowlist to the operator.
func TestDockerfile(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(root, "deploy/docker/Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	d := parseDockerfile(t, string(data))
	if len(d.from) == 0 || !strings.HasPrefix(d.from[0], "gcr.io/distroless/static") ||
		!strings.Contains(d.from[0], ":nonroot@") {
		t.Errorf("base image %q, want distroless static:nonroot", d.from)
	}
	for _, ref := range d.from {
		if !pinnedImage.MatchString(ref) && !stageName.MatchString(ref) {
			t.Errorf("FROM %s: not pinned by digest", ref)
		}
	}
	if d.user != "65532:65532" {
		t.Errorf("USER %q, want 65532:65532 (distroless nonroot)", d.user)
	}
	want := []string{"/usr/local/bin/remotesigner", "--data-path=/data", "--http-listen-host=0.0.0.0",
		"--tls-generate-self-signed"}
	if !slices.Equal(d.entrypoint, want) {
		t.Errorf("ENTRYPOINT %q, want %q", d.entrypoint, want)
	}
	for _, arg := range slices.Concat(d.entrypoint, d.cmd) {
		for _, operator := range []string{"--network", "--http-host-allowlist", "--Xallow"} {
			if strings.HasPrefix(arg, operator) {
				t.Errorf("the image sets %s, which the operator must choose", arg)
			}
		}
	}
	if !slices.Equal(d.cmd, []string{"consensus"}) {
		t.Errorf("CMD %q, want [consensus]", d.cmd)
	}
	for _, p := range basePinProblems(d, string(data)) {
		t.Error(p)
	}
}

// basePinProblems returns what is wrong with the base-image pin of a
// Dockerfile: Renovate's docker:pinDigests rewrites the digest in FROM lines
// only, so any other copy of it (a base.digest label, say) would name a base
// the image is no longer built from after the first update; and the
// base.name label, when set, must name the base FROM pins.
func basePinProblems(d dockerfile, text string) []string {
	var p []string
	for _, ref := range d.from {
		name, digest, ok := strings.Cut(ref, "@")
		if !ok {
			continue
		}
		if n := strings.Count(text, strings.TrimPrefix(digest, "sha256:")); n != 1 {
			p = append(p, fmt.Sprintf("the base digest %s appears %d times; keep it in the FROM line only", digest, n))
		}
		if got, ok := d.labels["org.opencontainers.image.base.name"]; ok && ref == d.from[0] && got != name {
			p = append(p, fmt.Sprintf("label org.opencontainers.image.base.name = %q, want %q (the FROM image)", got, name))
		}
	}
	return p
}

func TestBasePinProblems(t *testing.T) {
	digest := "sha256:" + strings.Repeat("ab", 32)
	from := "FROM gcr.io/distroless/static-debian13:nonroot@" + digest + " AS base\nFROM base\n"
	tests := []struct {
		name, text string
		want       string // a substring of the one problem; "" for none
	}{
		{"pinned once", from + `LABEL org.opencontainers.image.base.name="gcr.io/distroless/static-debian13:nonroot"` + "\n", ""},
		{"no base label", from, ""},
		{"a digest label", from + `LABEL org.opencontainers.image.base.digest="` + digest + `"` + "\n", "appears 2 times"},
		{"a digest in a comment", "# base " + digest + "\n" + from, "appears 2 times"},
		{"another base name", from + `LABEL org.opencontainers.image.base.name="gcr.io/distroless/static-debian12:nonroot"` + "\n",
			"base.name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := basePinProblems(parseDockerfile(t, tt.text), tt.text)
			switch {
			case tt.want == "" && len(got) != 0:
				t.Errorf("problems %q, want none", got)
			case tt.want != "" && (len(got) != 1 || !strings.Contains(got[0], tt.want)):
				t.Errorf("problems %q, want one mentioning %q", got, tt.want)
			}
		})
	}
}

// The compose example runs the image hardened, reachable only on an
// internal network, and points the validator client at it by service name
// over TLS with the signer's certificate and sign token.
func TestComposeExample(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(root, "deploy/docker/compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Services map[string]struct {
			Command     []string `yaml:"command"`
			ReadOnly    bool     `yaml:"read_only"`
			CapDrop     []string `yaml:"cap_drop"`
			SecurityOpt []string `yaml:"security_opt"`
			Ports       []any    `yaml:"ports"`
			Volumes     []string `yaml:"volumes"`
			Networks    []string `yaml:"networks"`
			User        string   `yaml:"user"`
		} `yaml:"services"`
		Networks map[string]struct {
			Internal bool `yaml:"internal"`
		} `yaml:"networks"`
	}
	if err := yaml.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	s, ok := c.Services["signer"]
	if !ok {
		t.Fatal("no signer service")
	}
	if !s.ReadOnly || !slices.Equal(s.CapDrop, []string{"ALL"}) || !slices.Contains(s.SecurityOpt, "no-new-privileges:true") {
		t.Errorf("signer: read_only %v, cap_drop %q, security_opt %q", s.ReadOnly, s.CapDrop, s.SecurityOpt)
	}
	if s.User != "" {
		t.Errorf("signer: user %q overrides the image's nonroot user", s.User)
	}
	if len(s.Ports) != 0 {
		t.Errorf("signer: publishes ports %v; only the validator client reaches it", s.Ports)
	}
	if !slices.Contains(s.Command, "--http-host-allowlist=signer") || !slices.Contains(s.Command, "consensus") {
		t.Errorf("signer: command %q lacks --http-host-allowlist=signer or consensus", s.Command)
	}
	if !slices.Contains(s.Volumes, "signer-data:/data") {
		t.Errorf("signer: volumes %q, want a named volume at /data", s.Volumes)
	}
	for _, n := range s.Networks {
		if !c.Networks[n].Internal {
			t.Errorf("signer: network %s is not internal", n)
		}
	}
	v, ok := c.Services["validator"]
	if !ok {
		t.Fatal("no validator service")
	}
	for _, want := range []string{"--validators-external-signer-url=https://signer:9000",
		"--validators-external-signer-tls-ca-file=", "--validators-external-signer-auth-token-file="} {
		if !slices.ContainsFunc(v.Command, func(a string) bool { return strings.HasPrefix(a, want) }) {
			t.Errorf("validator: command %q lacks %s", v.Command, want)
		}
	}
	if slices.ContainsFunc(v.Volumes, func(m string) bool { return strings.HasPrefix(m, "signer-data:") }) {
		t.Error("validator: mounts the signer's data volume, which holds the admin token and the TLS key")
	}
}

// The systemd unit runs the signer as its own unprivileged user with a
// private state directory, the config file and the hardening the
// deployment guide describes.
func TestSystemdUnit(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(root, "deploy/systemd/remotesigner.service"))
	if err != nil {
		t.Fatal(err)
	}
	set := map[string][]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if k, v, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(line, "#") {
			set[k] = append(set[k], v)
		}
	}
	for k, want := range map[string]string{
		"User":                     "remotesigner",
		"ExecStart":                "/usr/local/bin/remotesigner --config-file=/etc/remotesigner/remotesigner.yaml consensus",
		"StateDirectory":           "remotesigner",
		"StateDirectoryMode":       "0700",
		"UMask":                    "0077",
		"NoNewPrivileges":          "yes",
		"CapabilityBoundingSet":    "",
		"ProtectSystem":            "strict",
		"KillSignal":               "SIGTERM",
		"RestartPreventExitStatus": "2",
	} {
		if !slices.Contains(set[k], want) {
			t.Errorf("%s=%q, want %q", k, set[k], want)
		}
	}
}

// digestPin finds an image reference pinned by digest.
var digestPin = regexp.MustCompile(`[a-z0-9][a-z0-9./-]*(?::[A-Za-z0-9._-]+)?@(sha256:[0-9a-f]{64})`)

// renovateManager is a regex custom manager of renovate.json, compiled.
type renovateManager struct {
	files   []*regexp.Regexp
	matches []*regexp.Regexp
}

// renovateConfig returns renovate.json's ignorePaths and its regex custom
// managers. Renovate's patterns are JavaScript regular expressions; the ones
// this repository uses are also valid RE2.
func renovateConfig(t *testing.T) (ignore []string, managers []renovateManager) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "renovate.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		IgnorePaths    []string `json:"ignorePaths"`
		CustomManagers []struct {
			CustomType          string   `json:"customType"`
			ManagerFilePatterns []string `json:"managerFilePatterns"`
			MatchStrings        []string `json:"matchStrings"`
		} `json:"customManagers"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("renovate.json: %v", err)
	}
	for _, m := range cfg.CustomManagers {
		if m.CustomType != "regex" {
			continue
		}
		var rm renovateManager
		for _, p := range m.ManagerFilePatterns {
			body, slash := strings.CutPrefix(p, "/")
			body, ok := strings.CutSuffix(body, "/")
			if !slash || !ok {
				t.Fatalf("renovate.json: managerFilePatterns %q is not a /regex/", p)
			}
			rm.files = append(rm.files, regexp.MustCompile(body))
		}
		for _, s := range m.MatchStrings {
			rm.matches = append(rm.matches, regexp.MustCompile(s))
		}
		managers = append(managers, rm)
	}
	return cfg.IgnorePaths, managers
}

// unmanagedPins returns the digest pins in the file at path that no
// Renovate manager updates: a Dockerfile's FROM, COPY --from and RUN
// --mount lines are Renovate's dockerfile manager's, and a workflow's image
// lines (a job's container and services) its github-actions manager's; any
// other pin needs a regex custom manager whose file pattern matches path and
// whose match string captures the digest as currentDigest.
func unmanagedPins(path, text string, managers []renovateManager) []string {
	managed := map[string]bool{}
	for _, m := range managers {
		if !slices.ContainsFunc(m.files, func(re *regexp.Regexp) bool { return re.MatchString(path) }) {
			continue
		}
		for _, re := range m.matches {
			i := re.SubexpIndex("currentDigest")
			for _, sm := range re.FindAllStringSubmatch(text, -1) {
				if i >= 0 {
					managed[sm[i]] = true
				}
			}
		}
	}
	dockerfile := strings.HasPrefix(filepath.Base(path), "Dockerfile")
	workflow := strings.HasPrefix(path, ".github/workflows/")
	var out []string
	for i, line := range strings.Split(text, "\n") {
		for _, sm := range digestPin.FindAllStringSubmatch(line, -1) {
			if dockerfile && slices.Contains([]string{"FROM", "COPY", "RUN"}, strings.ToUpper(firstField(line))) ||
				workflow && firstField(line) == "image:" || managed[sm[1]] {
				continue
			}
			out = append(out, fmt.Sprintf("%s:%d: %s", path, i+1, sm[0]))
		}
	}
	return out
}

func firstField(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return ""
}

// TestImagePinsFollowRenovate fails for an image pinned by digest that no
// Renovate manager moves, such as a Go constant without its
// '// renovate: datasource=docker' marker: that pin would never be updated.
func TestImagePinsFollowRenovate(t *testing.T) {
	ignore, managers := renovateConfig(t)
	n := 0
	for _, f := range repoFiles(t) {
		if slices.ContainsFunc(ignore, func(g string) bool {
			return strings.HasPrefix(f.path, strings.TrimSuffix(g, "**"))
		}) {
			continue
		}
		pins := len(digestPin.FindAllString(f.text, -1))
		n += pins
		if pins == 0 {
			continue
		}
		for _, p := range unmanagedPins(f.path, f.text, managers) {
			t.Errorf("%s: pinned by digest, but no Renovate manager updates it (renovate.json)", p)
		}
	}
	if n < 2 {
		t.Errorf("found %d image pins, want at least the Dockerfile's base and the systemd smoke test's", n)
	}
}

func TestUnmanagedPins(t *testing.T) {
	_, managers := renovateConfig(t)
	ref := `ubuntu:24.04@sha256:` + strings.Repeat("cd", 32)
	tests := []struct {
		name, path, text string
		want             int
	}{
		{"Dockerfile FROM", "deploy/docker/Dockerfile", "FROM " + ref + " AS base\n", 0},
		{"Dockerfile COPY --from", "deploy/docker/Dockerfile", "COPY --from=" + ref + " /a /b\n", 0},
		{"Dockerfile label", "deploy/docker/Dockerfile", `LABEL org.example.base="` + ref + `"` + "\n", 1},
		{"Go constant with the marker", "test/release/x_test.go", "// renovate: datasource=docker\nconst base = \"" + ref + "\"\n", 0},
		{"Go constant without it", "test/release/x_test.go", "const base = \"" + ref + "\"\n", 1},
		{"marker outside test/", "internal/x/x.go", "// renovate: datasource=docker\nconst base = \"" + ref + "\"\n", 1},
		{"workflow service image", ".github/workflows/ci.yml", "    services:\n      db:\n        image: " + ref + "\n", 0},
		{"workflow env pin", ".github/workflows/ci.yml", "env:\n  BASE: " + ref + "\n", 1},
		{"Makefile variable with the marker", "Makefile", "# renovate: datasource=docker\nIMAGE ?= " + ref + "\n", 0},
		{"Makefile variable without it", "Makefile", "IMAGE ?= " + ref + "\n", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unmanagedPins(tt.path, tt.text, managers); len(got) != tt.want {
				t.Errorf("unmanaged %q, want %d", got, tt.want)
			}
		})
	}
}

// workflowStep is one step of a GitHub Actions job.
type workflowStep struct {
	Name string         `yaml:"name"`
	Uses string         `yaml:"uses"`
	Run  string         `yaml:"run"`
	With map[string]any `yaml:"with"`
}

// releaseWorkflowProblems returns what is wrong with the release job's
// steps: before the step that publishes (goreleaser release without
// --snapshot), it must check that the tagged commit is on main, with a
// checkout that fetched main, run the compliance gates and write the release
// notes from CHANGELOG.md, which the publishing step passes to goreleaser;
// and setup-go must not restore a cache an earlier run saved.
func releaseWorkflowProblems(steps []workflowStep) []string {
	publish := slices.IndexFunc(steps, func(s workflowStep) bool {
		return strings.Contains(s.Run, "goreleaser release") && !strings.Contains(s.Run, "--snapshot")
	})
	if publish < 0 {
		return []string{"no step runs goreleaser release"}
	}
	before := steps[:publish]
	var p []string
	checkout := slices.IndexFunc(before, func(s workflowStep) bool { return strings.HasPrefix(s.Uses, "actions/checkout@") })
	if checkout < 0 || fmt.Sprint(before[checkout].With["fetch-depth"]) != "0" {
		p = append(p, "the checkout does not fetch every branch (fetch-depth: 0), so origin/main is missing")
	}
	if !slices.ContainsFunc(before, func(s workflowStep) bool {
		return strings.Contains(s.Run, "git merge-base --is-ancestor") && strings.Contains(s.Run, "origin/main")
	}) {
		p = append(p, "no step before publishing checks that the tagged commit is on main")
	}
	var commands []string // the make targets and the other command lines run before publishing
	for _, s := range before {
		for _, line := range strings.Split(s.Run, "\n") {
			line = strings.TrimSpace(line)
			if rest, ok := strings.CutPrefix(line, "make "); ok {
				for _, f := range strings.Fields(rest) {
					if !strings.Contains(f, "=") {
						commands = append(commands, "make "+f)
					}
				}
				continue
			}
			commands = append(commands, line)
		}
	}
	for _, gate := range []string{"make license-hash", "make headercheck", "make nogpl", "make licenses",
		"go vet ./...", "go vet -tags noexecution ./...", "make release-check"} {
		if !slices.Contains(commands, gate) {
			p = append(p, "no step before publishing runs "+gate)
		}
	}
	for _, s := range steps {
		if strings.HasPrefix(s.Uses, "actions/setup-go@") && fmt.Sprint(s.With["cache"]) != "false" {
			p = append(p, "setup-go restores a cache (want cache: false): the release would be built from it")
		}
	}
	if !slices.ContainsFunc(before, func(s workflowStep) bool { return strings.Contains(s.Run, "tools/releasedocs -notes") }) {
		p = append(p, "no step before publishing writes the release notes from the tag's CHANGELOG.md entry (tools/releasedocs -notes)")
	}
	if !strings.Contains(steps[publish].Run, "--release-notes") {
		p = append(p, "goreleaser release runs without --release-notes, so the release page lists the git log instead of the CHANGELOG.md entry")
	}
	return p
}

// The release workflow publishes only for a tag on main, after the
// compliance gates and the dry run, built from a cold cache.
func TestReleaseWorkflow(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(root, ".github/workflows/release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var w struct {
		On struct {
			Push struct {
				Tags     []string `yaml:"tags"`
				Branches []string `yaml:"branches"`
			} `yaml:"push"`
		} `yaml:"on"`
		Jobs map[string]struct {
			Steps []workflowStep `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &w); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(w.On.Push.Tags, []string{"v*"}) || len(w.On.Push.Branches) != 0 {
		t.Errorf("on.push: tags %q branches %q, want version tags only", w.On.Push.Tags, w.On.Push.Branches)
	}
	job, ok := w.Jobs["release"]
	if !ok {
		t.Fatal("no release job")
	}
	for _, p := range releaseWorkflowProblems(job.Steps) {
		t.Error(p)
	}
}

func TestReleaseWorkflowProblems(t *testing.T) {
	good := []workflowStep{
		{Uses: "actions/checkout@abc", With: map[string]any{"fetch-depth": 0}},
		{Run: `git merge-base --is-ancestor HEAD refs/remotes/origin/main`},
		{Uses: "actions/setup-go@abc", With: map[string]any{"cache": false}},
		{Run: `go install "github.com/google/go-licenses/v2@${GO_LICENSES_VERSION}"`},
		{Run: "make license-hash headercheck nogpl licenses GO_LICENSES=x\ngo vet ./...\ngo vet -tags noexecution ./...\n"},
		{Run: `go run ./tools/releasedocs -notes "${GITHUB_REF_NAME}" > notes.md`},
		{Run: "make release-snapshot GORELEASER=goreleaser\nmake release-check\n"},
		{Name: "Publish", Run: "goreleaser release --clean --release-notes notes.md"},
	}
	with := func(edit func([]workflowStep) []workflowStep) []workflowStep {
		steps := slices.Clone(good)
		for i := range steps {
			steps[i].With = maps.Clone(steps[i].With)
		}
		return edit(steps)
	}
	tests := []struct {
		name  string
		steps []workflowStep
		want  []string // a substring of each problem
	}{
		{"good", good, nil},
		{"no main check", with(func(s []workflowStep) []workflowStep { return slices.Delete(s, 1, 2) }), []string{"on main"}},
		{"main check after publishing", with(func(s []workflowStep) []workflowStep {
			return append(slices.Delete(s, 1, 2), workflowStep{Run: "git merge-base --is-ancestor HEAD origin/main"})
		}), []string{"on main"}},
		{"shallow checkout", with(func(s []workflowStep) []workflowStep { delete(s[0].With, "fetch-depth"); return s }),
			[]string{"fetch-depth"}},
		{"setup-go cache", with(func(s []workflowStep) []workflowStep { delete(s[2].With, "cache"); return s }),
			[]string{"cache: false"}},
		{"no make gates", with(func(s []workflowStep) []workflowStep {
			s[4].Run = "go vet ./...\ngo vet -tags noexecution ./...\n"
			return s
		}), []string{"make license-hash", "make headercheck", "make nogpl", "make licenses"}},
		{"no dry run checks", with(func(s []workflowStep) []workflowStep { return slices.Delete(s, 6, 7) }),
			[]string{"make release-check"}},
		{"no release notes", with(func(s []workflowStep) []workflowStep { return slices.Delete(s, 5, 6) }),
			[]string{"CHANGELOG.md entry (tools/releasedocs -notes)"}},
		{"notes not passed", with(func(s []workflowStep) []workflowStep { s[7].Run = "goreleaser release --clean"; return s }),
			[]string{"--release-notes"}},
		{"no publish step", good[:7], []string{"goreleaser release"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := releaseWorkflowProblems(tt.steps)
			ok := len(got) == len(tt.want)
			for _, w := range tt.want {
				ok = ok && slices.ContainsFunc(got, func(p string) bool { return strings.Contains(p, w) })
			}
			if !ok {
				t.Errorf("problems %q, want one mentioning each of %q", got, tt.want)
			}
		})
	}
}

// make build reports the version a release of the same tag reports
// (docs/operations/release.md section 4): git describe's output without
// the tag's "v", as goreleaser's {{ .Version }} drops it, so that a build of
// a checkout of v1.0.0 prints 1.0.0. make -n prints the build commands
// without running them.
func TestMakeBuildVersion(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("make is not installed")
	}
	const commit = "0123456789abcdef0123456789abcdef01234567"
	for _, tt := range []struct{ describe, want string }{
		{"v1.0.0", "1.0.0"},
		{"v1.1.0-rc.1", "1.1.0-rc.1"},
		{"v1.0.0-3-g0123456-dirty", "1.0.0-3-g0123456-dirty"},
		{"0123456", "0123456"}, // no tag yet: the short commit
	} {
		for _, target := range []string{"build", "build-consensus"} {
			cmd := exec.Command("make", "-n", "-C", root, target, "GIT_DESCRIBE="+tt.describe, "COMMIT="+commit)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("make -n %s: %v: %s", target, err, out)
			}
			want := fmt.Sprintf("-X main.version=%s -X main.commit=%s", tt.want, commit)
			if !strings.Contains(string(out), want) {
				t.Errorf("make %s for git describe %s: no %q in\n%s", target, tt.describe, want, out)
			}
		}
	}
}

// make release-version builds for the tag of the newest version that
// CHANGELOG.md has an entry for, unless RELEASE_TAG names another tag
// (docs/operations/release.md section 4), so that its default follows the
// release being prepared.
func TestReleaseTagDefault(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("make is not installed")
	}
	data, err := os.ReadFile(filepath.Join(root, "CHANGELOG.md"))
	if err != nil {
		t.Fatal(err)
	}
	newest := regexp.MustCompile(`(?m)^## \[(\d+\.\d+\.\d+)\] - `).FindSubmatch(data)
	if newest == nil {
		t.Fatal("CHANGELOG.md has no version entry")
	}
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "RELEASE_TAG=") {
			env = append(env, kv)
		}
	}
	for _, tt := range []struct {
		args []string
		want string
	}{
		{nil, "v" + string(newest[1])},
		{[]string{"RELEASE_TAG=v9.8.7-rc.1"}, "v9.8.7-rc.1"},
	} {
		args := append([]string{"-n", "-C", root, "release-version", "GO_LICENSES=go-licenses"}, tt.args...)
		cmd := exec.Command("make", args...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("make %q: %v: %s", args, err, out)
		}
		if want := "GORELEASER_CURRENT_TAG=" + tt.want + " "; !strings.Contains(string(out), want) {
			t.Errorf("make %q: no %q in\n%s", args, want, out)
		}
	}
}

// releaseURL is the GitHub release of a version, where its source archive
// is attached, as NOTICE.execution writes it.
const releaseURL = "https://github.com/rgeraldes24/go-remotesigner/releases/tag/v<version>"

// releaseConfig is the part of .goreleaser.yaml that attaches the source
// archive to a release.
type releaseConfig struct {
	Before struct {
		Hooks []string `yaml:"hooks"`
	} `yaml:"before"`
	Checksum struct {
		ExtraFiles []extraFile `yaml:"extra_files"`
	} `yaml:"checksum"`
	Release struct {
		ExtraFiles []extraFile `yaml:"extra_files"`
	} `yaml:"release"`
}

type extraFile struct {
	Glob string `yaml:"glob"`
}

// releaseSourceProblems checks that a release built with cfg attaches the
// source archive that `make release-src` writes to src (for one version),
// with its checksum, and that the default flavour's NOTICE, which ends with
// NOTICE.execution (notice), tells where that archive is: its file name and
// the URL of the GitHub release that attaches it.
func releaseSourceProblems(cfg releaseConfig, src, notice string) []string {
	var p []string
	docs := slices.IndexFunc(cfg.Before.Hooks, func(h string) bool { return strings.HasPrefix(h, "make release-docs ") })
	srcHook := slices.IndexFunc(cfg.Before.Hooks, func(h string) bool {
		return strings.HasPrefix(h, "make release-src ") && strings.Contains(h, "VERSION={{ .Version }}")
	})
	switch {
	case srcHook < 0:
		p = append(p, "no before hook runs make release-src VERSION={{ .Version }}")
	case srcHook < docs:
		p = append(p, "make release-src runs before make release-docs, which empties the directory it writes to")
	}
	takes := func(files []extraFile) bool {
		return slices.ContainsFunc(files, func(f extraFile) bool {
			ok, err := filepath.Match(f.Glob, src)
			return err == nil && ok
		})
	}
	if !takes(cfg.Release.ExtraFiles) {
		p = append(p, "release.extra_files does not attach "+src)
	}
	if !takes(cfg.Checksum.ExtraFiles) {
		p = append(p, "checksum.extra_files does not cover "+src)
	}
	var words []string
	for _, w := range strings.Fields(notice) {
		words = append(words, strings.TrimRight(w, ",.:;"))
	}
	for _, want := range []string{"remotesigner-<version>-src-vendored.tar.gz", releaseURL} {
		if !slices.Contains(words, want) {
			p = append(p, "NOTICE.execution does not name "+want)
		}
	}
	return p
}

// Every release attaches the source archive the LGPL asks for, next to the
// archives (docs/operations/release.md section 1): a before hook of
// .goreleaser.yaml runs make release-src, the release and checksums.txt take
// the file it writes, and the default flavour's NOTICE says where it is. The
// dry run builds and checks that archive (TestReleaseSource in test/release)
// but publishes no release, so this is the check of the release's own step.
func TestReleaseAttachesSource(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("make is not installed")
	}
	data, err := os.ReadFile(filepath.Join(root, ".goreleaser.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg releaseConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	notice, err := os.ReadFile(filepath.Join(root, "NOTICE.execution"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("make", "-n", "-C", root, "release-src", "VERSION=1.1.0").CombinedOutput()
	if err != nil {
		t.Fatalf("make -n release-src: %v: %s", err, out)
	}
	src := regexp.MustCompile(`-czf (\S+-src-vendored\.tar\.gz) `).FindStringSubmatch(string(out))
	if src == nil || src[1] != "build/release/remotesigner-1.1.0-src-vendored.tar.gz" {
		t.Fatalf("make release-src VERSION=1.1.0 writes %q, want build/release/remotesigner-1.1.0-src-vendored.tar.gz:\n%s",
			src, out)
	}
	for _, p := range releaseSourceProblems(cfg, src[1], string(notice)) {
		t.Error(p)
	}
}

func TestReleaseSourceProblems(t *testing.T) {
	const src = "build/release/remotesigner-1.1.0-src-vendored.tar.gz"
	const notice = "published with it as\nremotesigner-<version>-src-vendored.tar.gz, a file of the release\n" +
		releaseURL + ", where"
	glob := []extraFile{{Glob: "build/release/remotesigner-*-src-vendored.tar.gz"}}
	good := func() releaseConfig {
		var c releaseConfig
		c.Before.Hooks = []string{"make release-docs GO_LICENSES=x RELEASE_REF={{ .Tag }}",
			"make release-src VERSION={{ .Version }}"}
		c.Checksum.ExtraFiles = slices.Clone(glob)
		c.Release.ExtraFiles = slices.Clone(glob)
		return c
	}
	tests := []struct {
		name   string
		edit   func(*releaseConfig)
		notice string
		want   string // a substring of the one problem
	}{
		{"good", func(*releaseConfig) {}, notice, ""},
		{"no release-src hook", func(c *releaseConfig) { c.Before.Hooks = c.Before.Hooks[:1] }, notice, "no before hook"},
		{"release-src before release-docs", func(c *releaseConfig) { slices.Reverse(c.Before.Hooks) }, notice, "empties"},
		{"not attached", func(c *releaseConfig) { c.Release.ExtraFiles = nil }, notice, "release.extra_files"},
		{"another file attached", func(c *releaseConfig) {
			c.Release.ExtraFiles = []extraFile{{Glob: "build/release/*.licenses"}}
		}, notice, "release.extra_files"},
		{"no checksum", func(c *releaseConfig) { c.Checksum.ExtraFiles = nil }, notice, "checksum.extra_files"},
		{"notice without the archive", func(*releaseConfig) {}, "the source is at " + releaseURL, "src-vendored"},
		{"notice without the release", func(*releaseConfig) {}, "the source is remotesigner-<version>-src-vendored.tar.gz",
			"releases/tag"},
		{"notice with another release", func(*releaseConfig) {},
			"remotesigner-<version>-src-vendored.tar.gz at https://github.com/theQRL/go-qrl/releases/tag/v<version>",
			"releases/tag"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := good()
			tt.edit(&c)
			got := releaseSourceProblems(c, src, tt.notice)
			if tt.want == "" && len(got) != 0 || tt.want != "" && (len(got) != 1 || !strings.Contains(got[0], tt.want)) {
				t.Errorf("problems %q, want one mentioning %q", got, tt.want)
			}
		})
	}
}

var (
	// dockerRunNetwork finds the network a documented `docker run` joins,
	// written `--network <name>`; the signer's own --network flag is
	// written with `=`.
	dockerRunNetwork = regexp.MustCompile(`(?m)^docker run .*--network ([a-z0-9][a-z0-9_.-]*)`)
	// dockerNetworkCreate finds a documented `docker network create`.
	dockerNetworkCreate = regexp.MustCompile(`(?m)^docker network create(?: --?[a-z-]+(?:=\S+)?)* ([a-z0-9][a-z0-9_.-]*)`)
)

// missingNetworks returns the user-defined networks the `docker run`
// commands of a page join that no `docker network create` on the page
// creates: docker run fails with "network not found" for them.
func missingNetworks(text string) []string {
	created := map[string]bool{"bridge": true, "host": true, "none": true}
	for _, m := range dockerNetworkCreate.FindAllStringSubmatch(text, -1) {
		created[m[1]] = true
	}
	var out []string
	for _, m := range dockerRunNetwork.FindAllStringSubmatch(text, -1) {
		if !created[m[1]] {
			out = append(out, m[1])
		}
	}
	return out
}

// Every `docker run` example in the docs runs as written: the network it
// joins is created on the same page.
func TestDocsDockerNetworksExist(t *testing.T) {
	for _, f := range repoFiles(t) {
		if !strings.HasSuffix(f.path, ".md") {
			continue
		}
		for _, n := range missingNetworks(f.text) {
			t.Errorf("%s: docker run joins network %s, which the page never creates (docker network create %s)", f.path, n, n)
		}
	}
	for _, tt := range []struct {
		text string
		want int
	}{
		{"docker run -d --network signer-net img\n", 1},
		{"docker network create signer-net\ndocker run -d --network signer-net img\n", 0},
		{"docker network create --internal signer-net\ndocker run --network signer-net img\n", 0},
		{"docker run --network host img\n", 0},
		{"docker run img consensus --network=/network/config.yaml\n", 0},
	} {
		if got := missingNetworks(tt.text); len(got) != tt.want {
			t.Errorf("missingNetworks(%q) = %q, want %d", tt.text, got, tt.want)
		}
	}
}

// runAsRoot matches advice to run the signer's container as root.
var runAsRoot = regexp.MustCompile(`(?i)runAsUser:\s*0\b|User\(\s*uid\s*=\s*0\b|--user[ =](?:0\b|root\b)|^\s*user:\s*["']?(?:0|root)\b`)

// The deployment docs and examples never run the image as root: it is built
// to run as 65532, and as root without capabilities it cannot even write
// /data.
func TestDeployNeverRunsAsRoot(t *testing.T) {
	n := 0
	for _, f := range repoFiles(t) {
		if !strings.HasPrefix(f.path, "deploy/") && !strings.HasPrefix(f.path, "docs/operations/") {
			continue
		}
		n++
		for i, line := range strings.Split(f.text, "\n") {
			if runAsRoot.MatchString(line) {
				t.Errorf("%s:%d: %q runs the container as root", f.path, i+1, strings.TrimSpace(line))
			}
		}
	}
	if n == 0 {
		t.Fatal("no deployment files")
	}
	for _, tt := range []struct {
		line string
		want bool
	}{
		{"or run the container as root (Kurtosis `User(uid=0, gid=0)`, Kubernetes `runAsUser: 0`)", true},
		{"docker run --user 0:0 img", true},
		{"docker run --user=root img", true},
		{`    user: "0:0"`, true},
		{"Kubernetes `runAsUser: 65532`", false},
		{"`fsGroup: 65532`", false},
		{"docker run --user 65532:65532 img", false},
	} {
		if got := runAsRoot.MatchString(tt.line); got != tt.want {
			t.Errorf("runAsRoot(%q) = %v, want %v", tt.line, got, tt.want)
		}
	}
}
