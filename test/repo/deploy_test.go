// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"encoding/json"
	"fmt"
	"os"
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
