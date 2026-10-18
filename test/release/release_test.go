// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// artifact is one entry of goreleaser's dist/artifacts.json.
type artifact struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Goos   string `json:"goos"`
	Goarch string `json:"goarch"`
	Type   string `json:"type"`
	Extra  struct {
		ID        string   `json:"ID"`
		Binaries  []string `json:"Binaries"`
		Digest    string   `json:"Digest"`
		Platforms []string `json:"Platforms"`
	} `json:"extra"`
}

// releaseTargets are the os/arch pairs .goreleaser.yaml builds archives
// for, and imageArchs the architectures of its linux images.
var (
	releaseTargets = []string{"darwin/amd64", "darwin/arm64", "linux/amd64", "linux/arm64"}
	imageArchs     = []string{"amd64", "arm64"}
)

// distDir returns the dry run's dist/ directory, or skips the test.
func distDir(t *testing.T) string {
	t.Helper()
	dist := os.Getenv("REMOTESIGNER_RELEASE_DIST")
	if dist == "" {
		t.Skip("set REMOTESIGNER_RELEASE_DIST to a goreleaser dist/ directory (make release-snapshot release-check)")
	}
	return dist
}

// readArtifacts returns dist/artifacts.json. Its file artifacts live
// directly in dist/.
func readArtifacts(t *testing.T, dist string) []artifact {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dist, "artifacts.json"))
	if err != nil {
		t.Fatal(err)
	}
	var as []artifact
	if err := json.Unmarshal(data, &as); err != nil {
		t.Fatalf("artifacts.json: %v", err)
	}
	return as
}

func ofType(as []artifact, typ string) []artifact {
	var out []artifact
	for _, a := range as {
		if a.Type == typ {
			out = append(out, a)
		}
	}
	return out
}

// TestReleaseArchives checks every archive of the dry run: both flavours for
// every target, each with its binary, LICENSE, the flavour's NOTICE,
// LICENSES/ and third_party_licenses/, a static trimmed binary and, in the
// consensus flavour, no go-qrl module in `go version -m`; and checksums.txt
// covers every archive.
func TestReleaseArchives(t *testing.T) {
	dist := distDir(t)
	as := readArtifacts(t, dist)
	archives := ofType(as, "Archive")
	sums := readChecksums(t, filepath.Join(dist, "checksums.txt"))

	for _, flavour := range flavours {
		var targets []string
		for _, a := range archives {
			if a.Extra.ID == flavour {
				targets = append(targets, a.Goos+"/"+a.Goarch)
			}
		}
		slices.Sort(targets)
		if !slices.Equal(targets, releaseTargets) {
			t.Errorf("%s archives for %q, want %q", flavour, targets, releaseTargets)
		}
	}

	for _, a := range archives {
		t.Run(a.Name, func(t *testing.T) {
			p := filepath.Join(dist, filepath.Base(a.Path))
			data, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(data)
			if got := sums[a.Name]; got != hex.EncodeToString(sum[:]) {
				t.Errorf("checksums.txt has %q for %s, want %x", got, a.Name, sum)
			}
			zr, err := gzip.NewReader(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			// The archive wraps its files in a directory named after it.
			files, err := readTar(zr, 1)
			if err != nil {
				t.Fatal(err)
			}
			checkLicenceFiles(t, a.Extra.ID, files)
			bin, ok := files[a.Extra.ID]
			if !ok || bin.hdr.FileInfo().Mode().Perm()&0o111 == 0 {
				t.Fatalf("no executable %s in the archive", a.Extra.ID)
			}
			checkBinary(t, a.Extra.ID, writeTemp(t, a.Extra.ID, bin.data, 0o755))
		})
	}
}

// readChecksums parses a goreleaser checksums.txt: "<sha256>  <name>" lines.
func readChecksums(t *testing.T, p string) map[string]string {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if sum, name, ok := strings.Cut(sc.Text(), "  "); ok {
			out[name] = sum
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestReleaseSBOMs checks that every archive has an SPDX SBOM, unless the
// dry run skipped the SBOM step (syft not installed).
func TestReleaseSBOMs(t *testing.T) {
	dist := distDir(t)
	as := readArtifacts(t, dist)
	sboms := ofType(as, "SBOM")
	if len(sboms) == 0 {
		if os.Getenv("REMOTESIGNER_RELEASE_SBOM") == "1" {
			t.Fatal("the dry run wrote no SBOM")
		}
		t.Skip("the dry run wrote no SBOM (sbom skipped); REMOTESIGNER_RELEASE_SBOM=1 requires them")
	}
	for _, a := range ofType(as, "Archive") {
		i := slices.IndexFunc(sboms, func(s artifact) bool { return strings.HasPrefix(s.Name, a.Name) })
		if i < 0 {
			t.Errorf("no SBOM for %s", a.Name)
			continue
		}
		data, err := os.ReadFile(filepath.Join(dist, filepath.Base(sboms[i].Path)))
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			SPDXVersion string            `json:"spdxVersion"`
			Packages    []json.RawMessage `json:"packages"`
		}
		if err := json.Unmarshal(data, &doc); err != nil || doc.SPDXVersion == "" || len(doc.Packages) == 0 {
			t.Errorf("%s: not an SPDX document with packages (%v)", sboms[i].Name, err)
		}
	}
}

// imageConfig is the part of `docker image inspect` the tests read.
type imageConfig struct {
	Architecture string `json:"Architecture"`
	Os           string `json:"Os"`
	Config       struct {
		User       string            `json:"User"`
		Entrypoint []string          `json:"Entrypoint"`
		Cmd        []string          `json:"Cmd"`
		Env        []string          `json:"Env"`
		Labels     map[string]string `json:"Labels"`
		WorkingDir string            `json:"WorkingDir"`
	} `json:"Config"`
}

// inspectImage returns the configuration of a local image.
func inspectImage(t *testing.T, image string) imageConfig {
	t.Helper()
	var cfgs []imageConfig
	if err := json.Unmarshal([]byte(docker(t, "image", "inspect", image)), &cfgs); err != nil || len(cfgs) != 1 {
		t.Fatalf("docker image inspect %s: %v", image, err)
	}
	return cfgs[0]
}

// imageConfigProblems returns what is wrong with an image's configuration:
// it must run as the nonroot user with the entrypoint exactly and the
// default command, set no plaintext-token override in its entrypoint,
// command or environment, and carry the OCI labels of its flavour, the
// licence label naming licences.
func imageConfigProblems(flavour string, cfg imageConfig, licences string) []string {
	var p []string
	c := cfg.Config
	if c.User != nonroot {
		p = append(p, fmt.Sprintf("image user %q, want %s (non-root)", c.User, nonroot))
	}
	if !slices.Equal(c.Entrypoint, entrypoint) {
		p = append(p, fmt.Sprintf("entrypoint %q, want %q", c.Entrypoint, entrypoint))
	}
	if !slices.Equal(c.Cmd, []string{"consensus"}) {
		p = append(p, fmt.Sprintf("command %q, want [consensus]", c.Cmd))
	}
	for _, s := range slices.Concat(c.Entrypoint, c.Cmd, c.Env) {
		if plaintextOverride.MatchString(s) {
			p = append(p, fmt.Sprintf("the image sets the plaintext-token override: %q", s))
		}
	}
	for _, l := range []struct{ key, want string }{
		{"org.opencontainers.image.title", flavour},
		{"org.opencontainers.image.licenses", licences},
		{"org.opencontainers.image.source", "https://github.com/rgeraldes24/go-remotesigner"},
	} {
		if got := c.Labels[l.key]; got != l.want {
			p = append(p, fmt.Sprintf("label %s = %q, want %q", l.key, got, l.want))
		}
	}
	if flavour == consensusFlavour && strings.Contains(c.Labels["org.opencontainers.image.licenses"], "GPL") {
		p = append(p, "the consensus image's licence label names a GPL licence")
	}
	return p
}

// checkImageConfig reports imageConfigProblems as test errors.
func checkImageConfig(t *testing.T, flavour string, cfg imageConfig, licences string) {
	t.Helper()
	for _, msg := range imageConfigProblems(flavour, cfg, licences) {
		t.Error(msg)
	}
}

// checkImageFiles checks the files of an image: the licence files under
// /usr/share/doc/remotesigner/, the flavour's binary, and /data empty (no
// token, key or store baked in), owned by the nonroot user with mode 0700.
func checkImageFiles(t *testing.T, flavour, image string) {
	t.Helper()
	ctr := strings.TrimSpace(docker(t, "create", image))
	defer docker(t, "rm", ctr)
	checkLicenceFiles(t, flavour, dockerTar(t, 1, "cp", ctr+":/usr/share/doc/remotesigner/", "-"))
	bin, ok := dockerTar(t, 0, "cp", ctr+":/usr/local/bin/remotesigner", "-")["remotesigner"]
	if !ok {
		t.Fatal("no /usr/local/bin/remotesigner")
	}
	checkBinary(t, flavour, writeTemp(t, "remotesigner", bin.data, 0o755))
	dataDir := dockerTar(t, 0, "cp", ctr+":/data", "-")
	data, ok := dataDir["data"]
	if !ok {
		t.Fatal("no /data")
	}
	if len(dataDir) != 1 {
		t.Errorf("/data is not empty in the image: %d entries", len(dataDir)-1)
	}
	if owner := fmt.Sprintf("%d:%d", data.hdr.Uid, data.hdr.Gid); owner != nonroot || data.hdr.FileInfo().Mode().Perm() != 0o700 {
		t.Errorf("/data is %s mode %04o, want %s mode 0700", owner, data.hdr.FileInfo().Mode().Perm(), nonroot)
	}
}

// TestReleaseImages checks every image of the dry run, which goreleaser
// loads into the local image store with one tag per architecture: its user,
// entrypoint and labels, its licence files and binary, and, for the images of
// this machine's architecture, that it runs as non-root with a read-only
// root file system.
func TestReleaseImages(t *testing.T) {
	dist := distDir(t)
	requireDocker(t)
	images := ofType(readArtifacts(t, dist), "Docker Image")
	hostArch := strings.TrimSpace(docker(t, "version", "--format", "{{.Server.Arch}}"))

	for _, flavour := range flavours {
		var archs []string
		for _, img := range images {
			if img.Extra.ID == flavour && !strings.Contains(img.Name, ":latest") {
				archs = append(archs, strings.TrimPrefix(img.Extra.Platforms[0], "linux/"))
			}
		}
		slices.Sort(archs)
		if archs = slices.Compact(archs); !slices.Equal(archs, imageArchs) {
			t.Errorf("%s images for %q, want %q", flavour, archs, imageArchs)
		}
	}

	for _, img := range images {
		if strings.Contains(img.Name, ":latest") {
			continue // the same image as its version tag
		}
		t.Run(img.Name, func(t *testing.T) {
			flavour := img.Extra.ID
			licences := strings.TrimSpace(string(readRepo(t, "build/release/"+flavour+".licenses")))
			cfg := inspectImage(t, img.Name)
			arch := strings.TrimPrefix(img.Extra.Platforms[0], "linux/")
			if cfg.Os != "linux" || cfg.Architecture != arch {
				t.Errorf("image platform %s/%s, want linux/%s", cfg.Os, cfg.Architecture, arch)
			}
			checkImageConfig(t, flavour, cfg, licences)
			checkImageFiles(t, flavour, img.Name)
			if arch != hostArch {
				t.Logf("not run: the image is %s, the Docker host %s", arch, hostArch)
				return
			}
			out := docker(t, "run", "--rm", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", img.Name, "--version")
			if !strings.HasPrefix(out, flavour+" version ") {
				t.Errorf("--version printed %q, want the %s flavour's version", out, flavour)
			}
		})
	}
}
