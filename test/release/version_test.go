// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// metadata is the part of goreleaser's dist/metadata.json the version check
// reads: the tag the run built (GORELEASER_CURRENT_TAG, or the latest tag),
// the version it derived from it, and the commit.
type metadata struct {
	Tag     string `json:"tag"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// snapshotSuffix starts the suffix goreleaser's default snapshot version
// template appends to the tag's version: -SNAPSHOT-<short commit>.
const snapshotSuffix = "-SNAPSHOT-"

// readMetadata returns dist/metadata.json.
func readMetadata(t *testing.T, dist string) metadata {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dist, "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	var md metadata
	if err := json.Unmarshal(data, &md); err != nil {
		t.Fatalf("metadata.json: %v", err)
	}
	return md
}

// versionProblems returns what is wrong with the version a goreleaser run
// derived from its tag: a release of the tag v<X> is version <X>, the "v"
// dropped, and a snapshot (the dry run) is <X>-SNAPSHOT-<short commit>.
func versionProblems(md metadata) []string {
	base, ok := strings.CutPrefix(md.Tag, "v")
	if !ok || base == "" {
		return []string{fmt.Sprintf("tag %q is not a version tag v<major>.<minor>.<patch>", md.Tag)}
	}
	if md.Commit == "" {
		return []string{"metadata.json names no commit"}
	}
	if rest, ok := strings.CutPrefix(md.Version, base+snapshotSuffix); ok {
		if rest == "" || !strings.HasPrefix(md.Commit, rest) {
			return []string{fmt.Sprintf("snapshot version %q does not end in the short commit of %s", md.Version, md.Commit)}
		}
		return nil
	}
	if md.Version != base {
		return []string{fmt.Sprintf("version %q for the tag %s, want %q", md.Version, md.Tag, base)}
	}
	return nil
}

// versionLine is the start of what `<flavour> --version` prints for a build
// of md's version and commit.
func versionLine(flavour string, md metadata) string {
	return fmt.Sprintf("%s version %s (commit %s, ", flavour, md.Version, md.Commit)
}

// TestReleaseVersion checks the version every binary of a goreleaser run
// reports: the version goreleaser derived from the tag, so that a release
// of the tag v1.0.0 prints "remotesigner version 1.0.0 (commit ...", through
// the ldflags of .goreleaser.yaml. It runs every binary built for this
// machine; `make release-check` runs it on the dry run, and `make
// release-version` on a build for a tag that need not exist
// (docs/operations/release.md).
func TestReleaseVersion(t *testing.T) {
	dist := distDir(t)
	md := readMetadata(t, dist)
	for _, p := range versionProblems(md) {
		t.Error(p)
	}
	ran := map[string]bool{}
	for _, a := range ofType(readArtifacts(t, dist), "Binary") {
		if a.Goos != runtime.GOOS || a.Goarch != runtime.GOARCH {
			continue
		}
		flavour := a.Extra.ID
		bin := filepath.Join(dist, filepath.Base(filepath.Dir(a.Path)), filepath.Base(a.Path))
		out, err := exec.Command(bin, "--version").CombinedOutput()
		if err != nil {
			t.Errorf("%s --version: %v: %s", bin, err, out)
			continue
		}
		if want := versionLine(flavour, md); !strings.HasPrefix(string(out), want) {
			t.Errorf("%s --version printed %q, want it to start with %q", bin, out, want)
		}
		ran[flavour] = true
	}
	for _, f := range flavours {
		if !ran[f] {
			t.Errorf("no %s binary for %s/%s in the run", f, runtime.GOOS, runtime.GOARCH)
		}
	}
}

func TestVersionProblems(t *testing.T) {
	const commit = "86dbd1a0c0ffee0c0ffee0c0ffee0c0ffee0c0ff"
	tests := []struct {
		name string
		md   metadata
		want string // a substring of the one problem; "" for none
	}{
		{"release", metadata{Tag: "v1.0.0", Version: "1.0.0", Commit: commit}, ""},
		{"pre-release", metadata{Tag: "v1.1.0-rc.1", Version: "1.1.0-rc.1", Commit: commit}, ""},
		{"snapshot", metadata{Tag: "v1.0.0", Version: "1.0.0-SNAPSHOT-86dbd1a", Commit: commit}, ""},
		{"the tag's v kept", metadata{Tag: "v1.0.0", Version: "v1.0.0", Commit: commit}, `want "1.0.0"`},
		{"another version", metadata{Tag: "v1.0.0", Version: "1.0.1", Commit: commit}, `want "1.0.0"`},
		{"snapshot of another commit", metadata{Tag: "v1.0.0", Version: "1.0.0-SNAPSHOT-1234567", Commit: commit},
			"short commit"},
		{"not a version tag", metadata{Tag: "1.0.0", Version: "1.0.0", Commit: commit}, "not a version tag"},
		{"no commit", metadata{Tag: "v1.0.0", Version: "1.0.0"}, "no commit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := versionProblems(tt.md)
			switch {
			case tt.want == "" && len(got) != 0:
				t.Errorf("problems %q, want none", got)
			case tt.want != "" && (len(got) != 1 || !strings.Contains(got[0], tt.want)):
				t.Errorf("problems %q, want one mentioning %q", got, tt.want)
			}
		})
	}
	md := metadata{Tag: "v1.0.0", Version: "1.0.0", Commit: commit}
	if got, want := versionLine(fullFlavour, md), "remotesigner version 1.0.0 (commit "+commit+", "; got != want {
		t.Errorf("versionLine = %q, want %q", got, want)
	}
}
