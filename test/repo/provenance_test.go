// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"os"
	"os/exec"
	"path"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// provenanceRow matches the path cell of a PROVENANCE.md file-table row.
var provenanceRow = regexp.MustCompile("^\\| `([^`]+)` \\|")

// provenancePaths returns the paths of the PROVENANCE.md file table; a
// vendored directory ends in "/".
func provenancePaths(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(root + "/PROVENANCE.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	begin, end := strings.Index(text, "<!-- headercheck:begin -->"), strings.Index(text, "<!-- headercheck:end -->")
	if begin < 0 || end < begin {
		t.Fatal("PROVENANCE.md: no file table between the headercheck markers")
	}
	var paths []string
	for _, line := range strings.Split(text[begin:end], "\n") {
		if m := provenanceRow.FindStringSubmatch(line); m != nil {
			paths = append(paths, m[1])
		}
	}
	return paths
}

// rowless reports whether a file needs no PROVENANCE.md row, as PROVENANCE.md
// ("Header classes") lists them: project Markdown, the build and module
// files, the licence texts and the NOTICE files, and the generated golden
// vectors, which PROVENANCE.md covers as a whole ("Golden vectors").
func rowless(p string) bool {
	base := path.Base(p)
	switch {
	case strings.HasSuffix(base, ".md"):
		return true
	case base == "go.mod", base == "go.sum":
		return true
	case slices.Contains([]string{"LICENSE", "NOTICE", "NOTICE.execution", "Makefile", ".gitignore", "renovate.json"}, p):
		return true
	case strings.HasPrefix(p, "LICENSES/") && strings.HasSuffix(base, ".txt"):
		return true
	case strings.HasPrefix(p, "testdata/vectors/"):
		return true
	}
	return false
}

// PROVENANCE.md is complete: every tracked file has a row, lies in a
// vendored tree that has one, or is one of the kinds PROVENANCE.md says
// need none. headercheck checks the headers of the kinds it reads, and that
// every row's file exists; this keeps a file of any other kind from shipping
// without a recorded origin.
func TestProvenanceCoversEveryFile(t *testing.T) {
	out, err := exec.Command("git", "-C", root, "-c", "gc.auto=0", "ls-files").Output()
	if err != nil {
		t.Skipf("git ls-files: %v (not a git checkout)", err)
	}
	rows := provenancePaths(t)
	recorded := map[string]bool{}
	var trees []string
	for _, p := range rows {
		if strings.HasSuffix(p, "/") {
			trees = append(trees, p)
		}
		recorded[p] = true
	}
	tracked := strings.Fields(string(out))
	if len(tracked) == 0 {
		t.Fatal("git ls-files listed nothing")
	}
	for _, p := range tracked {
		inTree := slices.ContainsFunc(trees, func(dir string) bool { return strings.HasPrefix(p, dir) })
		if !recorded[p] && !inTree && !rowless(p) {
			t.Errorf("%s: no PROVENANCE.md row, and not a kind PROVENANCE.md exempts", p)
		}
	}
}

func TestRowless(t *testing.T) {
	for p, want := range map[string]bool{
		"README.md": true, "docs/operations/release.md": true, "tools/vectorgen/go.sum": true,
		"LICENSES/MIT.txt": true, "NOTICE": true, "NOTICE.execution": true,
		"testdata/vectors/signing/attestation.json": true, "docs/LICENSE": false,
		"deploy/systemd/remotesigner.service": false, "internal/consensus/testdata/signing.json": false,
		"LICENSES/notes.md.bak": false, "deploy/config/example.toml": false,
	} {
		if got := rowless(p); got != want {
			t.Errorf("rowless(%q) = %v, want %v", p, got, want)
		}
	}
}
