// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

// srcVendored matches the source archive each release attaches.
const srcVendored = "remotesigner-*-src-vendored.tar.gz"

// TestReleaseSource checks the source archive of the dry run
// (make release-src, in RELEASE_DIR): the committed tree with LICENSE, both
// NOTICE files and the GNU texts, and every linked module in vendor/, go-qrl
// at the version go.mod requires with its COPYING.LESSER, and no qrysm;
// no entry the packing tar added (sourceEntryProblems); checksums.txt
// covers it; and it builds the default flavour offline, from vendor/ alone,
// into a binary that links that go-qrl and says so in --version. That is
// the corresponding source the LGPL asks for.
func TestReleaseSource(t *testing.T) {
	dir := os.Getenv("REMOTESIGNER_RELEASE_DOCS")
	if dir == "" {
		t.Skip("set REMOTESIGNER_RELEASE_DOCS to the release-docs directory (make release-snapshot release-check)")
	}
	matches, err := filepath.Glob(filepath.Join(dir, srcVendored))
	if err != nil || len(matches) != 1 {
		t.Fatalf("%s in %s: %q (%v), want one", srcVendored, dir, matches, err)
	}
	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if dist := os.Getenv("REMOTESIGNER_RELEASE_DIST"); dist != "" {
		sum := sha256.Sum256(data)
		if got := readChecksums(t, filepath.Join(dist, "checksums.txt"))[filepath.Base(matches[0])]; got != hex.EncodeToString(sum[:]) {
			t.Errorf("checksums.txt has %q for %s, want %x", got, filepath.Base(matches[0]), sum)
		}
	}
	hdrs, err := tarHeaders(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range sourceEntryProblems(hdrs) {
		t.Error(p)
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	files, err := readTar(zr, 1)
	if err != nil {
		t.Fatal(err)
	}
	version := goQRLVersion(t)
	for _, name := range []string{"go.mod", "go.sum", "LICENSE", "NOTICE", "NOTICE.execution",
		"LICENSES/LGPL-3.0-or-later.txt", "LICENSES/GPL-3.0-or-later.txt", "vendor/modules.txt",
		"vendor/github.com/theQRL/go-qrl/COPYING.LESSER", "vendor/github.com/theQRL/go-qrl/core/types/transaction_signing.go"} {
		if _, ok := files[name]; !ok {
			t.Errorf("the source archive has no %s", name)
		}
	}
	if !strings.Contains(string(files["vendor/modules.txt"].data), "# "+goQRL+" "+version+"\n") {
		t.Errorf("vendor/modules.txt does not vendor %s %s", goQRL, version)
	}
	for name := range files {
		if strings.HasPrefix(name, "vendor/github.com/theQRL/qrysm/") {
			t.Fatalf("the source archive vendors qrysm: %s", name)
		}
	}

	src := t.TempDir()
	for name, f := range files {
		p := filepath.Join(src, filepath.FromSlash(name))
		if f.hdr.FileInfo().IsDir() {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, f.data, f.hdr.FileInfo().Mode().Perm()|0o200); err != nil {
			t.Fatal(err)
		}
	}
	bin := filepath.Join(t.TempDir(), fullFlavour)
	build := exec.Command(goTool(t), "build", "-mod=vendor", "-trimpath", "-o", bin, "./cmd/remotesigner")
	build.Dir = src
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOPROXY=off", "GOFLAGS=", "GOTOOLCHAIN=local",
		"GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building from the source archive: %v\n%s", err, out)
	}
	out, err := exec.Command(goTool(t), "version", "-m", bin).Output()
	if err != nil || !strings.Contains(string(out), "\tdep\t"+goQRL+"\t"+version+"\t") {
		t.Fatalf("the rebuilt binary does not link %s %s: %v\n%s", goQRL, version, err, out)
	}
	out, err = exec.Command(bin, "--version").Output()
	if err != nil || !strings.Contains(string(out), "GNU Lesser") {
		t.Fatalf("the rebuilt binary's --version: %v %s", err, out)
	}
}

// tarHeaders returns the header of every entry of a gzipped tar archive.
func tarHeaders(data []byte) ([]*tar.Header, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	var hdrs []*tar.Header
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return hdrs, nil
		}
		if err != nil {
			return nil, err
		}
		hdrs = append(hdrs, hdr)
	}
}

// sourceEntryProblems returns the entries of the source archive that are
// not the tree's: the AppleDouble ._ files macOS's tar (bsdtar) adds for a
// file's extended attributes, and extended attributes in PAX records
// (LIBARCHIVE.xattr.* from bsdtar, SCHILY.xattr.* from GNU tar), which GNU
// tar warns about when it extracts the archive. make release-src packs
// without them on either tar (Makefile).
func sourceEntryProblems(hdrs []*tar.Header) []string {
	var p []string
	for _, h := range hdrs {
		if strings.HasPrefix(path.Base(h.Name), "._") {
			p = append(p, "the source archive holds the AppleDouble file "+h.Name)
			continue
		}
		for k := range h.PAXRecords {
			if strings.HasPrefix(k, "LIBARCHIVE.xattr.") || strings.HasPrefix(k, "SCHILY.xattr.") {
				p = append(p, fmt.Sprintf("the source archive's %s carries the extended attribute %s", h.Name, k))
			}
		}
	}
	return p
}

func TestSourceEntryProblems(t *testing.T) {
	const dir = "remotesigner-1.1.0-src-vendored/"
	tests := []struct {
		name string
		hdr  tar.Header
		want string // a substring of the one problem; "" for none
	}{
		{"a file", tar.Header{Name: dir + "go.mod"}, ""},
		{"a directory", tar.Header{Name: dir + "cmd/", Typeflag: tar.TypeDir}, ""},
		{"a dotfile", tar.Header{Name: dir + ".goreleaser.yaml"}, ""},
		{"a PAX path record", tar.Header{Name: dir + "go.sum", PAXRecords: map[string]string{"path": dir + "go.sum"}}, ""},
		{"AppleDouble of the top directory", tar.Header{Name: "._remotesigner-1.1.0-src-vendored"}, "AppleDouble"},
		{"AppleDouble of a file", tar.Header{Name: dir + "._CHANGELOG.md"}, "AppleDouble"},
		{"AppleDouble of a dotfile", tar.Header{Name: dir + "._.goreleaser.yaml"}, "AppleDouble"},
		{"bsdtar xattr", tar.Header{Name: dir + "go.mod",
			PAXRecords: map[string]string{"LIBARCHIVE.xattr.com.apple.provenance": "AQ"}}, "LIBARCHIVE.xattr"},
		{"GNU tar xattr", tar.Header{Name: dir + "go.mod",
			PAXRecords: map[string]string{"SCHILY.xattr.user.x": "1"}}, "SCHILY.xattr"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sourceEntryProblems([]*tar.Header{&tt.hdr})
			switch {
			case tt.want == "" && len(got) != 0:
				t.Errorf("problems %q, want none", got)
			case tt.want != "" && (len(got) != 1 || !strings.Contains(got[0], tt.want)):
				t.Errorf("problems %q, want one mentioning %q", got, tt.want)
			}
		})
	}
}

// goQRLVersion is the go-qrl version go.mod requires.
func goQRLVersion(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Version}}", goQRL)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -m %s: %v", goQRL, err)
	}
	return strings.TrimSpace(string(out))
}

// goTool is the go command of the toolchain the module selects, which the
// archive builds with offline.
func goTool(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("go", "env", "GOROOT")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go env GOROOT: %v", err)
	}
	return filepath.Join(strings.TrimSpace(string(out)), "bin", "go")
}
