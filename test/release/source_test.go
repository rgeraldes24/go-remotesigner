// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
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
// checksums.txt covers it; and it builds the default flavour offline, from
// vendor/ alone, into a binary that links that go-qrl and says so in
// --version. That is the corresponding source the LGPL asks for.
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
