// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// goQRLModule is the LGPL go-qrl module; go-qrllib (MIT) is another one.
const goQRLModule = "github.com/theQRL/go-qrl"

// executionPackage is the package only the default flavour builds.
const executionPackage = "github.com/rgeraldes24/go-remotesigner/internal/execution"

// listDeps returns the import paths and modules of the binary's packages
// for the tags.
func listDeps(t *testing.T, tags string) (pkgs, modules []string) {
	t.Helper()
	args := []string{"list", "-deps", "-f", "{{.ImportPath}}\t{{with .Module}}{{.Path}}{{end}}"}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	cmd := exec.Command("go", append(args, "./cmd/remotesigner")...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -tags %q: %v", tags, err)
	}
	for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		pkg, mod, _ := strings.Cut(line, "\t")
		pkgs, modules = append(pkgs, pkg), append(modules, mod)
	}
	return pkgs, modules
}

// The consensus-only flavour has no execution mode and links no go-qrl:
// neither its package graph (go list -deps) nor its binary (go version -m)
// names go-qrl or the execution package. The default flavour builds the
// execution package.
func TestConsensusFlavourLinksNoGoQRL(t *testing.T) {
	pkgs, modules := listDeps(t, "noexecution")
	for i, p := range pkgs {
		if p == executionPackage || strings.HasPrefix(p, executionPackage+"/") {
			t.Errorf("the noexecution build has %s", p)
		}
		if modules[i] == goQRLModule {
			t.Errorf("the noexecution build has %s from %s", p, goQRLModule)
		}
	}
	full, _ := listDeps(t, "")
	found := false
	for _, p := range full {
		found = found || p == executionPackage
	}
	if !found {
		t.Error("the default flavour does not build the execution package")
	}

	bin := filepath.Join(t.TempDir(), "remotesigner-consensus")
	build := exec.Command("go", "build", "-tags", "noexecution", "-o", bin, "./cmd/remotesigner")
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	out, err := exec.Command("go", "version", "-m", bin).Output()
	if err != nil {
		t.Fatal(err)
	}
	if regexp.MustCompile(`(?m)^\s*dep\s+` + regexp.QuoteMeta(goQRLModule) + `\s`).Match(out) {
		t.Fatalf("go version -m lists %s:\n%s", goQRLModule, out)
	}
	if !regexp.MustCompile(`(?m)^\s*build\s+-tags=noexecution\s*$`).Match(out) {
		t.Fatalf("the binary was not built with noexecution:\n%s", out)
	}
	if strings.Contains(string(out), executionPackage) {
		t.Fatalf("the binary records %s", executionPackage)
	}
}
