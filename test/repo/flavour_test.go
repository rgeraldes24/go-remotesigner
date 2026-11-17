// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
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

// goQRLCommit is the go-qrl commit the default flavour links, theQRL's own
// go-qrl. Moving it is a deliberate change that NOTICE.execution, the
// transaction vectors (make vectors) and the gqrl end-to-end test (make
// gqrl-e2e) follow.
const goQRLCommit = "b92884a3a1d5"

// The signer module requires theQRL's go-qrl at goQRLCommit and has no
// replace directive, so that go install builds what the release builds and
// no fork stands in for go-qrl; it requires no module of the cyyber stack,
// which only the tools/vectorgen modules link; and Renovate leaves the pin
// alone, since a bump must move everything above with it.
func TestGoQRLRequirement(t *testing.T) {
	renovate, err := os.ReadFile(filepath.Join(root, "renovate.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		IgnoreDeps []string `json:"ignoreDeps"`
	}
	if err := json.Unmarshal(renovate, &cfg); err != nil {
		t.Fatalf("renovate.json: %v", err)
	}
	if !slices.Contains(cfg.IgnoreDeps, goQRLModule) {
		t.Errorf("renovate.json's ignoreDeps does not name %s: Renovate would open bumps of the pin", goQRLModule)
	}

	cmd := exec.Command("go", "mod", "edit", "-json")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go mod edit -json: %v", err)
	}
	var mod struct {
		Require []struct{ Path, Version string }
		Replace []struct{ Old struct{ Path string } }
	}
	if err := json.Unmarshal(out, &mod); err != nil {
		t.Fatal(err)
	}
	for _, r := range mod.Replace {
		t.Errorf("go.mod replaces %s", r.Old.Path)
	}
	found := false
	for _, r := range mod.Require {
		if r.Path == goQRLModule {
			found = true
			if !strings.HasSuffix(r.Version, "-"+goQRLCommit) {
				t.Errorf("go.mod requires %s %s, not commit %s", goQRLModule, r.Version, goQRLCommit)
			}
		}
	}
	if !found {
		t.Errorf("go.mod does not require %s", goQRLModule)
	}
	sum, err := os.ReadFile(filepath.Join(root, "go.sum"))
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(sum), "\n") {
		if strings.HasPrefix(line, "github.com/cyyber/") {
			t.Errorf("go.sum names a module of the cyyber stack: %s", line)
		}
	}
}

// Only internal/execution imports go-qrl, in its code and in its tests, on
// every target: the rule the lint's depguard applies, checked without the
// linter. The consensus flavour's packages import none of it, tests
// included.
func TestGoQRLImportedOnlyByExecution(t *testing.T) {
	format := `{{.ImportPath}}{{range .Imports}} {{.}}{{end}}{{range .TestImports}} {{.}}{{end}}` +
		`{{range .XTestImports}} {{.}}{{end}}`
	imported := false
	for _, tg := range noticeTargets {
		for _, tags := range noticeFlavours {
			cmd := exec.Command("go", "list", "-e", "-tags", tags, "-f", format, "./...")
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "GOOS="+tg[0], "GOARCH="+tg[1], "CGO_ENABLED=0")
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("go list -tags %q for %s/%s: %v", tags, tg[0], tg[1], err)
			}
			for line := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
				f := strings.Fields(line)
				pkg := f[0]
				inExecution := pkg == executionPackage || strings.HasPrefix(pkg, executionPackage+"/")
				for _, imp := range f[1:] {
					if imp != goQRLModule && !strings.HasPrefix(imp, goQRLModule+"/") {
						continue
					}
					imported = imported || inExecution
					if !inExecution || tags == "noexecution" {
						t.Errorf("%s/%s, tags %q: %s imports %s", tg[0], tg[1], tags, pkg, imp)
					}
				}
			}
		}
	}
	if !imported {
		t.Error("internal/execution imports no go-qrl package")
	}
}

// goQRLDir returns the source directory of the go-qrl module the default
// flavour links.
func goQRLDir(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", goQRLModule)
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		t.Fatalf("go list -m %s: %v", goQRLModule, err)
	}
	return strings.TrimSpace(string(out))
}

// The GNU texts in LICENSES/ are the ones go-qrl itself ships, at the
// version the default flavour links: LGPL-3.0-or-later.txt is its
// COPYING.LESSER and GPL-3.0-or-later.txt its COPYING.
func TestGNUTextsAreGoQRLs(t *testing.T) {
	dir := goQRLDir(t)
	for text, upstream := range map[string]string{
		"LICENSES/LGPL-3.0-or-later.txt": "COPYING.LESSER",
		"LICENSES/GPL-3.0-or-later.txt":  "COPYING",
	} {
		got, err := os.ReadFile(filepath.Join(root, text))
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(filepath.Join(dir, upstream))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Errorf("%s is not go-qrl's %s", text, upstream)
		}
	}
}

var (
	// lgplHeader is the LGPL notice of a go-qrl library file.
	lgplHeader = regexp.MustCompile(`GNU Lesser General Public License`)
	// gplHeader is the GPL notice of a go-qrl command file.
	gplHeader = regexp.MustCompile(`GNU General Public License`)
)

// The default flavour links only go-qrl's library: on every target it
// builds for, no linked go-qrl package is under cmd/ or internal/, and every
// linked go-qrl file carries the LGPL notice or no GNU notice at all (go-qrl's
// README puts all of go-qrl outside cmd/ under the LGPL). A GPL-only file
// would make the binary a GPL work; go-licenses reads go-qrl's COPYING and
// reports GPL-3.0 for the whole module, which is why make licenses checks the
// module apart (docs/operations/release.md).
func TestLinkedGoQRLIsLGPL(t *testing.T) {
	files := map[string]bool{}
	for _, tg := range noticeTargets {
		cmd := exec.Command("go", "list", "-deps", "-f",
			`{{if .Module}}{{if eq .Module.Path "`+goQRLModule+`"}}{{range .GoFiles}}{{$.Dir}}/{{.}}{{"\n"}}{{end}}{{end}}{{end}}`,
			"./cmd/remotesigner")
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "GOOS="+tg[0], "GOARCH="+tg[1], "CGO_ENABLED=0")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list for %s/%s: %v", tg[0], tg[1], err)
		}
		for f := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
			files[f] = true
		}
	}
	dir := goQRLDir(t)
	if len(files) == 0 {
		t.Fatal("the default flavour links no go-qrl file")
	}
	for f := range files {
		rel, err := filepath.Rel(dir, f)
		if err != nil {
			t.Fatal(err)
		}
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, "cmd/") || strings.HasPrefix(rel, "internal/") {
			t.Errorf("the default flavour links go-qrl's %s", rel)
		}
		lines, err := readLines(f, headerLines)
		if err != nil {
			t.Fatal(err)
		}
		header := strings.Join(lines, " ")
		if gplHeader.MatchString(header) && !lgplHeader.MatchString(header) {
			t.Errorf("go-qrl's %s carries a GPL notice, not the LGPL's", rel)
		}
	}
}

// NOTICE.execution, which only the default flavour ships, carries the
// LGPL paragraph and names the GNU texts; NOTICE, which both ship, does not
// mention the LGPL.
func TestExecutionNotice(t *testing.T) {
	notice, err := os.ReadFile(filepath.Join(root, noticePath))
	if err != nil {
		t.Fatal(err)
	}
	if regexp.MustCompile(`(?i)LGPL|Lesser General Public`).Match(notice) {
		t.Error("NOTICE mentions the LGPL; that belongs in NOTICE.execution")
	}
	fragment, err := os.ReadFile(filepath.Join(root, executionPath))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(strings.Fields(string(fragment)), " ")
	for _, want := range []string{
		"links the go-qrl library (https://github.com/theQRL/go-qrl), licensed under the GNU Lesser General Public License",
		"LICENSES/LGPL-3.0-or-later.txt and LICENSES/GPL-3.0-or-later.txt",
		"remotesigner-<version>-src-vendored.tar.gz",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("NOTICE.execution does not say %q", want)
		}
	}
}
