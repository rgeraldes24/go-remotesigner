// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package acceptance

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/vectors"
)

// contractDir is the nested module of vectorgen contract mode. It links
// qrysm (GPL-3.0): these tests build it into a temporary directory and run
// it, and nothing here imports it.
const contractDir = "../../tools/vectorgen/contract"

// contractChecks is how many checks one contract run makes: capabilities,
// public keys, the ten signing oneofs, the epoch oneof and the RANDAO
// reveal.
const contractChecks = 14

// skipUnlessContract skips tests that build tools/vectorgen/contract unless
// REMOTESIGNER_VECTORS_CONTRACT is set (make vectors-contract).
func skipUnlessContract(t *testing.T) {
	t.Helper()
	if os.Getenv("REMOTESIGNER_VECTORS_CONTRACT") == "" {
		t.Skip("set REMOTESIGNER_VECTORS_CONTRACT=1 to build tools/vectorgen/contract and drive the binary with it")
	}
}

// contractNetworks returns the two end-to-end networks of the golden
// vectors, the qrysm e2e's first, each with its interop GVR.
func contractNetworks(t *testing.T) []vectors.Network {
	t.Helper()
	var out []vectors.Network
	for _, preset := range vectors.Presets {
		for _, nf := range vectors.Negative(t) {
			if nf.Preset == preset {
				out = append(out, nf.Network)
				break
			}
		}
	}
	if len(out) != len(vectors.Presets) {
		t.Fatalf("found %d networks for %d presets", len(out), len(vectors.Presets))
	}
	return out
}

// startForContract runs bin with the interop keys on network n as the qrysm
// VC finds it: bound to the interop GVR, with genesis time (so it releases
// RANDAO reveals), slashing protection on and exits enabled.
func startForContract(t *testing.T, bin string, n vectors.Network) *signer {
	t.Helper()
	keysDir := t.TempDir()
	writeInteropKeys(t, keysDir)
	s := start(t, options{bin: bin, keys: keysDir, noNetwork: true, consensus: []string{
		"--network=" + n.ConfigName,
		"--network-genesis-validators-root=" + n.GVR,
		"--network-genesis-time=" + strconv.Itoa(harnessGenesis),
		"--voluntary-exit-signing-enabled",
	}})
	s.waitReady()
	return s
}

// goCmd runs the go command in dir and returns its standard output.
func goCmd(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return string(out)
}

// buildContract builds the contract tool with the extra go build flags
// and returns the binary's path. The binary is a GPL-3.0 combined work and
// lives only in the test's temporary directory.
func buildContract(t *testing.T, flags ...string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "contract")
	args := append(append([]string{"build", "-o", bin}, flags...), ".")
	goCmd(t, contractDir, args...)
	return bin
}

// runContractTool drives s with the contract tool on network and returns
// its exit code and output.
func runContractTool(t *testing.T, tool string, s *signer, network string) (int, string) {
	t.Helper()
	vectorsDir, err := filepath.Abs("../../testdata/vectors")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(tool, "-signer", s.base, "-token-file", filepath.Join(s.data, "auth-token"),
		"-network", network, "-genesis-time", strconv.Itoa(harnessGenesis), "-vectors", vectorsDir)
	out, err := cmd.CombinedOutput()
	t.Logf("vectorgen contract:\n%s", out)
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, string(out)
}

// vectorgen contract against the built binary (PLAN S3b, DESIGN §7.1 L3
// contract): qrysm's own remote-web3signer keymanager, at the commit
// tools/vectorgen/contract pins, checks the capabilities, lists the keys,
// signs one request per SignRequest oneof and asks for one RANDAO reveal on
// each end-to-end network, and qrysm's verifiers check every answer.
func TestVectorgenContract(t *testing.T) {
	skipUnlessContract(t)
	tool := buildContract(t)
	for _, n := range contractNetworks(t) {
		t.Run(n.ConfigName, func(t *testing.T) {
			s := startForContract(t, binary, n)
			code, out := runContractTool(t, tool, s, n.ConfigName)
			if want := fmt.Sprintf("contract: %d passed, 0 failed\n", contractChecks); code != 0 || !strings.Contains(out, want) {
				t.Fatalf("exit %d, want 0 and %q", code, want)
			}
		})
	}
}

// rename replaces the one occurrence of from with to in file.
type rename struct{ file, from, to string }

// apply returns the content of r.file with the rename applied. A rename
// whose text no longer occurs exactly once fails the test, so the test
// cannot pass vacuously after the source moves.
func (r rename) apply(t *testing.T) []byte {
	t.Helper()
	src, err := os.ReadFile(r.file)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(src), r.from); n != 1 {
		t.Fatalf("%s has %d occurrences of %s, want 1: update the rename", r.file, n, r.from)
	}
	return []byte(strings.Replace(string(src), r.from, r.to, 1))
}

// writeOverlay writes renamed copies of the signer's files and a go build
// -overlay file that substitutes them, and returns its path. The working
// tree stays untouched, so no broken branch is needed.
func writeOverlay(t *testing.T, renames []rename) string {
	t.Helper()
	dir := t.TempDir()
	replace := map[string]string{}
	for i, r := range renames {
		file, err := filepath.Abs(r.file)
		if err != nil {
			t.Fatal(err)
		}
		r.file = file
		copyPath := filepath.Join(dir, fmt.Sprintf("%d-%s", i, filepath.Base(file)))
		if err := os.WriteFile(copyPath, r.apply(t), 0o600); err != nil {
			t.Fatal(err)
		}
		replace[file] = copyPath
	}
	b, err := json.Marshal(map[string]any{"Replace": replace})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// qrysmModule is the module path the contract tool imports qrysm by; its
// go.mod replaces it with the pinned commit.
const qrysmModule = "github.com/theQRL/qrysm"

// moduleDir returns the directory of module, as the build list of the
// module in dir resolves it (replacements included), downloading the
// module first. go list -m cannot stand in here: it does not download, so
// it reports no directory for a module whose source the cache does not
// hold yet.
func moduleDir(t *testing.T, dir, module string) string {
	t.Helper()
	var m struct{ Dir, Error string }
	if err := json.Unmarshal([]byte(goCmd(t, dir, "mod", "download", "-json", module)), &m); err != nil {
		t.Fatalf("go mod download -json %s: %v", module, err)
	}
	if m.Dir == "" {
		t.Fatalf("go mod download -json %s: no module directory (error %q)", module, m.Error)
	}
	return m.Dir
}

// mutantClientModFile copies, from the module cache, the packages of the
// pinned qrysm that the contract tool links, applies the renames (file
// paths relative to the module root) to the copy, and returns a go.mod for
// -modfile that replaces qrysm with the copy. go build -overlay cannot
// stand in here: it refuses to replace files in the module cache.
func mutantClientModFile(t *testing.T, renames []rename) string {
	t.Helper()
	modDir := moduleDir(t, contractDir, qrysmModule)
	pkgDirs := strings.Fields(goCmd(t, contractDir, "list", "-deps", "-f",
		`{{if and .Module (eq .Module.Path "`+qrysmModule+`")}}{{.Dir}}{{end}}`, "."))
	if len(pkgDirs) == 0 {
		t.Fatalf("go list found no packages of %s", qrysmModule)
	}
	tmp := t.TempDir()
	copyDir := filepath.Join(tmp, "qrysm")
	copyFile := func(rel string) {
		data, err := os.ReadFile(filepath.Join(modDir, rel))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(copyDir, filepath.Dir(rel)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(copyDir, rel), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	copyFile("go.mod")
	for _, dir := range pkgDirs {
		rel, err := filepath.Rel(modDir, dir)
		if err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.Type().IsRegular() {
				copyFile(filepath.Join(rel, e.Name()))
			}
		}
	}
	for _, r := range renames {
		r.file = filepath.Join(copyDir, r.file)
		if err := os.WriteFile(r.file, r.apply(t), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"go.mod", "go.sum"} {
		data, err := os.ReadFile(filepath.Join(contractDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tmp, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	modFile := filepath.Join(tmp, "go.mod")
	goCmd(t, contractDir, "mod", "edit", "-replace="+qrysmModule+"="+copyDir, modFile)
	return modFile
}

// wantFailures checks that the contract run failed exactly the checks in
// want, each with an error that contains its substring.
func wantFailures(t *testing.T, code int, out string, want map[string]string) {
	t.Helper()
	if code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if line := fmt.Sprintf("contract: %d passed, %d failed\n", contractChecks-len(want), len(want)); !strings.Contains(out, line) {
		t.Errorf("no %q", line)
	}
	failed := map[string]string{}
	for line := range strings.SplitSeq(out, "\n") {
		if rest, ok := strings.CutPrefix(line, "FAIL: "); ok {
			name, msg, _ := strings.Cut(rest, ": ")
			failed[name] = msg
		}
	}
	for name, sub := range want {
		msg, ok := failed[name]
		if !ok {
			t.Errorf("check %q did not fail", name)
		} else if !strings.Contains(msg, sub) {
			t.Errorf("check %q failed with %q, want it to mention %s", name, msg, sub)
		}
	}
	for name := range failed {
		if _, ok := want[name]; !ok {
			t.Errorf("check %q failed too", name)
		}
	}
}

// A deliberate DTO rename fails vectorgen contract (PLAN S3b acceptance),
// on either side of the contract. Each subtest builds a mutant in a
// temporary directory instead of a broken branch:
//
//   - signer side (go build -overlay): the binary renames the
//     AGGREGATION_SLOT payload key it decodes and the reveal key it answers
//     with, so the signer refuses the client's aggregation_slot body (400)
//     and the client's strict decoder refuses the signer's reveal;
//   - client side (a renamed copy of the pinned qrysm, through -modfile):
//     qrysm's keymanager renames the VOLUNTARY_EXIT payload key it sends and
//     the selection_proof_mode capabilities field it reads, so the signer
//     refuses the exit body (400) and the client refuses the capabilities.
//
// Every other check still passes, so each rename fails exactly the checks it
// concerns.
func TestVectorgenContractCatchesDTORenames(t *testing.T) {
	skipUnlessContract(t)
	n := contractNetworks(t)[0]

	t.Run("signer side", func(t *testing.T) {
		overlay := writeOverlay(t, []rename{
			{"../../internal/consensus/types/request.go",
				`{signingroot.AggregationSlot, "aggregation_slot",`, `{signingroot.AggregationSlot, "aggregationSlot",`},
			{"../../internal/api/consensus/randao.go", `{"randao_reveal":"0x`, `{"reveal":"0x`},
		})
		mutant := filepath.Join(t.TempDir(), "remotesigner")
		goCmd(t, ".", "build", "-overlay", overlay, "-o", mutant, "../../cmd/remotesigner")
		s := startForContract(t, mutant, n)
		code, out := runContractTool(t, buildContract(t), s, n.ConfigName)
		wantFailures(t, code, out, map[string]string{
			"sign slot (AGGREGATION_SLOT)": "status 400, reason UNKNOWN_FIELD",
			"randao reveal":                `unknown field "reveal"`,
		})
	})

	t.Run("client side", func(t *testing.T) {
		const km = "validator/keymanager/remote-web3signer"
		modFile := mutantClientModFile(t, []rename{
			{km + "/v1/web3signer_types.go", "`json:\"voluntary_exit\"`", "`json:\"exit\"`"},
			{km + "/internal/client.go", "`json:\"selection_proof_mode\"`", "`json:\"selection_proof\"`"},
		})
		s := startForContract(t, binary, n)
		code, out := runContractTool(t, buildContract(t, "-modfile="+modFile), s, n.ConfigName)
		wantFailures(t, code, out, map[string]string{
			"capabilities":               `unknown field "selection_proof_mode"`,
			"sign exit (VOLUNTARY_EXIT)": "status 400, reason UNKNOWN_FIELD",
		})
	})
}

// moduleDir works on a cold module cache, so the client-side subtest of
// TestVectorgenContractCatchesDTORenames does not rely on an earlier build
// having extracted qrysm (it used to fail when run alone on a fresh cache).
// The module here is json-iterator, which the contract tool's go.mod
// replaces as it does qrysm but which is far smaller to fetch.
func TestVectorgenContractModuleDirOnColdCache(t *testing.T) {
	skipUnlessContract(t)
	cache := t.TempDir()
	t.Setenv("GOMODCACHE", cache)
	t.Setenv("GOFLAGS", strings.TrimSpace(os.Getenv("GOFLAGS")+" -modcacherw")) // so t.TempDir can remove it
	t.Setenv("GOTOOLCHAIN", "local")                                            // no toolchain download into the empty cache

	dir := moduleDir(t, contractDir, "github.com/json-iterator/go")
	if want := filepath.Join(cache, "github.com", "prestonvanloon", "go@"); !strings.HasPrefix(dir, want) {
		t.Fatalf("module dir %s, want the replacement under %s", dir, want)
	}
	if _, err := os.Stat(filepath.Join(dir, "README.md")); err != nil {
		t.Fatalf("module source not extracted: %v", err)
	}
}
