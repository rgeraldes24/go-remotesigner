// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// cloudSDKs are the module path prefixes of the cloud secret stores' SDKs
// and of what only they bring in.
var cloudSDKs = []string{
	"github.com/aws/", "github.com/Azure/", "github.com/AzureAD/", "cloud.google.com/go/", "google.golang.org/api",
	"google.golang.org/grpc",
}

// buildDir holds the two flavours' binaries, built once and removed by
// TestMain.
var (
	buildOnce sync.Once
	buildDir  string
	buildErr  error
)

// flavourBinary builds both flavours as the Makefile does and returns the
// path of the one with tags.
func flavourBinary(t *testing.T, tags string) string {
	t.Helper()
	buildOnce.Do(func() {
		buildDir, buildErr = os.MkdirTemp("", "remotesigner-deps-")
		if buildErr != nil {
			return
		}
		for _, f := range []struct{ name, tags string }{{"remotesigner", ""}, {"remotesigner-consensus", "noexecution"}} {
			cmd := exec.Command("go", "build", "-trimpath", "-tags", f.tags, "-o", filepath.Join(buildDir, f.name),
				"./cmd/remotesigner")
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
			if out, err := cmd.CombinedOutput(); err != nil {
				buildErr = fmt.Errorf("go build -tags %q: %w\n%s", f.tags, err, out)
				return
			}
		}
	})
	if buildErr != nil {
		t.Fatalf("build the binaries: %v", buildErr)
	}
	if tags == "" {
		return filepath.Join(buildDir, "remotesigner")
	}
	return filepath.Join(buildDir, "remotesigner-consensus")
}

func TestMain(m *testing.M) {
	code := m.Run()
	if buildDir != "" {
		_ = os.RemoveAll(buildDir)
	}
	os.Exit(code)
}

// linkedModules returns the dependency modules `go version -m` lists for
// the binary at p.
func linkedModules(t *testing.T, p string) []string {
	t.Helper()
	out, err := exec.Command("go", "version", "-m", p).Output()
	if err != nil {
		t.Fatalf("go version -m %s: %v", p, err)
	}
	var mods []string
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && (f[0] == "dep" || f[0] == "=>") {
			mods = append(mods, f[1])
		}
	}
	if len(mods) == 0 {
		t.Fatalf("go version -m %s lists no modules:\n%s", p, out)
	}
	return mods
}

// deps returns the import paths of every package ./... links in the
// flavour of tags, tests excluded.
func deps(t *testing.T, tags string) []string {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", "-tags", tags, "./...")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps -tags %q: %v", tags, err)
	}
	return strings.Fields(string(out))
}

// TestNoVaultSDKLinked checks that HashiCorp Vault is read through
// Vault's HTTP API, as Web3Signer reads it, and no HashiCorp module (the Vault
// SDK and what it brings in) is in either flavour, by `go list -deps` of
// every package and by `go version -m` of the built binaries.
func TestNoVaultSDKLinked(t *testing.T) {
	for _, tags := range []string{"", "noexecution"} {
		for _, p := range deps(t, tags) {
			if strings.HasPrefix(p, "github.com/hashicorp/") {
				t.Errorf("tags %q: go list -deps lists %s", tags, p)
			}
		}
		for _, m := range linkedModules(t, flavourBinary(t, tags)) {
			if strings.HasPrefix(m, "github.com/hashicorp/") {
				t.Errorf("tags %q: go version -m lists %s", tags, m)
			}
		}
	}
}

// TestCloudSDKsInDefaultFlavourOnly checks that the AWS, Azure and GCP
// SDKs are linked by the default flavour, which reads those stores, and
// not by remotesigner-consensus.
func TestCloudSDKsInDefaultFlavourOnly(t *testing.T) {
	has := func(mods []string, prefix string) bool {
		for _, m := range mods {
			if strings.HasPrefix(m, prefix) {
				return true
			}
		}
		return false
	}
	full := linkedModules(t, flavourBinary(t, ""))
	consensus := linkedModules(t, flavourBinary(t, "noexecution"))
	for _, sdk := range cloudSDKs {
		if !has(full, sdk) {
			t.Errorf("remotesigner links no %s module", sdk)
		}
		if has(consensus, sdk) {
			t.Errorf("remotesigner-consensus links a %s module", sdk)
		}
	}
	for _, p := range deps(t, "noexecution") {
		for _, sdk := range cloudSDKs {
			if strings.HasPrefix(p, sdk) {
				t.Errorf("go list -deps -tags noexecution lists %s", p)
			}
		}
	}
}
