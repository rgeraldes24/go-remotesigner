// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package release checks what a release ships, outside the Go build: the
// archives and images of the release dry run (TestRelease, `make
// release-check`) and the image's real entrypoint in Docker (TestDockerSmoke,
// `make docker-smoke`). Both need artefacts or a Docker daemon and are
// skipped unless their environment variable names them.
package release

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// root is the repository root, relative to this package.
const root = "../.."

// Flavour names, as .goreleaser.yaml and tools/releasedocs name them.
const (
	fullFlavour      = "remotesigner"
	consensusFlavour = "remotesigner-consensus"
)

var flavours = []string{fullFlavour, consensusFlavour}

// nonroot is the image's user: distroless's nonroot user and group.
const nonroot = "65532:65532"

// entrypoint is the image's entrypoint, exactly.
var entrypoint = []string{"/usr/local/bin/remotesigner", "--data-path=/data", "--http-listen-host=0.0.0.0",
	"--tls-generate-self-signed"}

// plaintextOverride matches the plaintext-token override in any of its
// spellings: the flag, its environment variable and its config-file key.
var plaintextOverride = regexp.MustCompile(`(?i)allow[-_]plaintext[-_]token[-_]auth`)

// executionOnlyTexts are the LICENSES/ texts that only the default flavour
// may ship (with execution mode).
var executionOnlyTexts = []string{"GPL-3.0-or-later.txt", "LGPL-3.0-or-later.txt"}

// lgpl matches a NOTICE that mentions the LGPL.
var lgpl = regexp.MustCompile(`(?i)LGPL|Lesser General Public`)

// readRepo returns the content of a repository file.
func readRepo(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// releaseDocs are the licence files a flavour must ship.
type releaseDocs struct {
	license []byte
	notice  []byte
	texts   map[string][]byte // LICENSES/ by name
}

// wantDocs returns the licence files the flavour must ship, from the
// repository: LICENSE; NOTICE, followed in the default flavour by
// NOTICE.execution when the repository has that fragment; and the LICENSES/
// texts, without the GPL and LGPL texts in the consensus flavour.
func wantDocs(t *testing.T, flavour string) releaseDocs {
	t.Helper()
	d := releaseDocs{license: readRepo(t, "LICENSE"), notice: readRepo(t, "NOTICE"), texts: map[string][]byte{}}
	if flavour == fullFlavour {
		fragment, err := os.ReadFile(filepath.Join(root, "NOTICE.execution"))
		switch {
		case err == nil:
			var b bytes.Buffer
			b.Write(d.notice)
			if !bytes.HasSuffix(d.notice, []byte("\n")) {
				b.WriteByte('\n')
			}
			b.WriteByte('\n')
			b.Write(fragment)
			d.notice = b.Bytes()
		case !errors.Is(err, os.ErrNotExist):
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(root, "LICENSES"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.Type().IsRegular() || (flavour != fullFlavour && slices.Contains(executionOnlyTexts, e.Name())) {
			continue
		}
		d.texts[e.Name()] = readRepo(t, "LICENSES/"+e.Name())
	}
	return d
}

// tarFile is one regular file or directory of a tar stream.
type tarFile struct {
	hdr  *tar.Header
	data []byte
}

// readTar returns the entries of a tar stream by slash-separated name,
// with the first strip path elements removed (entries that have no more
// are dropped).
func readTar(r io.Reader, strip int) (map[string]tarFile, error) {
	out := map[string]tarFile{}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		parts := strings.Split(strings.Trim(path.Clean(hdr.Name), "/"), "/")
		if len(parts) <= strip {
			continue
		}
		name := strings.Join(parts[strip:], "/")
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		out[name] = tarFile{hdr: hdr, data: data}
	}
}

// qrllibLicense is the licence file go-licenses save writes for go-qrllib,
// which both flavours link.
const qrllibLicense = "third_party_licenses/github.com/theQRL/go-qrllib/LICENSE"

// licenceProblems returns what files, a release's tree, lacks for the
// flavour: LICENSE, the flavour's NOTICE (without any LGPL mention in the
// consensus flavour), exactly the flavour's LICENSES/ texts, and the
// third-party licence files of go-licenses save.
func licenceProblems(flavour string, want releaseDocs, files map[string]tarFile) []string {
	var p []string
	if f, ok := files["LICENSE"]; !ok || !bytes.Equal(f.data, want.license) {
		p = append(p, "LICENSE missing or not the repository's")
	}
	notice, ok := files["NOTICE"]
	switch {
	case !ok:
		p = append(p, "NOTICE missing")
	case flavour == consensusFlavour && lgpl.Match(notice.data):
		p = append(p, "the consensus flavour's NOTICE mentions the LGPL")
	case !bytes.Equal(notice.data, want.notice):
		p = append(p, "NOTICE is not the "+flavour+" flavour's NOTICE")
	}
	var got []string
	for name, f := range files {
		if rest, ok := strings.CutPrefix(name, "LICENSES/"); ok && f.hdr.Typeflag == tar.TypeReg {
			got = append(got, rest)
			if w, ok := want.texts[rest]; !ok || !bytes.Equal(f.data, w) {
				p = append(p, "LICENSES/"+rest+" is not one of the "+flavour+" flavour's licence texts")
			}
		}
	}
	for name := range want.texts {
		if !slices.Contains(got, name) {
			p = append(p, "LICENSES/"+name+" missing")
		}
	}
	if _, ok := files[qrllibLicense]; !ok {
		p = append(p, "third_party_licenses/ lacks go-qrllib's LICENSE")
	}
	slices.Sort(p)
	return p
}

// checkLicenceFiles reports licenceProblems as test errors.
func checkLicenceFiles(t *testing.T, flavour string, files map[string]tarFile) {
	t.Helper()
	for _, p := range licenceProblems(flavour, wantDocs(t, flavour), files) {
		t.Error(p)
	}
}

// buildInfo is what `go version -m` reports about a binary.
type buildInfo struct {
	deps     []string          // module paths
	settings map[string]string // build settings
}

// parseGoVersionM parses the output of `go version -m`.
func parseGoVersionM(out string) buildInfo {
	bi := buildInfo{settings: map[string]string{}}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimSpace(line), "\t")
		switch {
		case len(f) >= 2 && f[0] == "dep":
			bi.deps = append(bi.deps, f[1])
		case len(f) >= 2 && f[0] == "build":
			k, v, _ := strings.Cut(f[1], "=")
			bi.settings[k] = v
		}
	}
	return bi
}

// goQRL is the LGPL module only the default flavour may link (with
// execution mode). go-qrllib is another module.
const goQRL = "github.com/theQRL/go-qrl"

// buildProblems returns what is wrong with the build of a flavour's binary:
// it must be static and trimmed, and the consensus flavour built with
// noexecution and linking no go-qrl module.
func buildProblems(flavour string, bi buildInfo) []string {
	var p []string
	if bi.settings["CGO_ENABLED"] != "0" || bi.settings["-trimpath"] != "true" {
		p = append(p, fmt.Sprintf("CGO_ENABLED=%q -trimpath=%q, want a static, trimmed build",
			bi.settings["CGO_ENABLED"], bi.settings["-trimpath"]))
	}
	noexecution := slices.Contains(strings.Split(bi.settings["-tags"], ","), "noexecution")
	switch {
	case flavour == consensusFlavour && !noexecution:
		p = append(p, fmt.Sprintf("built with -tags=%q, want noexecution", bi.settings["-tags"]))
	case flavour == fullFlavour && noexecution:
		p = append(p, "the default flavour is built with noexecution")
	}
	if flavour == consensusFlavour && slices.Contains(bi.deps, goQRL) {
		p = append(p, "go version -m lists "+goQRL)
	}
	return p
}

// checkBinary runs `go version -m` on the flavour's binary at p and reports
// buildProblems as test errors.
func checkBinary(t *testing.T, flavour, p string) {
	t.Helper()
	out, err := exec.Command("go", "version", "-m", p).CombinedOutput()
	if err != nil {
		t.Fatalf("go version -m %s: %v: %s", p, err, out)
	}
	for _, msg := range buildProblems(flavour, parseGoVersionM(string(out))) {
		t.Errorf("%s: %s", p, msg)
	}
}

// writeTemp writes data to a new file in a test directory and returns its
// path.
func writeTemp(t *testing.T, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// dockerTimeout bounds one docker command.
const dockerTimeout = 5 * time.Minute

// dockerRun runs the docker CLI and returns its standard output, standard
// error and exit code; err is set only when docker could not run.
func dockerRun(args ...string) (stdout, stderr string, code int, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dockerTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err = cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return o.String(), e.String(), exit.ExitCode(), nil
	}
	if err != nil {
		return o.String(), e.String(), -1, fmt.Errorf("docker %s: %w", strings.Join(args, " "), err)
	}
	return o.String(), e.String(), 0, nil
}

// docker runs the docker CLI, fails the test unless it exits 0, and returns
// its standard output.
func docker(t *testing.T, args ...string) string {
	t.Helper()
	out, errOut, code, err := dockerRun(args...)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("docker %s: exit %d: %s%s", strings.Join(args, " "), code, out, errOut)
	}
	return out
}

// dockerTar runs a docker command that writes a tar stream (docker cp …
// -) and returns its entries.
func dockerTar(t *testing.T, strip int, args ...string) map[string]tarFile {
	t.Helper()
	files, err := readTar(strings.NewReader(docker(t, args...)), strip)
	if err != nil {
		t.Fatalf("docker %s: %v", strings.Join(args, " "), err)
	}
	return files
}

// requireDocker fails the test when no Docker daemon answers: the tests
// that call it run only when their environment variable asks for them.
func requireDocker(t *testing.T) {
	t.Helper()
	out, errOut, code, err := dockerRun("version", "--format", "{{.Server.Version}}")
	if err != nil || code != 0 {
		t.Fatalf("no Docker daemon answers: %v %s%s", err, out, errOut)
	}
}
