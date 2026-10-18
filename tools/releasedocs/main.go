// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Command releasedocs assembles the licence files that each release flavour
// ships in its archives and its image.
//
// For each flavour it writes <out>/<flavour>/ with:
//
//   - LICENSE and README.md, copied from the repository;
//   - NOTICE: the repository's NOTICE. The default flavour appends
//     NOTICE.execution when the repository has one: that fragment holds the
//     notices of the execution mode, which the consensus flavour never links;
//   - LICENSES/: the generic licence texts, without the GPL and LGPL texts in
//     the consensus flavour, which links permissively licensed code only. A
//     GNU GPL, LGPL or AGPL text that executionOnly does not list, found by
//     its file name or its title line, is an error rather than shipped in
//     the consensus flavour;
//   - third_party_licenses/: `go-licenses save` of the flavour's binary, each
//     linked module's own licence and notice files;
//
// and <out>/<flavour>.licenses, the SPDX expression of the licences the
// binary links (from `go-licenses report`), which the image carries in its
// org.opencontainers.image.licenses label.
//
// go-licenses runs for linux/amd64: the release images are linux, and the
// linux builds link a superset of the darwin builds' modules
// (github.com/prometheus/procfs is linux only). It runs with GOROOT set to
// the toolchain the module selects, so that a go-licenses built with another
// Go release still recognises the standard library.
//
// Usage:
//
//	go run ./tools/releasedocs [-root .] [-out build/release] [-go-licenses go-licenses]
package main

import (
	"bytes"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// flavour is one release flavour: a binary built from mainPkg with tags.
type flavour struct {
	name string // the binary's name
	tags string // build tags
	// execution is set for the flavour that carries execution mode, and with
	// it the notices and licence texts of the code that mode links.
	execution bool
}

// flavours are the release flavours, as .goreleaser.yaml builds them.
var flavours = []flavour{
	{name: "remotesigner", execution: true},
	{name: "remotesigner-consensus", tags: "noexecution"},
}

const (
	mainPkg = "./cmd/remotesigner"
	module  = "github.com/rgeraldes24/go-remotesigner"
	// ownLicence is the licence of this module's own code.
	ownLicence = "Apache-2.0"
	// executionNotice is the NOTICE fragment only the execution flavour
	// ships.
	executionNotice = "NOTICE.execution"
)

// executionOnly are the LICENSES/ texts that only the execution flavour
// ships: the texts of the LGPL code execution mode links and of the GPL it
// refers to.
var executionOnly = []string{"GPL-3.0-or-later.txt", "LGPL-3.0-or-later.txt"}

var (
	// gnuName matches the file name of a GNU GPL, LGPL or AGPL text.
	gnuName = regexp.MustCompile(`(?i)gpl`)
	// gnuTitle matches the title line of a GNU GPL, LGPL (or Library GPL) or
	// AGPL text. Permissive texts that mention these licences (MPL-2.0's
	// Secondary Licenses) do not write it in capitals.
	gnuTitle = regexp.MustCompile(`GNU (?:LESSER |LIBRARY |AFFERO )?GENERAL PUBLIC LICENSE`)
)

func main() {
	root := flag.String("root", ".", "repository root")
	out := flag.String("out", "build/release", "output directory; replaced")
	goLicenses := flag.String("go-licenses", "go-licenses", "the go-licenses command")
	flag.Parse()
	if err := run(*root, *out, *goLicenses); err != nil {
		fmt.Fprintln(os.Stderr, "releasedocs:", err)
		os.Exit(1)
	}
}

func run(root, out, goLicenses string) error {
	goroot, err := goEnv(root, "GOROOT")
	if err != nil {
		return err
	}
	if err := os.RemoveAll(out); err != nil {
		return err
	}
	for _, f := range flavours {
		dir := filepath.Join(out, f.name)
		if err := assemble(root, dir, f); err != nil {
			return fmt.Errorf("%s: %w", f.name, err)
		}
		tl := goLicensesTool{bin: goLicenses, root: root, goroot: goroot}
		save, err := filepath.Abs(filepath.Join(dir, "third_party_licenses"))
		if err != nil {
			return err
		}
		if _, err := tl.run(f, "save", mainPkg, "--save_path", save, "--ignore", module); err != nil {
			return fmt.Errorf("%s: go-licenses save: %w", f.name, err)
		}
		report, err := tl.run(f, "report", mainPkg)
		if err != nil {
			return fmt.Errorf("%s: go-licenses report: %w", f.name, err)
		}
		expr, err := spdxExpression(report)
		if err != nil {
			return fmt.Errorf("%s: %w", f.name, err)
		}
		if err := os.WriteFile(filepath.Join(out, f.name+".licenses"), []byte(expr+"\n"), 0o644); err != nil {
			return err
		}
		fmt.Printf("%s: %s\n", f.name, expr)
	}
	return nil
}

// assemble writes the repository's licence files for flavour f into dir:
// LICENSE, README.md, NOTICE and LICENSES/.
func assemble(root, dir string, f flavour) error {
	if err := os.MkdirAll(filepath.Join(dir, "LICENSES"), 0o755); err != nil {
		return err
	}
	for _, name := range []string{"LICENSE", "README.md"} {
		if err := copyFile(filepath.Join(root, name), filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	notice, err := noticeFor(root, f)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "NOTICE"), notice, 0o644); err != nil {
		return err
	}
	texts, err := licenseTexts(root, f)
	if err != nil {
		return err
	}
	for _, name := range texts {
		if err := copyFile(filepath.Join(root, "LICENSES", name), filepath.Join(dir, "LICENSES", name)); err != nil {
			return err
		}
	}
	return nil
}

// noticeFor returns the NOTICE flavour f ships: the repository's NOTICE,
// followed in the execution flavour by NOTICE.execution when it exists.
func noticeFor(root string, f flavour) ([]byte, error) {
	notice, err := os.ReadFile(filepath.Join(root, "NOTICE"))
	if err != nil {
		return nil, err
	}
	if !f.execution {
		return notice, nil
	}
	fragment, err := os.ReadFile(filepath.Join(root, executionNotice))
	if errors.Is(err, os.ErrNotExist) {
		return notice, nil
	}
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	b.Write(notice)
	if !bytes.HasSuffix(notice, []byte("\n")) {
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	b.Write(fragment)
	return b.Bytes(), nil
}

// licenseTexts returns the names of the LICENSES/ files flavour f ships, in
// name order. For the consensus flavour, a GNU GPL-family text left after
// the executionOnly texts is an error: listing it is a decision, and
// shipping it would break the flavour's permissive-only promise.
func licenseTexts(root string, f flavour) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(root, "LICENSES"))
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		if !f.execution {
			if slices.Contains(executionOnly, e.Name()) {
				continue
			}
			data, err := os.ReadFile(filepath.Join(root, "LICENSES", e.Name()))
			if err != nil {
				return nil, err
			}
			if gnuName.MatchString(e.Name()) || gnuTitle.Match(data) {
				return nil, fmt.Errorf("LICENSES/%s is a GNU GPL-family text that executionOnly does not list; "+
					"the consensus flavour ships permissive licence texts only", e.Name())
			}
		}
		names = append(names, e.Name())
	}
	return names, nil
}

// spdxExpression returns the SPDX expression of the licences in a
// `go-licenses report` CSV (package, URL, licence per line) together with
// this module's own licence: the distinct licence names in order, joined by
// AND. A package whose licence go-licenses could not identify is an error.
func spdxExpression(report []byte) (string, error) {
	r := csv.NewReader(bytes.NewReader(report))
	r.FieldsPerRecord = 3
	set := map[string]bool{ownLicence: true}
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("go-licenses report: %w", err)
		}
		name := strings.TrimSpace(rec[2])
		if name == "" || strings.EqualFold(name, "Unknown") {
			return "", fmt.Errorf("go-licenses report: %s has no identified licence", rec[0])
		}
		set[name] = true
	}
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	slices.Sort(names)
	return strings.Join(names, " AND "), nil
}

// goLicensesTool runs go-licenses in the repository root.
type goLicensesTool struct {
	bin, root, goroot string
}

// run runs go-licenses with args for flavour f's build (linux/amd64, f's
// tags) and returns its standard output. Its standard error goes to ours.
func (t goLicensesTool) run(f flavour, args ...string) ([]byte, error) {
	cmd := exec.Command(t.bin, args...)
	cmd.Dir = t.root
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOROOT="+t.goroot,
		"GOFLAGS=-tags="+f.tags)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return stdout.Bytes(), nil
}

// goEnv returns `go env name` in dir.
func goEnv(dir, name string) (string, error) {
	cmd := exec.Command("go", "env", name)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("go env %s: %w", name, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// copyFile copies the regular file src to dst with mode 0644.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}
