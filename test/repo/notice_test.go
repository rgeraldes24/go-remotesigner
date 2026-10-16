// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
)

// The NOTICE layout these tests read. Under the "Third-party software in the
// binaries" heading, a line indented by two spaces starts an entry (further
// two-space lines continue its subject), and lines indented by four spaces
// belong to it. The subject starts with the module path, or with "The Go
// standard library", and may name .go files or package directories inside
// the module. A four-space line is a notice line when it is a copyright line
// or an "All rights reserved." line; any other four-space line is a remark.
// Lines "--- <module> NOTICE ---" start the reproduced NOTICE file of that
// module.
const (
	noticePath     = "NOTICE"
	binariesTitle  = "Third-party software in the binaries"
	sourceTitle    = "Third-party code in the source repository only"
	stdSubject     = "The Go standard library"
	noticeFileHead = "--- "
	noticeFileTail = " NOTICE ---"
)

var (
	// copyrightLine is a copyright notice line, not licence prose about
	// copyright or a licence template's "Copyright [yyyy]".
	copyrightLine = regexp.MustCompile(`^Copyright (?:\([cC]\)|©|[0-9])`)
	// goFile is a .go file named in an entry.
	goFile = regexp.MustCompile(`[\w./-]+\.go\b`)
	// repoPath is a path into this repository named in NOTICE prose.
	repoPath = regexp.MustCompile(`\b(?:LICENSES|third_party|internal|cmd|tools|api|docs|testdata)/[\w./-]*`)
)

// noticeTargets are the platforms whose builds NOTICE must cover: the CI and
// release targets and the other main desktop and server systems.
var noticeTargets = [][2]string{
	{"linux", "amd64"}, {"linux", "arm64"}, {"darwin", "amd64"}, {"darwin", "arm64"},
	{"windows", "amd64"}, {"freebsd", "amd64"},
}

// noticeFlavours are the build tags of the two binaries.
var noticeFlavours = []string{"", "noexecution"}

type noticeEntry struct {
	line    int      // line of the subject in NOTICE
	subject string   // the two-space lines, joined with spaces
	notices []string // the notice lines
	remarks []string // the other four-space lines
}

func (e *noticeEntry) std() bool { return strings.HasPrefix(e.subject, stdSubject) }

// tokens returns the words of the subject without surrounding punctuation.
func (e *noticeEntry) tokens() []string {
	var out []string
	for _, f := range strings.Fields(e.subject) {
		if f = strings.Trim(f, ",.;:()"); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// goFiles returns the .go files the entry names, relative to its module.
func (e *noticeEntry) goFiles() []string {
	var out []string
	for _, s := range append([]string{e.subject}, e.remarks...) {
		out = append(out, goFile.FindAllString(s, -1)...)
	}
	return out
}

func isNoticeLine(s string) bool {
	return copyrightLine.MatchString(s) || strings.EqualFold(s, "All rights reserved.")
}

// notice is NOTICE as the tests read it.
type notice struct {
	entries []*noticeEntry
	files   map[string][]string // module path -> lines of its reproduced NOTICE file
	prose   []string            // the unindented lines
}

func parseNotice(text string) (*notice, error) {
	n := &notice{files: map[string][]string{}}
	var (
		section string // "", binariesTitle or sourceTitle
		entry   *noticeEntry
		file    string // module whose NOTICE file is being read
		inEntry bool   // the previous line was part of an entry
	)
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	for i, line := range lines {
		switch {
		case line == binariesTitle || line == sourceTitle:
			section, file, inEntry = line, "", false
			continue
		case section == binariesTitle && strings.HasPrefix(line, noticeFileHead) && strings.HasSuffix(line, noticeFileTail):
			file = strings.TrimSuffix(strings.TrimPrefix(line, noticeFileHead), noticeFileTail)
			if _, dup := n.files[file]; dup {
				return nil, fmt.Errorf("line %d: second NOTICE file for %s", i+1, file)
			}
			n.files[file] = nil
			continue
		case file != "":
			n.files[file] = append(n.files[file], line)
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		body := strings.TrimSpace(line)
		switch {
		case body == "":
			inEntry = false
		case indent == 0:
			n.prose = append(n.prose, line)
			inEntry = false
		case section != binariesTitle:
			return nil, fmt.Errorf("line %d: indented line outside the binaries list", i+1)
		case indent == 2:
			if inEntry && len(entry.notices)+len(entry.remarks) == 0 {
				entry.subject += " " + body
			} else {
				entry = &noticeEntry{line: i + 1, subject: body}
				n.entries = append(n.entries, entry)
			}
			inEntry = true
		case indent == 4 && inEntry:
			if isNoticeLine(body) {
				entry.notices = append(entry.notices, body)
			} else {
				entry.remarks = append(entry.remarks, body)
			}
		default:
			return nil, fmt.Errorf("line %d: indented by %d spaces, want 2 (an entry) or 4 (its notice)", i+1, indent)
		}
	}
	if len(n.entries) == 0 {
		return nil, fmt.Errorf("no entries under %q", binariesTitle)
	}
	return n, nil
}

func readNotice(t *testing.T) *notice {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, noticePath))
	if err != nil {
		t.Fatal(err)
	}
	n, err := parseNotice(string(b))
	if err != nil {
		t.Fatalf("%s: %v", noticePath, err)
	}
	return n
}

// linkSet is what the binaries link, over noticeTargets and noticeFlavours.
type linkSet struct {
	modules  map[string]string // module path -> source directory
	vendored map[string]bool   // golang.org/x modules vendored into the standard library
	goroot   string
}

var (
	linkOnce sync.Once
	linked   linkSet
	linkErr  error
)

func goList(goos, goarch, tags string) (string, error) {
	args := []string{"list", "-deps", "-f",
		"{{if .Module}}{{if not .Module.Main}}module\t{{.Module.Path}}\t{{.Module.Dir}}{{end}}" +
			"{{else if .Standard}}std\t{{.ImportPath}}{{end}}"}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	cmd := exec.Command("go", append(args, "./cmd/remotesigner")...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			err = fmt.Errorf("%w: %s", err, ee.Stderr)
		}
		return "", fmt.Errorf("go list for %s/%s, tags %q: %w", goos, goarch, tags, err)
	}
	return string(out), nil
}

func linkedSet(t *testing.T) linkSet {
	t.Helper()
	linkOnce.Do(func() {
		linked = linkSet{modules: map[string]string{}, vendored: map[string]bool{}}
		var (
			mu   sync.Mutex
			wg   sync.WaitGroup
			errs []error
		)
		for _, tg := range noticeTargets {
			for _, tags := range noticeFlavours {
				wg.Add(1)
				go func() {
					defer wg.Done()
					out, err := goList(tg[0], tg[1], tags)
					mu.Lock()
					defer mu.Unlock()
					if err != nil {
						errs = append(errs, err)
						return
					}
					for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
						f := strings.Split(line, "\t")
						switch {
						case f[0] == "module" && len(f) == 3:
							linked.modules[f[1]] = f[2]
						case f[0] == "std" && strings.HasPrefix(f[1], "vendor/golang.org/x/"):
							name := strings.SplitN(strings.TrimPrefix(f[1], "vendor/golang.org/x/"), "/", 2)[0]
							linked.vendored["golang.org/x/"+name] = true
						}
					}
				}()
			}
		}
		wg.Wait()
		if len(errs) > 0 {
			linkErr = errs[0]
			return
		}
		out, err := exec.Command("go", "env", "GOROOT").Output()
		if err != nil {
			linkErr = fmt.Errorf("go env GOROOT: %w", err)
			return
		}
		linked.goroot = strings.TrimSpace(string(out))
		for m, dir := range linked.modules {
			if dir == "" {
				linkErr = fmt.Errorf("module %s has no source directory; run go mod download", m)
				return
			}
		}
	})
	if linkErr != nil {
		t.Fatal(linkErr)
	}
	return linked
}

// sourceLine normalises a line of a licence or source file: indentation, a
// comment or quote marker and trailing space are dropped.
func sourceLine(s string) string {
	s = strings.TrimSpace(s)
	for _, m := range []string{"//", "/*", "#", ">", "*"} {
		if strings.HasPrefix(s, m) {
			s = strings.TrimSpace(s[len(m):])
			break
		}
	}
	return s
}

// readLines returns the normalised lines of the file at p, at most max lines
// (all of them when max is 0).
func readLines(p string, max int) ([]string, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() && (max == 0 || len(out) < max) {
		out = append(out, sourceLine(sc.Text()))
	}
	return out, sc.Err()
}

// isLicenceFile reports whether name is a licence or notice file.
func isLicenceFile(name string) bool {
	u := strings.ToUpper(name)
	return strings.HasPrefix(u, "LICENSE") || strings.HasPrefix(u, "LICENCE") || strings.HasPrefix(u, "COPYING") ||
		strings.HasPrefix(u, "NOTICE")
}

// licenceFiles returns the licence and notice files directly in dir.
func licenceFiles(dir string) []string {
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, de := range des {
		if !de.IsDir() && isLicenceFile(de.Name()) {
			out = append(out, filepath.Join(dir, de.Name()))
		}
	}
	return out
}

// headerLines is how much of a named .go file is read for its copyright
// lines: the licence header at its top.
const headerLines = 40

// entrySources returns, for an entry, the source directories of its modules
// and the files its notice lines must come from: the licence files of each
// module's root, the licence files of every directory on the way to a path
// the subject names, and the named .go files.
func entrySources(t *testing.T, e *noticeEntry, ls linkSet) (dirs, files, named []string) {
	t.Helper()
	if e.std() {
		return []string{ls.goroot}, []string{filepath.Join(ls.goroot, "LICENSE")}, nil
	}
	for _, tok := range e.tokens() {
		if dir, ok := ls.modules[tok]; ok {
			dirs = append(dirs, dir)
		}
	}
	for _, dir := range dirs {
		files = append(files, licenceFiles(dir)...)
		for _, tok := range append(e.tokens(), e.goFiles()...) {
			if !strings.Contains(tok, "/") {
				continue
			}
			for d := path.Dir(tok); d != "." && d != "/"; d = path.Dir(d) {
				files = append(files, licenceFiles(filepath.Join(dir, filepath.FromSlash(d)))...)
			}
			if fi, err := os.Stat(filepath.Join(dir, filepath.FromSlash(tok))); err == nil && fi.IsDir() {
				files = append(files, licenceFiles(filepath.Join(dir, filepath.FromSlash(tok)))...)
			}
		}
		for _, g := range e.goFiles() {
			if p := filepath.Join(dir, filepath.FromSlash(g)); fileExists(p) {
				named = append(named, p)
			}
		}
	}
	slices.Sort(files)
	return dirs, slices.Compact(files), named
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// TestNoticeCoversLinkedModules checks that NOTICE names every module either
// binary links on any of noticeTargets, every golang.org/x module vendored
// into the standard library they link, and no module they do not link.
func TestNoticeCoversLinkedModules(t *testing.T) {
	n, ls := readNotice(t), linkedSet(t)
	named := map[string]bool{}
	var std *noticeEntry
	for _, e := range n.entries {
		if e.std() {
			std = e
			continue
		}
		toks := e.tokens()
		if _, ok := ls.modules[toks[0]]; !ok {
			t.Errorf("NOTICE:%d: %s is not linked into either binary on any target", e.line, toks[0])
		}
		for _, tok := range toks {
			named[tok] = true
		}
	}
	for m := range ls.modules {
		if !named[m] {
			t.Errorf("NOTICE does not name %s, which the binaries link", m)
		}
	}
	if std == nil {
		t.Fatalf("NOTICE has no %q entry", stdSubject)
	}
	for m := range ls.vendored {
		if !slices.Contains(std.tokens(), m) {
			t.Errorf("NOTICE:%d: the standard library entry does not name %s, whose packages are vendored into "+
				"the standard library the binaries link", std.line, m)
		}
	}
}

// TestNoticeLinesAreVerbatim checks that every notice line of an entry is
// copied verbatim from the component's licence or named file: a copyright
// line, with the "All rights reserved." lines that follow it, appears there
// as the same consecutive lines. A copyright notice inside a remark cannot
// be checked, so it fails too.
func TestNoticeLinesAreVerbatim(t *testing.T) {
	n, ls := readNotice(t), linkedSet(t)
	for _, e := range n.entries {
		for _, r := range e.remarks {
			if strings.Contains(r, "Copyright ") {
				t.Errorf("NOTICE:%d (%s): %q: a copyright notice starts its own line", e.line, e.subject, r)
			}
		}
		dirs, files, named := entrySources(t, e, ls)
		if len(dirs) == 0 {
			continue // reported by TestNoticeCoversLinkedModules
		}
		var sources [][]string
		for _, p := range append(files, named...) {
			lines, err := readLines(p, 0)
			if err != nil {
				t.Fatal(err)
			}
			sources = append(sources, lines)
		}
		for i := 0; i < len(e.notices); {
			block := []string{e.notices[i]}
			for i++; i < len(e.notices) && !copyrightLine.MatchString(e.notices[i]); i++ {
				block = append(block, e.notices[i])
			}
			if !copyrightLine.MatchString(block[0]) {
				t.Errorf("NOTICE:%d: %q does not follow a copyright line", e.line, block[0])
				continue
			}
			if !slices.ContainsFunc(sources, func(src []string) bool { return containsRun(src, block) }) {
				t.Errorf("NOTICE:%d (%s): %q is not verbatim in its licence or named files", e.line, e.subject,
					strings.Join(block, " / "))
			}
		}
	}
}

// containsRun reports whether lines holds run as consecutive lines.
func containsRun(lines, run []string) bool {
	for i := 0; i+len(run) <= len(lines); i++ {
		if slices.Equal(lines[i:i+len(run)], run) {
			return true
		}
	}
	return false
}

// TestNoticeHasEveryCopyrightLine checks the other direction: every
// copyright line in the root licence file of a linked module is in NOTICE,
// and every copyright line in the header of a .go file an entry names is in
// that entry.
func TestNoticeHasEveryCopyrightLine(t *testing.T) {
	n, ls := readNotice(t), linkedSet(t)
	inNotice := map[string]map[string]bool{} // module path -> its notice lines
	add := func(m string, lines []string) {
		if inNotice[m] == nil {
			inNotice[m] = map[string]bool{}
		}
		for _, l := range lines {
			inNotice[m][l] = true
		}
	}
	for _, e := range n.entries {
		if e.std() {
			add("std", e.notices)
		}
		for _, tok := range e.tokens() {
			add(tok, e.notices)
		}
		_, _, named := entrySources(t, e, ls)
		for _, p := range named {
			lines, err := readLines(p, headerLines)
			if err != nil {
				t.Fatal(err)
			}
			for _, l := range lines {
				if copyrightLine.MatchString(l) && !slices.Contains(e.notices, l) {
					t.Errorf("NOTICE:%d (%s): %s has %q, which the entry does not carry", e.line, e.subject,
						filepath.Base(p), l)
				}
			}
		}
	}
	for m, lines := range n.files {
		add(m, lines)
	}
	check := func(m string, files []string) {
		for _, p := range files {
			if strings.HasPrefix(strings.ToUpper(filepath.Base(p)), "NOTICE") {
				continue // TestNoticeReproducesNoticeFiles compares those whole
			}
			lines, err := readLines(p, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, l := range lines {
				if copyrightLine.MatchString(l) && !inNotice[m][l] {
					t.Errorf("NOTICE does not carry %q from %s of %s", l, filepath.Base(p), m)
				}
			}
		}
	}
	check("std", []string{filepath.Join(ls.goroot, "LICENSE")})
	for m, dir := range ls.modules {
		check(m, licenceFiles(dir))
	}
}

// TestNoticeReproducesNoticeFiles checks that the NOTICE file of every
// linked module that has one is reproduced verbatim, and nothing else is.
func TestNoticeReproducesNoticeFiles(t *testing.T) {
	n, ls := readNotice(t), linkedSet(t)
	trim := func(lines []string) []string {
		out := make([]string, len(lines))
		for i, l := range lines {
			out[i] = strings.TrimRight(l, " \t\r")
		}
		for len(out) > 0 && out[0] == "" {
			out = out[1:]
		}
		for len(out) > 0 && out[len(out)-1] == "" {
			out = out[:len(out)-1]
		}
		return out
	}
	want := map[string]bool{}
	for m, dir := range ls.modules {
		p := filepath.Join(dir, "NOTICE")
		if !fileExists(p) {
			continue
		}
		want[m] = true
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := n.files[m]
		if !ok {
			t.Errorf("NOTICE does not reproduce the NOTICE file of %s", m)
			continue
		}
		if !slices.Equal(trim(got), trim(strings.Split(string(b), "\n"))) {
			t.Errorf("NOTICE: the reproduced NOTICE file of %s differs from %s", m, p)
		}
	}
	for m := range n.files {
		if !want[m] {
			t.Errorf("NOTICE reproduces a NOTICE file for %s, which is not linked or has none", m)
		}
	}
}

// TestNoticePathsExist checks that every repository path NOTICE's prose
// names exists, so NOTICE never describes code that is not in the tree.
func TestNoticePathsExist(t *testing.T) {
	n := readNotice(t)
	for _, line := range n.prose {
		for _, p := range repoPath.FindAllString(line, -1) {
			p = strings.TrimRight(p, ".")
			if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(p))); err != nil {
				t.Errorf("NOTICE names %s, which is not in the repository: %v", p, err)
			}
		}
	}
}

func TestParseNotice(t *testing.T) {
	const text = "intro\n\n" + binariesTitle + "\n---\n\nMIT License:\n\n" +
		"  example.com/a, the files (x.go,\n  y.go)\n    Copyright (c) 2020 A\n    All rights reserved.\n" +
		"    z.go is derived from elsewhere,\n" +
		"  example.com/b\n  example.com/c\n    Their notices follow.\n\n" +
		"--- example.com/b NOTICE ---\nB\n\nCopyright 2019 B\n\n" +
		sourceTitle + "\n---\n\nthird_party/x/ is a copy.\n"
	n, err := parseNotice(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(n.entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(n.entries))
	}
	a, bc := n.entries[0], n.entries[1]
	if a.subject != "example.com/a, the files (x.go, y.go)" ||
		!slices.Equal(a.notices, []string{"Copyright (c) 2020 A", "All rights reserved."}) ||
		!slices.Equal(a.goFiles(), []string{"x.go", "y.go", "z.go"}) {
		t.Errorf("entry a = %+v, files %q", a, a.goFiles())
	}
	if !slices.Equal(bc.tokens(), []string{"example.com/b", "example.com/c"}) || len(bc.notices) != 0 {
		t.Errorf("entry b, c = %+v", bc)
	}
	if got := n.files["example.com/b"]; !slices.Equal(got, []string{"B", "", "Copyright 2019 B", ""}) {
		t.Errorf("NOTICE file of b = %q", got)
	}
	if !slices.Contains(n.prose, "third_party/x/ is a copy.") {
		t.Errorf("prose = %q", n.prose)
	}
	for _, bad := range []string{
		binariesTitle + "\n   three spaces\n",
		binariesTitle + "\n    a notice before any entry\n",
		sourceTitle + "\n  indented\n",
	} {
		if _, err := parseNotice(bad); err == nil {
			t.Errorf("parseNotice(%q) succeeded", bad)
		}
	}
}
