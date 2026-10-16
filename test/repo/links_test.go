// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode"
)

var (
	// mdLink is an inline Markdown link; group 1 is its target.
	mdLink = regexp.MustCompile(`\]\(([^()\s]+)\)`)
	// mdHeading is an ATX heading; group 1 is its text.
	mdHeading = regexp.MustCompile(`^#{1,6}\s+(.*?)(?:\s+#+)?\s*$`)
	// codeSpan is an inline code span.
	codeSpan = regexp.MustCompile("`[^`]*`")
)

// fence reports whether line opens or closes a fenced code block.
func fence(line string) bool {
	l := strings.TrimSpace(line)
	return strings.HasPrefix(l, "```") || strings.HasPrefix(l, "~~~")
}

// slug is the anchor GitHub gives a heading: lower case, punctuation other
// than '-' and '_' dropped, spaces turned into '-'.
func slug(heading string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(heading) {
		switch {
		case r == ' ':
			b.WriteByte('-')
		case r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r):
			b.WriteRune(r)
		}
	}
	return b.String()
}

// headingAnchors returns the anchors of the headings of a Markdown text,
// numbered as GitHub numbers repeated headings ("x", "x-1", ...).
func headingAnchors(text string) map[string]bool {
	anchors := map[string]bool{}
	seen := map[string]int{}
	inFence := false
	for _, line := range strings.Split(text, "\n") {
		if fence(line) {
			inFence = !inFence
			continue
		}
		m := mdHeading.FindStringSubmatch(line)
		if inFence || m == nil {
			continue
		}
		s := slug(m[1])
		if k := seen[s]; k > 0 {
			anchors[fmt.Sprintf("%s-%d", s, k)] = true
		} else {
			anchors[s] = true
		}
		seen[s]++
	}
	return anchors
}

// mdLinks returns the targets of the inline links of a Markdown text that
// point into the repository, with their line numbers. Links in code are
// left out.
func mdLinks(text string) (targets []string, lines []int) {
	inFence := false
	for i, line := range strings.Split(text, "\n") {
		if fence(line) {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		for _, m := range mdLink.FindAllStringSubmatch(codeSpan.ReplaceAllString(line, ""), -1) {
			if t := m[1]; !strings.Contains(t, "://") && !strings.HasPrefix(t, "mailto:") {
				targets, lines = append(targets, t), append(lines, i+1)
			}
		}
	}
	return targets, lines
}

func TestHeadingAnchors(t *testing.T) {
	text := "# Title\n## 7. Request envelope and validation pipeline\n## 16. Capabilities and `api_version`\n" +
		"```\n# not a heading\n```\n## Notes\n## Notes\n"
	want := []string{"title", "7-request-envelope-and-validation-pipeline", "16-capabilities-and-api_version",
		"notes", "notes-1"}
	got := headingAnchors(text)
	for _, a := range want {
		if !got[a] {
			t.Errorf("anchor %q missing from %v", a, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("anchors = %v, want %v", got, want)
	}
}

// TestMarkdownLinksResolve checks that every relative link of every
// Markdown file names a file or directory of the repository and, for a
// Markdown target, one of its headings.
func TestMarkdownLinksResolve(t *testing.T) {
	files := repoFiles(t)
	md := map[string]string{}
	for _, f := range files {
		if strings.HasSuffix(f.path, ".md") {
			md[f.path] = f.text
		}
	}
	anchors := map[string]map[string]bool{}
	anchorsOf := func(p string) map[string]bool {
		if anchors[p] == nil {
			anchors[p] = headingAnchors(md[p])
		}
		return anchors[p]
	}
	checked, withAnchor := 0, 0
	for p, text := range md {
		targets, lines := mdLinks(text)
		checked += len(targets)
		for i, target := range targets {
			file, anchor, _ := strings.Cut(target, "#")
			dest := p
			if file != "" {
				dest = path.Clean(path.Join(path.Dir(p), file))
				if dest == ".." || strings.HasPrefix(dest, "../") {
					t.Errorf("%s:%d: %s leaves the repository", p, lines[i], target)
					continue
				}
				if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(dest))); err != nil {
					t.Errorf("%s:%d: %s: %v", p, lines[i], target, err)
					continue
				}
			}
			if anchor != "" && strings.HasSuffix(dest, ".md") {
				withAnchor++
				if !anchorsOf(dest)[anchor] {
					t.Errorf("%s:%d: %s: %s has no heading #%s", p, lines[i], target, dest, anchor)
				}
			}
		}
	}
	if checked == 0 || withAnchor == 0 {
		t.Fatalf("found %d links, %d with a heading anchor: the link parser is broken", checked, withAnchor)
	}
	t.Logf("%d links in %d Markdown files, %d with a heading anchor", checked, len(md), withAnchor)
}
