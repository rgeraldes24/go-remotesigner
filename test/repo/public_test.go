// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var (
	// lineBreak is a line break with the indentation and comment or quote
	// marker of the next line, so that wrapped prose reads as one line.
	lineBreak = regexp.MustCompile(`\s*\n\s*(?://+|#+|>|\*)?\s*`)
	// visibility is a statement of visibility, at the end of the text.
	visibility = regexp.MustCompile(`(?i)\b(?:is|are)\s+(?:now\s+)?(?:public|private)$`)
	// repoSubject names the repository (or refers back to it as "it").
	repoSubject = regexp.MustCompile(`(?i)\brepositor(?:y|ies)\b|go-remotesigner|\bit\b`)
	// clauseBreak ends a clause: a punctuation mark, any closing emphasis,
	// bracket or quote, and a space.
	clauseBreak = regexp.MustCompile("[.;:!?][*_)\"'`]*\\s")
	// condition ties a statement to a state of the repository.
	condition = regexp.MustCompile(`(?i)\b(?:once|until|while|when|whenever|after|before|if|unless)\b`)
)

// clauseStart returns the start of the clause that contains offset i: the
// end of the last clause break before it, or 0.
func clauseStart(s string, i int) int {
	start := 0
	for _, m := range clauseBreak.FindAllStringIndex(s[:i], -1) {
		start = m[1]
	}
	return start
}

// visibilityClaims returns the clauses of text that state the repository's
// visibility as a present fact: "is public" or "is private" with the
// repository as subject and no condition such as "once" or "while". The
// repository is developed privately and made public when the user decides,
// and changes may reach main before or after that, so every such statement
// must hold in both states.
func visibilityClaims(text string) []string {
	var claims []string
	lower := strings.ToLower(text)
	for _, word := range []string{"public", "private"} {
		for off := 0; ; {
			i := strings.Index(lower[off:], word)
			if i < 0 {
				break
			}
			end := off + i + len(word)
			off = end
			if end < len(text) && isWordByte(text[end]) {
				continue // "publicly", "privateKey"
			}
			// The clause in front of the word, wrapped prose joined.
			prose := lineBreak.ReplaceAllString(text[max(0, end-clauseWindow):end], " ")
			m := visibility.FindStringIndex(prose)
			if m == nil {
				continue
			}
			clause := prose[clauseStart(prose, m[0]):]
			if repoSubject.MatchString(clause) && !condition.MatchString(clause) {
				claims = append(claims, clause)
			}
		}
	}
	return claims
}

// clauseWindow is how far visibilityClaims looks back for the start of a
// clause.
const clauseWindow = 1000

func isWordByte(c byte) bool {
	return c == '_' || '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

func TestVisibilityClaims(t *testing.T) {
	tests := []struct {
		name, text string
		want       []string
	}{
		{"present fact", "- This repository is public, and qrysm CI fetches the signer",
			[]string{"- This repository is public"}},
		{"named repository", "**Chosen option.** `github.com/rgeraldes24/go-remotesigner` is public. qrysm clones it",
			[]string{"`github.com/rgeraldes24/go-remotesigner` is public"}},
		{"wrapped comment", "The arm64 legs run natively\n// now that the repository\n// is private.",
			[]string{"The arm64 legs run natively now that the repository is private"}},
		{"once", "Fork PRs run every job once the repository is public.", nil},
		{"once it", "Once it is public, qrysm's e2e build clones it anonymously.", nil},
		{"while, wrapped", "# While the repository is private, the arm64 legs\n# run on amd64.", nil},
		{"until", "Until the repository is public, qrysm CI cannot fetch it.", nil},
		{"another subject", "> (d) I understand that this project and the contribution are public and", nil},
		{"not visibility", "The key is private to the signer; the repository is made public later.", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := visibilityClaims(tt.text); !slices.Equal(got, tt.want) {
				t.Fatalf("visibilityClaims = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestPublicationStatementsHoldBothWays fails on any statement that the
// repository is public, or private, as a present fact.
func TestPublicationStatementsHoldBothWays(t *testing.T) {
	for _, f := range repoFiles(t) {
		if ownFile(f.path) {
			continue
		}
		for _, c := range visibilityClaims(f.prose) {
			t.Errorf("%s: %q states the repository's visibility as a fact; describe the choice and when it takes "+
				"effect (\"once the repository is public\") so that it reads correctly before and after the flip",
				f.path, c)
		}
	}
}

// planningRefs are references into the design documents and evidence notes
// the port was planned with. None of them is in the repository, so a reader
// cannot resolve them: a page here states the behaviour instead.
var planningRefs = []struct {
	re   *regexp.Regexp
	what string
}{
	{regexp.MustCompile(`\b(?:CO|CH|OF|SP|QI|CM|L|G[1-6]|DESIGN|PLAN)(?:\.md)? §`), "a section of a planning note"},
	{regexp.MustCompile(`\bG[1-6] [A-Z][0-9]+`), "a scenario of an evidence note"},
	{regexp.MustCompile(`\bS(?:0|[1-9][0-9]?)[a-z]?[0-9]?\b|\bQ[1-4]\b|\bE2E-1\b`), "a milestone or scenario id"},
	{regexp.MustCompile(`\bD(?:[1-9]|[12][0-9])\b`), "a design decision id"},
	{regexp.MustCompile(`(?i)\bwalking skeleton\b|\bmilestones?\b`), "planning vocabulary"},
	{regexp.MustCompile(`\b(?:DESIGN|PLAN|decisions|milestone-followups)\.md\b|\bunderstand/`), "a planning file"},
}

// mayCite is a fast filter for planningRefs: it reports whether line holds
// a "§", "milestone", "skeleton", ".md", "understand/", or an uppercase S,
// Q, D, G or E that starts a word and is followed by a digit. Go's regexp
// is slow on long inputs, so only the lines that pass are matched.
func mayCite(line string) bool {
	if strings.Contains(line, "§") || strings.Contains(line, ".md") || strings.Contains(line, "understand/") {
		return true
	}
	for i := 0; i+1 < len(line); i++ {
		switch c := line[i]; {
		case strings.IndexByte("SQDGE", c) >= 0 && '0' <= line[i+1] && line[i+1] <= '9' &&
			(i == 0 || !isWordByte(line[i-1])):
			return true
		case (c == 'm' || c == 'M') && len(line)-i >= 9 && strings.EqualFold(line[i:i+9], "milestone"),
			(c == 's' || c == 'S') && len(line)-i >= 8 && strings.EqualFold(line[i:i+8], "skeleton"):
			return true
		}
	}
	return false
}

// planningRefsIn returns each planning reference in text, with what it is.
func planningRefsIn(text string) []string {
	var found []string
	for i, line := range strings.Split(text, "\n") {
		if !mayCite(line) {
			continue
		}
		for _, p := range planningRefs {
			for _, m := range p.re.FindAllString(line, -1) {
				found = append(found, fmt.Sprintf("line %d: %q (%s)", i+1, m, p.what))
			}
		}
	}
	return found
}

func TestPlanningRefsIn(t *testing.T) {
	tests := []struct {
		text string
		want int
	}{
		{"// S15: every type at its bound passes", 1},
		{"// S32 (exit gate): VOLUNTARY_EXIT is refused", 1},
		{"content type, body limit (G4 S1, S4, S5).", 4},
		{"(DESIGN §7.5) only ran by hand", 1},
		{"PLAN S5b closes the S4b line", 2},
		{"specified with the keymanager milestone.", 1},
		{"// The walking skeleton signs", 1},
		{"per D27 (QI §2.3)", 2},
		{"see $D/understand/gap-4.md", 1},
		{"Apache-2.0 §4(c); contract §7; SHA-256; ML-DSA-87; B7; X45", 0},
		{"the TLS variant is benchmarked once TLS support lands", 0},
	}
	for _, tt := range tests {
		if got := planningRefsIn(tt.text); len(got) != tt.want {
			t.Errorf("planningRefsIn(%q) = %q, want %d", tt.text, got, tt.want)
		}
	}
}

// TestNoPlanningReferences fails on any reference to the private planning
// notes in a text file of the repository.
func TestNoPlanningReferences(t *testing.T) {
	for _, f := range repoFiles(t) {
		if ownFile(f.path) {
			continue
		}
		for _, r := range planningRefsIn(f.prose) {
			t.Errorf("%s: %s: the planning notes are not in the repository; point at the page that states "+
				"the behaviour, or drop the reference", f.path, r)
		}
	}
}

var (
	benchmarkID  = regexp.MustCompile(`\bB[0-9]{1,2}\b`)
	benchmarkRow = regexp.MustCompile(`(?m)^\| (B[0-9]{1,2}) \|`)
)

// TestBenchmarkIDsAreDefined fails on a benchmark id (B7) that no row of
// docs/benchmarks.md defines.
func TestBenchmarkIDsAreDefined(t *testing.T) {
	files := repoFiles(t)
	i := slices.IndexFunc(files, func(f textFile) bool { return f.path == "docs/benchmarks.md" })
	if i < 0 {
		t.Fatal("docs/benchmarks.md not found")
	}
	defined := map[string]bool{}
	for _, m := range benchmarkRow.FindAllStringSubmatch(files[i].text, -1) {
		defined[m[1]] = true
	}
	if len(defined) == 0 {
		t.Fatal("docs/benchmarks.md defines no benchmark rows")
	}
	for _, f := range files {
		if ownFile(f.path) || !benchmarkID.MatchString(f.prose) {
			continue
		}
		for n, line := range strings.Split(f.prose, "\n") {
			for _, id := range benchmarkID.FindAllString(line, -1) {
				if !defined[id] {
					t.Errorf("%s:%d: benchmark %s is not defined in docs/benchmarks.md", f.path, n+1, id)
				}
			}
		}
	}
}
