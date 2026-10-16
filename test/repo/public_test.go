// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"regexp"
	"slices"
	"testing"
)

var (
	// lineBreak is a line break with the indentation and comment or quote
	// marker of the next line, so that wrapped prose reads as one line.
	lineBreak = regexp.MustCompile(`\s*\n\s*(?://+|#+|>|\*)?\s*`)
	// visibility is a statement of visibility.
	visibility = regexp.MustCompile(`(?i)\b(?:is|are)\s+(?:now\s+)?(?:public|private)\b`)
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
	prose := lineBreak.ReplaceAllString(text, " ")
	var claims []string
	for _, m := range visibility.FindAllStringIndex(prose, -1) {
		clause := prose[clauseStart(prose, m[0]):m[1]]
		if repoSubject.MatchString(clause) && !condition.MatchString(clause) {
			claims = append(claims, clause)
		}
	}
	return claims
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
		for _, c := range visibilityClaims(f.text) {
			t.Errorf("%s: %q states the repository's visibility as a fact; describe the choice and when it takes "+
				"effect (\"once the repository is public\") so that it reads correctly before and after the flip",
				f.path, c)
		}
	}
}
