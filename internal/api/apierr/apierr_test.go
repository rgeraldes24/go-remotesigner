// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package apierr

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

// The catalogue must equal the error table of docs/contract.md, which the
// contract tests in api/openapi already check against the spec's enum.
func TestCatalogueMatchesContract(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/contract.md")
	if err != nil {
		t.Fatal(err)
	}
	const begin, end = "<!-- contract:reasons:begin -->", "<!-- contract:reasons:end -->"
	text := string(raw)
	i, j := strings.Index(text, begin), strings.Index(text, end)
	if i < 0 || j < i {
		t.Fatal("reasons table markers not found")
	}
	doc := map[Reason]int{}
	for _, line := range strings.Split(text[i+len(begin):j], "\n") {
		cells := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
		if len(cells) < 2 {
			continue
		}
		status, err := strconv.Atoi(strings.TrimSpace(cells[1]))
		if err != nil {
			continue // header and separator rows
		}
		doc[Reason(strings.Trim(strings.TrimSpace(cells[0]), "`"))] = status
	}
	if len(doc) != len(statuses) {
		t.Errorf("contract lists %d reasons, catalogue has %d", len(doc), len(statuses))
	}
	for r, want := range doc {
		if !r.Known() {
			t.Errorf("%s is in the contract but not in the catalogue", r)
			continue
		}
		if got := r.Status(); got != want {
			t.Errorf("%s: status %d, contract says %d", r, got, want)
		}
	}
	if got := len(Reasons()); got != len(doc) {
		t.Errorf("Reasons() returns %d values", got)
	}
}

func TestUnknownReasonIs500(t *testing.T) {
	if s := Reason("NOPE").Status(); s != 500 {
		t.Errorf("status %d", s)
	}
}

func TestErrorPath(t *testing.T) {
	tests := []struct {
		segments []string // applied innermost first
		want     string
	}{
		{nil, "BAD_FIELD: wrong length"},
		{[]string{"slot"}, "BAD_FIELD at slot: wrong length"},
		{[]string{Index(3), "signatures", "aggregate"}, "BAD_FIELD at aggregate.signatures[3]: wrong length"},
		{[]string{"root", "source", "attestation"}, "BAD_FIELD at attestation.source.root: wrong length"},
	}
	for _, tt := range tests {
		e := New(BadField, "wrong length")
		for _, s := range tt.segments {
			e = e.In(s)
		}
		if got := e.Error(); got != tt.want {
			t.Errorf("got %q, want %q", got, tt.want)
		}
	}
}

func TestReasonOf(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", New(ClockBound, "slot ahead"))
	if r, ok := ReasonOf(err); !ok || r != ClockBound {
		t.Errorf("ReasonOf = %q, %v", r, ok)
	}
	if _, ok := ReasonOf(fmt.Errorf("plain")); ok {
		t.Error("ReasonOf found a reason in a plain error")
	}
	if s := New(ClockBound, "").Status(); s != 412 {
		t.Errorf("status %d", s)
	}
}

// Every reason has a fixed message, and the messages carry nothing request-
// or process-specific.
func TestEveryReasonHasAMessage(t *testing.T) {
	for _, r := range Reasons() {
		m, ok := messages[r]
		if !ok || m == "" {
			t.Errorf("%s has no message", r)
		}
		if strings.ContainsAny(m, "/%{}") {
			t.Errorf("%s message %q looks templated or carries a path", r, m)
		}
	}
	if len(messages) != len(statuses) {
		t.Errorf("%d messages for %d reasons", len(messages), len(statuses))
	}
	if got := Reason("NOPE").Message(); got != "internal error" {
		t.Errorf("unknown reason message = %q", got)
	}
}
