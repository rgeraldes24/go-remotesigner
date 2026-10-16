// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package openapi

import (
	"maps"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// docs/contract.md carries three machine-checked tables between these
// markers.
const (
	reasonsBegin    = "<!-- contract:reasons:begin -->"
	reasonsEnd      = "<!-- contract:reasons:end -->"
	endpointsBegin  = "<!-- contract:endpoints:begin -->"
	endpointsEnd    = "<!-- contract:endpoints:end -->"
	deviationsBegin = "<!-- contract:deviations:begin -->"
	deviationsEnd   = "<!-- contract:deviations:end -->"
)

// deviationsPath is the register of differences from Web3Signer.
const deviationsPath = "../../DEVIATIONS.md"

// tableRows returns the data rows of the Markdown table between begin and
// end in docs/contract.md, as trimmed cells with code spans unwrapped.
func tableRows(t *testing.T, begin, end string, columns int) [][]string {
	t.Helper()
	raw, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatalf("read %s: %v", contractPath, err)
	}
	text := string(raw)
	i, j := strings.Index(text, begin), strings.Index(text, end)
	if i < 0 || j < i {
		t.Fatalf("%s: markers %s ... %s not found", contractPath, begin, end)
	}
	var rows [][]string
	header := 0
	for _, line := range strings.Split(text[i+len(begin):j], "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") {
			continue
		}
		if header < 2 { // column titles and the |---| separator
			header++
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) != columns {
			t.Fatalf("%s: row %q has %d columns, want %d", contractPath, line, len(cells), columns)
		}
		for k := range cells {
			cells[k] = strings.TrimSpace(strings.ReplaceAll(cells[k], "`", ""))
		}
		rows = append(rows, cells)
	}
	if len(rows) == 0 {
		t.Fatalf("%s: table between %s and %s is empty", contractPath, begin, end)
	}
	return rows
}

type reasonDoc struct {
	status int
	when   string
}

// reasonCatalogue reads the error catalogue: reason | status | when | client.
func reasonCatalogue(t *testing.T) map[string]reasonDoc {
	t.Helper()
	out := map[string]reasonDoc{}
	for _, row := range tableRows(t, reasonsBegin, reasonsEnd, 4) {
		status, err := strconv.Atoi(row[1])
		if err != nil || status < 400 || status > 599 {
			t.Fatalf("%s: reason %s has status %q", contractPath, row[0], row[1])
		}
		if _, dup := out[row[0]]; dup {
			t.Fatalf("%s: reason %s is listed twice", contractPath, row[0])
		}
		if row[2] == "" || row[3] == "" {
			t.Errorf("%s: reason %s needs a description and a client mapping", contractPath, row[0])
		}
		out[row[0]] = reasonDoc{status: status, when: row[2]}
	}
	return out
}

// TestReasonCatalogueMatchesSpec checks the acceptance criterion "every
// reason value is documented with its status code".
func TestReasonCatalogueMatchesSpec(t *testing.T) {
	enum := enumStrings(t, schema(t, "ErrorReason"))
	documented := slices.Sorted(maps.Keys(reasonCatalogue(t)))
	sort.Strings(enum)
	if !slices.Equal(enum, documented) {
		t.Errorf("ErrorReason enum and the docs/contract.md catalogue differ:\n spec: %v\n docs: %v", enum, documented)
	}
}

// TestEndpointTableMatchesSpec keeps the endpoint table in docs/contract.md
// in step with the paths, scopes and status codes of the specification.
func TestEndpointTableMatchesSpec(t *testing.T) {
	doc := loadSpec(t)
	type endpoint struct{ scope, statuses string }
	documented := map[string]endpoint{}
	for _, row := range tableRows(t, endpointsBegin, endpointsEnd, 4) {
		key := row[0]
		if _, dup := documented[key]; dup {
			t.Fatalf("%s: endpoint %s is listed twice", contractPath, key)
		}
		documented[key] = endpoint{scope: row[1], statuses: normaliseCodes(row[2] + ", " + row[3])}
	}

	inSpec := map[string]bool{}
	for _, o := range operations(t) {
		key := o.method + " " + o.path
		inSpec[key] = true
		got, ok := documented[key]
		if !ok {
			t.Errorf("%s is in the spec but not in the docs/contract.md endpoint table", key)
			continue
		}
		if want := scopeOf(o.op.Security, doc.Security); got.scope != want {
			t.Errorf("%s: docs say scope %q, spec says %q", key, got.scope, want)
		}
		codes := slices.Sorted(maps.Keys(o.op.Responses.Map()))
		if want := normaliseCodes(strings.Join(codes, ", ")); got.statuses != want {
			t.Errorf("%s: docs list status codes %s, spec lists %s", key, got.statuses, want)
		}
	}
	for key := range documented {
		if !inSpec[key] {
			t.Errorf("%s is in the docs/contract.md endpoint table but not in the spec", key)
		}
	}
}

// scopeOf names the token scope an operation requires: "none", "sign",
// "admin", or "none, sign" when both anonymous and sign-token access are
// declared (the healthcheck).
func scopeOf(op *openapi3.SecurityRequirements, global openapi3.SecurityRequirements) string {
	reqs := global
	if op != nil {
		reqs = *op
	}
	var scopes []string
	for _, req := range reqs {
		switch {
		case len(req) == 0:
			scopes = append(scopes, "none")
		case has(req, "adminToken"):
			scopes = append(scopes, "admin")
		case has(req, "signToken"):
			scopes = append(scopes, "sign")
		}
	}
	if len(scopes) == 0 {
		return "none"
	}
	return strings.Join(scopes, ", ")
}

func has(req openapi3.SecurityRequirement, scheme string) bool {
	_, ok := req[scheme]
	return ok
}

// normaliseCodes turns a comma-separated list of status codes into a sorted,
// de-duplicated canonical string.
func normaliseCodes(s string) string {
	var codes []string
	for _, c := range strings.Split(s, ",") {
		if c = strings.TrimSpace(c); c != "" && c != "—" {
			codes = append(codes, c)
		}
	}
	sort.Strings(codes)
	return strings.Join(slices.Compact(codes), ", ")
}

var (
	deviationID     = regexp.MustCompile(`\bX[0-9]+\b`)
	sectionAnchor   = regexp.MustCompile(`\(#([0-9]+)-`)
	contractSection = regexp.MustCompile(`docs/contract\.md#([0-9]+)-`)
)

// TestDeviationsMapMatchesRegister keeps the map in docs/contract.md section
// 21 and the links of DEVIATIONS.md in step: every register row that links a
// contract section is in the map under that section, and every row the map
// lists links into the contract.
func TestDeviationsMapMatchesRegister(t *testing.T) {
	mapped := map[string][]string{} // row -> the sections the map gives
	for _, cells := range tableRows(t, deviationsBegin, deviationsEnd, 2) {
		var sections []string
		for _, m := range sectionAnchor.FindAllStringSubmatch(cells[1], -1) {
			sections = append(sections, m[1])
		}
		ids := deviationID.FindAllString(cells[0], -1)
		if len(ids) == 0 || len(sections) == 0 {
			t.Errorf("section 21 row %q names no register row or no section", cells)
		}
		for _, id := range ids {
			if _, dup := mapped[id]; dup {
				t.Errorf("section 21 lists %s twice", id)
			}
			mapped[id] = sections
		}
	}

	raw, err := os.ReadFile(deviationsPath)
	if err != nil {
		t.Fatal(err)
	}
	linked := map[string][]string{} // row -> the contract sections it links
	for _, line := range strings.Split(string(raw), "\n") {
		cells := strings.Split(line, "|")
		if len(cells) < 3 || !deviationID.MatchString(strings.TrimSpace(cells[1])) {
			continue
		}
		id := strings.TrimSpace(cells[1])
		linked[id] = nil
		for _, m := range contractSection.FindAllStringSubmatch(line, -1) {
			linked[id] = append(linked[id], m[1])
		}
	}
	if len(linked) == 0 {
		t.Fatalf("%s: no register rows found", deviationsPath)
	}

	for id, sections := range linked {
		for _, sec := range sections {
			if !slices.Contains(mapped[id], sec) {
				t.Errorf("%s links contract section %s, but section 21 does not map it there (it gives %v)",
					id, sec, mapped[id])
			}
		}
	}
	for id := range mapped {
		if sections, ok := linked[id]; !ok {
			t.Errorf("section 21 maps %s, which is not in %s", id, deviationsPath)
		} else if len(sections) == 0 {
			t.Errorf("section 21 maps %s, but its %s row links no contract section", id, deviationsPath)
		}
	}
}
