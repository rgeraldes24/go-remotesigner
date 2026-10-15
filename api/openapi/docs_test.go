// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package openapi

import (
	"maps"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// docs/contract.md carries two machine-checked tables between these markers.
const (
	reasonsBegin   = "<!-- contract:reasons:begin -->"
	reasonsEnd     = "<!-- contract:reasons:end -->"
	endpointsBegin = "<!-- contract:endpoints:begin -->"
	endpointsEnd   = "<!-- contract:endpoints:end -->"
)

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
