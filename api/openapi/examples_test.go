// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package openapi

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// example is one example value found in the specification, together with
// the schema it must satisfy.
type example struct {
	where   string // location, for failure messages
	schema  *openapi3.Schema
	value   any
	request bool // validated as request data (readOnly properties forbidden)
}

// operation is one method on one path.
type operation struct {
	method, path string
	op           *openapi3.Operation
}

// operations returns every operation of the specification in a stable order.
func operations(t *testing.T) []operation {
	t.Helper()
	var ops []operation
	for path, item := range loadSpec(t).Paths.Map() {
		for method, op := range item.Operations() {
			ops = append(ops, operation{method: method, path: path, op: op})
		}
	}
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].path != ops[j].path {
			return ops[i].path < ops[j].path
		}
		return ops[i].method < ops[j].method
	})
	return ops
}

// mediaExamples returns the examples of one media type.
func mediaExamples(where string, mt *openapi3.MediaType, request bool) []example {
	if mt == nil || mt.Schema == nil {
		return nil
	}
	var out []example
	if mt.Example != nil {
		out = append(out, example{where: where + " example", schema: mt.Schema.Value, value: mt.Example, request: request})
	}
	for name, ex := range mt.Examples {
		out = append(out, example{where: where + " examples." + name, schema: mt.Schema.Value, value: ex.Value.Value, request: request})
	}
	return out
}

// parameterExamples returns the examples of one parameter or header.
func parameterExamples(where string, p *openapi3.Parameter) []example {
	if p.Schema == nil {
		return nil
	}
	var out []example
	if p.Example != nil {
		out = append(out, example{where: where + " example", schema: p.Schema.Value, value: p.Example, request: true})
	}
	for name, ex := range p.Examples {
		out = append(out, example{where: where + " examples." + name, schema: p.Schema.Value, value: ex.Value.Value, request: true})
	}
	return out
}

// allExamples collects every example in the specification: parameters,
// request bodies, responses, response headers and component schemas.
func allExamples(t *testing.T) []example {
	t.Helper()
	var out []example
	for _, o := range operations(t) {
		at := o.method + " " + o.path
		for _, p := range o.op.Parameters {
			out = append(out, parameterExamples(at+" parameter "+p.Value.Name, p.Value)...)
		}
		if rb := o.op.RequestBody; rb != nil {
			for ct, mt := range rb.Value.Content {
				out = append(out, mediaExamples(at+" request "+ct, mt, true)...)
			}
		}
		for code, resp := range o.op.Responses.Map() {
			for ct, mt := range resp.Value.Content {
				out = append(out, mediaExamples(at+" response "+code+" "+ct, mt, false)...)
			}
			for name, h := range resp.Value.Headers {
				out = append(out, parameterExamples(at+" response "+code+" header "+name, &h.Value.Parameter)...)
			}
		}
	}
	for name, s := range loadSpec(t).Components.Schemas {
		if s.Value.Example != nil {
			out = append(out, example{where: "components.schemas." + name + " example", schema: s.Value, value: s.Value.Example})
		}
	}
	return out
}

func TestEveryExampleMatchesItsSchema(t *testing.T) {
	examples := allExamples(t)
	// 9 sign requests, the RANDAO pair, capabilities, errors and the rest.
	if len(examples) < 60 {
		t.Fatalf("found only %d examples; the walk is missing parts of the spec", len(examples))
	}
	for _, ex := range examples {
		opts := []openapi3.SchemaValidationOption{openapi3.MultiErrors()}
		if ex.request {
			opts = append(opts, openapi3.VisitAsRequest())
		} else {
			opts = append(opts, openapi3.VisitAsResponse())
		}
		if err := ex.schema.VisitJSON(ex.value, opts...); err != nil {
			t.Errorf("%s does not match its schema: %v", ex.where, err)
		}
	}
}

// TestNoAbbreviatedHexInExamples guards against "0x…" placeholders, which
// look plausible to a reader but fail every length check.
func TestNoAbbreviatedHexInExamples(t *testing.T) {
	for _, ex := range allExamples(t) {
		walkStrings(ex.value, func(s string) {
			if strings.Contains(s, "0x…") || strings.Contains(s, "0x...") {
				t.Errorf("%s contains an abbreviated hex value %.40q", ex.where, s)
			}
		})
	}
}

func walkStrings(v any, f func(string)) {
	switch v := v.(type) {
	case string:
		f(v)
	case []any:
		for _, e := range v {
			walkStrings(e, f)
		}
	case map[string]any:
		for _, e := range v {
			walkStrings(e, f)
		}
	}
}

// TestEverySignTypeHasSchemaAndExample checks the acceptance criterion
// "every request type has a schema and an example", and that the
// discriminator, the per-type schemas and the examples agree.
func TestEverySignTypeHasSchemaAndExample(t *testing.T) {
	doc := loadSpec(t)
	types := enumStrings(t, schema(t, "ArtifactType"))
	if len(types) != 9 {
		t.Fatalf("ArtifactType has %d values, want the 9 qrysm duty types", len(types))
	}

	signReq := schema(t, "SignRequest")
	if signReq.Discriminator == nil || signReq.Discriminator.PropertyName != "type" {
		t.Fatal("SignRequest must discriminate on type")
	}
	mapping := signReq.Discriminator.Mapping
	if len(mapping) != len(types) || len(signReq.OneOf) != len(types) {
		t.Fatalf("SignRequest has %d mappings and %d oneOf entries, want %d each", len(mapping), len(signReq.OneOf), len(types))
	}

	op := doc.Paths.Value("/api/v1/consensus/sign/{identifier}").Post
	examples := op.RequestBody.Value.Content.Get("application/json").Examples

	for _, typ := range types {
		t.Run(typ, func(t *testing.T) {
			ref, ok := mapping[typ]
			if !ok {
				t.Fatalf("no discriminator mapping for %s", typ)
			}
			name := strings.TrimPrefix(ref.Ref, "#/components/schemas/")
			s := schema(t, name)

			if got := enumStrings(t, s.Properties["type"].Value); !slices.Equal(got, []string{typ}) {
				t.Errorf("%s.type enum = %v, want [%s]", name, got, typ)
			}
			_, hasForkInfo := s.Properties["fork_info"]
			forkInfoRequired := slices.Contains(s.Required, "fork_info")
			if typ == "VALIDATOR_REGISTRATION" {
				if hasForkInfo {
					t.Errorf("%s must not accept fork_info", name)
				}
			} else if !forkInfoRequired {
				t.Errorf("%s must require fork_info (400 MISSING_FORK_INFO)", name)
			}
			for _, key := range []string{"signing_root", "signingRoot"} {
				if _, ok := s.Properties[key]; !ok {
					t.Errorf("%s must accept %s", name, key)
				}
			}

			ex, ok := examples[typ]
			if !ok {
				t.Fatalf("sign operation has no example named %s", typ)
			}
			v, _ := ex.Value.Value.(map[string]any)
			if v["type"] != typ {
				t.Errorf("example %s has type %v", typ, v["type"])
			}
			if err := s.VisitJSON(ex.Value.Value, openapi3.MultiErrors(), openapi3.VisitAsRequest()); err != nil {
				t.Errorf("example %s does not match %s: %v", typ, name, err)
			}
		})
	}
}

// TestSchemasAreClosed checks that every object in a request body, and in
// every response of the consensus namespace, rejects unknown fields
// (additionalProperties: false). Strict JSON applies to both directions, so
// adding a field is a contract change.
func TestSchemasAreClosed(t *testing.T) {
	for _, o := range operations(t) {
		at := o.method + " " + o.path
		if rb := o.op.RequestBody; rb != nil {
			for ct, mt := range rb.Value.Content {
				checkClosed(t, at+" request "+ct, mt.Schema, map[*openapi3.Schema]bool{})
			}
		}
		if !strings.HasPrefix(o.path, "/api/v1/consensus/") {
			continue
		}
		for code, resp := range o.op.Responses.Map() {
			if mt := resp.Value.Content.Get("application/json"); mt != nil {
				checkClosed(t, at+" response "+code, mt.Schema, map[*openapi3.Schema]bool{})
			}
		}
	}
}

func checkClosed(t *testing.T, where string, ref *openapi3.SchemaRef, seen map[*openapi3.Schema]bool) {
	t.Helper()
	if ref == nil || ref.Value == nil || seen[ref.Value] {
		return
	}
	s := ref.Value
	seen[s] = true
	if ref.Ref != "" {
		where += " (" + strings.TrimPrefix(ref.Ref, "#/components/schemas/") + ")"
	}
	if s.Type.Is("object") || len(s.Properties) > 0 {
		if s.AdditionalProperties.Has == nil || *s.AdditionalProperties.Has {
			t.Errorf("%s: object schema must set additionalProperties: false", where)
		}
	}
	for name, p := range s.Properties {
		checkClosed(t, where+"."+name, p, seen)
	}
	checkClosed(t, where+"[]", s.Items, seen)
	for i, sub := range slices.Concat(s.OneOf, s.AnyOf, s.AllOf) {
		checkClosed(t, fmt.Sprintf("%s#%d", where, i), sub, seen)
	}
}

// healthPaths answer errors in their own documented shapes (plain text, the
// healthcheck JSON) instead of ErrorResponse.
var healthPaths = map[string]bool{"/upcheck": true, "/healthcheck": true}

// TestErrorExamplesAgreeWithStatus checks that every error response uses the
// ErrorResponse shape, and every error example against the reason catalogue
// in docs/contract.md: code equals the response status, and the reason is one
// the catalogue lists for that status.
func TestErrorExamplesAgreeWithStatus(t *testing.T) {
	catalogue := reasonCatalogue(t)
	checked := 0
	for _, o := range operations(t) {
		if healthPaths[o.path] {
			continue
		}
		for code, resp := range o.op.Responses.Map() {
			status, err := strconv.Atoi(code)
			if err != nil || status < 400 {
				continue
			}
			mt := resp.Value.Content.Get("application/json")
			if mt == nil || mt.Schema == nil || mt.Schema.Ref != "#/components/schemas/ErrorResponse" {
				t.Errorf("%s %s: %s response must be an application/json ErrorResponse", o.method, o.path, code)
				continue
			}
			if mt.Example == nil && len(mt.Examples) == 0 {
				t.Errorf("%s %s: %s response has no example", o.method, o.path, code)
			}
			for _, ex := range mediaExamples(o.method+" "+o.path+" "+code, mt, false) {
				v, ok := ex.value.(map[string]any)
				if !ok {
					t.Errorf("%s: not an object", ex.where)
					continue
				}
				if c, _ := v["code"].(float64); int(c) != status {
					t.Errorf("%s: code %v, want %d", ex.where, v["code"], status)
				}
				reason, _ := v["reason"].(string)
				if got, ok := catalogue[reason]; !ok || got.status != status {
					t.Errorf("%s: reason %q is documented with status %d, used under %d", ex.where, reason, got.status, status)
				}
				checked++
			}
		}
	}
	if checked < 20 {
		t.Fatalf("checked only %d error examples", checked)
	}
}
