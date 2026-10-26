// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package openapi

import (
	"context"
	"maps"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// execution.yaml describes execution mode's JSON-RPC endpoint and its
// public-key listing; docs/operations/execution.md is its prose.
const (
	executionSpecPath = "execution.yaml"
	executionDocPath  = "../../docs/operations/execution.md"

	// executionVersion is the version of execution.yaml. A change to a
	// request or response it describes bumps it.
	executionVersion = "1.0.0"
)

var (
	executionOnce sync.Once
	executionDoc  *openapi3.T
	executionErr  error
)

// loadExecutionSpec parses execution.yaml once per test binary; like
// consensus.yaml it is one self-contained file.
func loadExecutionSpec(t *testing.T) *openapi3.T {
	t.Helper()
	executionOnce.Do(func() {
		loader := openapi3.NewLoader()
		loader.IsExternalRefsAllowed = false
		executionDoc, executionErr = loader.LoadFromFile(executionSpecPath)
	})
	if executionErr != nil {
		t.Fatalf("load %s: %v", executionSpecPath, executionErr)
	}
	return executionDoc
}

func executionSchema(t *testing.T, name string) *openapi3.Schema {
	t.Helper()
	ref, ok := loadExecutionSpec(t).Components.Schemas[name]
	if !ok || ref.Value == nil {
		t.Fatalf("execution.yaml: components.schemas.%s is missing", name)
	}
	return ref.Value
}

func TestExecutionSpecIsValidOpenAPI(t *testing.T) {
	doc := loadExecutionSpec(t)
	if doc.OpenAPI != "3.0.3" {
		t.Errorf("openapi = %q, want 3.0.3", doc.OpenAPI)
	}
	if err := doc.Validate(context.Background(), openapi3.EnableExamplesValidation()); err != nil {
		t.Fatalf("execution.yaml does not validate: %v", err)
	}
	info := doc.Info
	if info.Version != executionVersion || info.Title != "QRL Remote Signer Execution API" ||
		info.License == nil || info.License.Name != "Apache 2.0" {
		t.Errorf("info %+v", info)
	}
	var paths []string
	for p, item := range doc.Paths.Map() {
		for m := range item.Operations() {
			paths = append(paths, m+" "+p)
		}
	}
	slices.Sort(paths)
	if want := []string{"GET /api/v1/execution/publicKeys", "POST /"}; !slices.Equal(paths, want) {
		t.Errorf("operations %v, want %v", paths, want)
	}
}

// Every example validates against its schema, as a request or as a
// response, and none abbreviates a hex value.
func TestExecutionExamplesMatchTheirSchemas(t *testing.T) {
	examples := examplesOf(loadExecutionSpec(t))
	if len(examples) < 40 {
		t.Fatalf("found only %d examples", len(examples))
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
		walkStrings(ex.value, func(s string) {
			if strings.Contains(s, "…") || strings.Contains(s, "...") {
				t.Errorf("%s abbreviates a value: %.40q", ex.where, s)
			}
		})
	}
}

// localMethods returns the methods execution.yaml says the signer answers,
// each with the schema of its result (x-result-schema), and the methods it
// never forwards (x-never-forwarded).
func localMethods(t *testing.T) (answered map[string]string, neverForwarded []string) {
	t.Helper()
	answered = map[string]string{}
	for _, ref := range executionSchema(t, "Request").OneOf {
		s := ref.Value
		if never, ok := s.Extensions["x-never-forwarded"]; ok {
			for _, m := range never.([]any) {
				neverForwarded = append(neverForwarded, m.(string))
			}
			continue
		}
		result, _ := s.Extensions["x-result-schema"].(string)
		methods := s.Properties["method"].Value.Enum
		if result == "" || len(methods) != 1 {
			t.Fatalf("%s: a local request schema needs one method and an x-result-schema", ref.Ref)
		}
		if _, ok := loadExecutionSpec(t).Components.Schemas[result]; !ok {
			t.Fatalf("%s: x-result-schema %s is not a schema", ref.Ref, result)
		}
		answered[methods[0].(string)] = result
	}
	return answered, neverForwarded
}

// The other-methods schema excludes exactly the answered methods, so that
// every request matches one request schema.
func TestExecutionRequestSchemasPartitionMethods(t *testing.T) {
	answered, never := localMethods(t)
	if len(answered) != 5 || !slices.Equal(never, []string{"qrl_signTypedData"}) {
		t.Fatalf("answered %v, never forwarded %v", answered, never)
	}
	var other *openapi3.Schema
	for _, ref := range executionSchema(t, "Request").OneOf {
		if _, ok := ref.Value.Extensions["x-never-forwarded"]; ok {
			other = ref.Value
		}
	}
	var excluded []string
	for _, v := range other.Properties["method"].Value.Not.Value.Enum {
		excluded = append(excluded, v.(string))
	}
	slices.Sort(excluded)
	if want := slices.Sorted(maps.Keys(answered)); !slices.Equal(excluded, want) {
		t.Errorf("OtherRequest excludes %v, want the answered methods %v", excluded, want)
	}
	// Each request matches one schema: a method that takes no params, or
	// any other method, without params; qrl_sign never without its own.
	req := executionSchema(t, "Request")
	for m, ok := range map[string]bool{"qrl_accounts": true, "health_status": true, "qrl_signTypedData": true,
		"net_version": true, "qrl_sign": false, "qrl_signTransaction": false} {
		if err := req.VisitJSON(map[string]any{"jsonrpc": "2.0", "id": 1.0, "method": m}); (err == nil) != ok {
			t.Errorf("a %s request without params: %v", m, err)
		}
	}
}

// Each local method's response example, named after the method, has a
// result that matches the method's x-result-schema.
func TestExecutionResultExamples(t *testing.T) {
	answered, _ := localMethods(t)
	op := loadExecutionSpec(t).Paths.Value("/").Post
	responses := op.Responses.Status(200).Value.Content.Get("application/json").Examples
	requests := op.RequestBody.Value.Content.Get("application/json").Examples
	for method, result := range answered {
		req, resp := requests[method], responses[method]
		if req == nil || resp == nil {
			t.Errorf("%s has no request or response example", method)
			continue
		}
		if got := req.Value.Value.(map[string]any)["method"]; got != method {
			t.Errorf("request example %s is a %v request", method, got)
		}
		r := resp.Value.Value.(map[string]any)
		if r["id"] != req.Value.Value.(map[string]any)["id"] {
			t.Errorf("%s: response id %v, request id %v", method, r["id"], req.Value.Value.(map[string]any)["id"])
		}
		if err := executionSchema(t, result).VisitJSON(r["result"], openapi3.VisitAsResponse()); err != nil {
			t.Errorf("%s: result does not match %s: %v", method, result, err)
		}
	}
}

// rpcErrorExample is one JSON-RPC error example of POST /.
type rpcErrorExample struct {
	name    string
	status  int
	code    int
	message string
}

// rpcErrorExamples returns the JSON-RPC error examples of POST /, single
// responses and batch elements, with the status they are listed under.
func rpcErrorExamples(t *testing.T) []rpcErrorExample {
	t.Helper()
	var out []rpcErrorExample
	add := func(name string, status int, v any) {
		m, ok := v.(map[string]any)
		if !ok {
			return
		}
		e, ok := m["error"].(map[string]any)
		if !ok {
			return
		}
		out = append(out, rpcErrorExample{name: name, status: status, code: int(e["code"].(float64)),
			message: e["message"].(string)})
	}
	for code, resp := range loadExecutionSpec(t).Paths.Value("/").Post.Responses.Map() {
		mt := resp.Value.Content.Get("application/json")
		if mt == nil {
			continue
		}
		status, _ := strconv.Atoi(code)
		values := map[string]any{"example": mt.Example}
		for name, ex := range mt.Examples {
			values[name] = ex.Value.Value
		}
		for name, v := range values {
			if list, ok := v.([]any); ok { // a batch: always 200
				for _, e := range list {
					add(name, status, e)
				}
				continue
			}
			add(name, status, v)
		}
	}
	return out
}

// execution.md section 4 documents the methods and the errors that
// execution.yaml describes: the methods table names each answered method,
// the refused typed-data method and "anything else"; every row of the
// errors table has an example under each HTTP status it lists, every error
// example is a row of the table, and RpcError's enums hold exactly the
// table's codes and messages.
func TestExecutionSpecMatchesDocs(t *testing.T) {
	raw, err := os.ReadFile(executionDocPath)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)

	answered, never := localMethods(t)
	var documented []string
	for _, row := range markdownTable(t, doc, "| Method | Answer |") {
		documented = append(documented, strings.Trim(row[0], "`"))
	}
	want := append(slices.Collect(maps.Keys(answered)), never...)
	want = append(want, "anything else")
	slices.Sort(want)
	slices.Sort(documented)
	if !slices.Equal(documented, want) {
		t.Errorf("execution.md documents the methods %v, execution.yaml %v", documented, want)
	}

	type key struct{ code, status int }
	documentedErrors := map[key]bool{}
	var tableText string
	codes := map[int]bool{}
	number := regexp.MustCompile(`\b[1-5][0-9]{2}\b`)
	for _, row := range markdownTable(t, doc, "| Code | Message | HTTP status of a single request |") {
		code, err := strconv.Atoi(row[0])
		if err != nil {
			t.Fatalf("errors table: code %q", row[0])
		}
		codes[code] = true
		tableText += row[1] + "\n"
		statuses := number.FindAllString(strings.Split(row[2], "(")[0], -1)
		if len(statuses) == 0 {
			t.Fatalf("errors table: no status in %q", row[2])
		}
		for _, s := range statuses {
			st, _ := strconv.Atoi(s)
			documentedErrors[key{code, st}] = true
		}
	}
	examples := map[key]bool{}
	for _, ex := range rpcErrorExamples(t) {
		k := key{ex.code, ex.status}
		examples[k] = true
		if !documentedErrors[k] {
			t.Errorf("example %s: error %d under HTTP %d is not in execution.md's errors table", ex.name, ex.code, ex.status)
		}
	}
	for k := range documentedErrors {
		if !examples[k] {
			t.Errorf("execution.md lists error %d with HTTP %d, which execution.yaml has no example of", k.code, k.status)
		}
	}

	rpcError := executionSchema(t, "RpcError")
	var enumCodes []int
	for _, c := range rpcError.Properties["code"].Value.Enum {
		enumCodes = append(enumCodes, int(c.(float64)))
	}
	slices.Sort(enumCodes)
	if want := slices.Sorted(maps.Keys(codes)); !slices.Equal(enumCodes, want) {
		t.Errorf("RpcError codes %v, execution.md's %v", enumCodes, want)
	}
	for _, m := range rpcError.Properties["message"].Value.Enum {
		if !strings.Contains(tableText, m.(string)) {
			t.Errorf("RpcError message %q is not in execution.md's errors table", m)
		}
	}

	// The public-key listing has the members execution.md shows.
	props := slices.Sorted(maps.Keys(executionSchema(t, "AccountPublicKey").Properties))
	if !slices.Equal(props, []string{"address", "public_key"}) || !strings.Contains(doc, `[{"address":"Q…","public_key":"0x…"}]`) {
		t.Errorf("AccountPublicKey has %v; execution.md shows another listing", props)
	}
	if !strings.Contains(doc, "api/openapi/execution.yaml") {
		t.Error("execution.md does not point to api/openapi/execution.yaml")
	}
}

// markdownTable returns the data rows, as trimmed cells, of the Markdown
// table whose header line is header.
func markdownTable(t *testing.T, doc, header string) [][]string {
	t.Helper()
	i := strings.Index(doc, header+"\n")
	if i < 0 {
		t.Fatalf("no table %q", header)
	}
	columns := strings.Count(header, "|") - 1
	var rows [][]string
	for n, line := range strings.Split(doc[i:], "\n") {
		if n < 2 {
			continue // the header and its separator
		}
		if !strings.HasPrefix(line, "|") {
			break
		}
		cells := strings.Split(strings.Trim(line, "|"), " | ")
		if len(cells) != columns {
			t.Fatalf("table %q: row %q has %d cells, want %d", header, line, len(cells), columns)
		}
		for k := range cells {
			cells[k] = strings.TrimSpace(cells[k])
		}
		rows = append(rows, cells)
	}
	if len(rows) == 0 {
		t.Fatalf("table %q is empty", header)
	}
	return rows
}
