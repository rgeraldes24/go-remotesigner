// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package openapi holds the contract tests for consensus.yaml, the frozen HTTP
// contract between the qrysm validator client and the signer, and for
// execution.yaml, the description of execution mode's JSON-RPC endpoint. The
// tests lint the specifications, validate every example against its schema,
// pin the strict JSON encoding rules, and keep docs/contract.md and
// docs/operations/execution.md in step with them.
package openapi

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

const (
	specPath     = "consensus.yaml"
	contractPath = "../../docs/contract.md"

	// frozenVersion is the contract version this tree implements. Changing
	// it is a contract change (docs/contract.md, "Versioning").
	frozenVersion = "1.0.0"
)

var (
	specOnce sync.Once
	specDoc  *openapi3.T
	specErr  error
)

// loadSpec parses consensus.yaml once per test binary. External references
// are not allowed: the contract is a single self-contained file.
func loadSpec(t *testing.T) *openapi3.T {
	t.Helper()
	specOnce.Do(func() {
		loader := openapi3.NewLoader()
		loader.IsExternalRefsAllowed = false
		specDoc, specErr = loader.LoadFromFile(specPath)
	})
	if specErr != nil {
		t.Fatalf("load %s: %v", specPath, specErr)
	}
	return specDoc
}

// schema returns the named component schema.
func schema(t *testing.T, name string) *openapi3.Schema {
	t.Helper()
	ref, ok := loadSpec(t).Components.Schemas[name]
	if !ok || ref.Value == nil {
		t.Fatalf("components.schemas.%s is missing", name)
	}
	return ref.Value
}

// enumStrings returns the string values of a schema's enum.
func enumStrings(t *testing.T, s *openapi3.Schema) []string {
	t.Helper()
	out := make([]string, 0, len(s.Enum))
	for _, v := range s.Enum {
		str, ok := v.(string)
		if !ok {
			t.Fatalf("enum value %v is not a string", v)
		}
		out = append(out, str)
	}
	return out
}

// decode parses a JSON document into the generic form that schema
// validation expects.
func decode(t *testing.T, doc string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(doc), &v); err != nil {
		t.Fatalf("test JSON does not parse: %v\n%s", err, doc)
	}
	return v
}

// deepCopy returns an independent copy of a decoded JSON value.
func deepCopy(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return decode(t, string(b))
}

func TestSpecIsValidOpenAPI(t *testing.T) {
	doc := loadSpec(t)
	if doc.OpenAPI != "3.0.3" {
		t.Errorf("openapi = %q, want 3.0.3", doc.OpenAPI)
	}
	// Validate also checks every example against its schema.
	if err := doc.Validate(context.Background(), openapi3.EnableExamplesValidation()); err != nil {
		t.Fatalf("specification does not validate: %v", err)
	}
}

func TestSpecInfo(t *testing.T) {
	info := loadSpec(t).Info
	if info.Version != frozenVersion {
		t.Errorf("info.version = %q, want %q: a contract change needs a deliberate version bump", info.Version, frozenVersion)
	}
	if info.Title != "QRL Remote Signer API" {
		t.Errorf("info.title = %q", info.Title)
	}
	if strings.Contains(strings.ToLower(info.Title), "web3signer") {
		t.Errorf("info.title must not use the Web3Signer product name")
	}
	if info.License == nil || info.License.Name != "Apache 2.0" {
		t.Errorf("info.license must be the Apache 2.0 block, got %+v", info.License)
	}
	const derived = "Derived from ethereum/remote-signing-api v1.4.0 (CC0-1.0) and Web3Signer (Apache-2.0)"
	if !strings.Contains(strings.Join(strings.Fields(info.Description), " "), derived) {
		t.Errorf("info.description must state %q", derived)
	}
}

func TestCapabilitiesAPIVersionMatchesInfo(t *testing.T) {
	doc := loadSpec(t)
	op := doc.Paths.Value("/api/v1/consensus/capabilities").Get
	mt := op.Responses.Status(200).Value.Content.Get("application/json")
	if len(mt.Examples) == 0 {
		t.Fatal("capabilities has no examples")
	}
	for name, ex := range mt.Examples {
		v, _ := ex.Value.Value.(map[string]any)
		if got := v["api_version"]; got != doc.Info.Version {
			t.Errorf("capabilities example %s: api_version = %v, want info.version %q", name, got, doc.Info.Version)
		}
	}
	if got := schema(t, "Capabilities").Properties["api_version"].Value.Example; got != frozenVersion {
		t.Errorf("Capabilities.api_version example = %v, want %q", got, frozenVersion)
	}
}
