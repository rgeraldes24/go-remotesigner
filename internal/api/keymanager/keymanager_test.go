// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package keymanager

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	km "github.com/rgeraldes24/go-remotesigner/internal/keymanager"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/argon"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystoretest"
	"github.com/rgeraldes24/go-remotesigner/internal/signer/provider"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/memstore"
)

func reason(t *testing.T, e *apierr.Error) apierr.Reason {
	t.Helper()
	if e == nil {
		return ""
	}
	return e.Reason
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestDecodeImport(t *testing.T) {
	ks := `{"version":1,"crypto":{}}`
	ok := `{"keystores":[` + quote(ks) + `],"passwords":["pé\n"],"slashing_protection":"{}"}`
	req, e := DecodeImport([]byte(ok))
	if e != nil || len(req.Keystores) != 1 || string(req.Keystores[0]) != ks || string(req.Passwords[0]) != "pé\n" ||
		string(req.SlashingProtection) != "{}" {
		t.Fatalf("decode: %+v %v", req, e)
	}
	if req, e := DecodeImport([]byte(`{"keystores":[],"passwords":[]}`)); e != nil || len(req.Keystores) != 0 ||
		req.SlashingProtection != nil {
		t.Fatalf("empty: %+v %v", req, e)
	}
	many := func(n int) string { return "[" + strings.TrimSuffix(strings.Repeat(`"",`, n), ",") + "]" }
	tests := []struct {
		name string
		body string
		want apierr.Reason
	}{
		{"not JSON", `{"keystores":`, apierr.MalformedJSON},
		{"duplicate key", `{"keystores":[],"keystores":[],"passwords":[]}`, apierr.MalformedJSON},
		{"unknown field", `{"keystores":[],"passwords":[],"extra":1}`, apierr.UnknownField},
		{"missing passwords", `{"keystores":[]}`, apierr.BadField},
		{"null keystores", `{"keystores":null,"passwords":[]}`, apierr.BadField},
		{"a keystore that is not a string", `{"keystores":[{}],"passwords":[""]}`, apierr.BadField},
		{"more passwords than keystores", `{"keystores":[""],"passwords":["",""]}`, apierr.InvariantViolation},
		{"65 keystores", `{"keystores":` + many(65) + `,"passwords":` + many(65) + `}`, apierr.InvariantViolation},
		{"65 passwords", `{"keystores":` + many(1) + `,"passwords":` + many(65) + `}`, apierr.InvariantViolation},
		{"slashing_protection not a string", `{"keystores":[],"passwords":[],"slashing_protection":{}}`, apierr.BadField},
	}
	for _, tt := range tests {
		if _, e := DecodeImport([]byte(tt.body)); reason(t, e) != tt.want {
			t.Errorf("%s: %v, want %s", tt.name, e, tt.want)
		}
	}
	if _, e := DecodeImport([]byte(`{"keystores":` + many(64) + `,"passwords":` + many(64) + `}`)); e != nil {
		t.Fatalf("64 keystores: %v", e)
	}
}

// A body of millions of empty strings is refused after the 65th element:
// the decoder never holds more than 64 of them.
func TestDecodeImportStopsAtTheBound(t *testing.T) {
	n := (BodyLimit - 64) / 6
	body := make([]byte, 0, BodyLimit)
	body = append(body, `{"keystores":[`...)
	for i := range n {
		if i > 0 {
			body = append(body, ',')
		}
		body = append(body, `""`...)
	}
	body = append(body, `],"passwords":[]}`...)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, e := DecodeImport(body)
	runtime.ReadMemStats(&after)
	if reason(t, e) != apierr.InvariantViolation {
		t.Fatalf("decode: %v", e)
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > 1<<20 {
		t.Fatalf("decoding allocated %d bytes", got)
	}
}

func TestDecodeDelete(t *testing.T) {
	pk := "0x" + strings.Repeat("aB", mldsa87.PublicKeySize)
	got, e := DecodeDelete([]byte(`{"pubkeys":["` + pk + `"]}`))
	if e != nil || len(got) != 1 || got[0][0] != 0xab {
		t.Fatalf("decode: %v %v", got, e)
	}
	for _, tt := range []struct {
		body string
		want apierr.Reason
	}{
		{`{"pubkeys": null}`, apierr.BadField},
		{`{"pubkeys":[],"extra":1}`, apierr.UnknownField},
		{`{}`, apierr.BadField},
		{`{"pubkeys":["0x00"]}`, apierr.BadField},
		{`{"pubkeys":["` + strings.Repeat("ab", mldsa87.PublicKeySize) + `"]}`, apierr.BadField},
		{`{"pubkeys":["0x` + strings.Repeat("zz", mldsa87.PublicKeySize) + `"]}`, apierr.BadField},
		{`[`, apierr.MalformedJSON},
	} {
		if _, e := DecodeDelete([]byte(tt.body)); reason(t, e) != tt.want {
			t.Errorf("%.40s: %v, want %s", tt.body, e, tt.want)
		}
	}
}

var (
	specOnce sync.Once
	spec     *openapi3.T
	specErr  error
)

// conforms checks a response body against a component schema of the
// contract.
func conforms(t *testing.T, schema string, body []byte) {
	t.Helper()
	specOnce.Do(func() { spec, specErr = openapi3.NewLoader().LoadFromFile("../../../api/openapi/consensus.yaml") })
	if specErr != nil {
		t.Fatal(specErr)
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("%s: %q: %v", schema, body, err)
	}
	if err := spec.Components.Schemas[schema].Value.VisitJSON(v, openapi3.VisitAsResponse()); err != nil {
		t.Fatalf("%s: %s does not conform: %v", schema, body, err)
	}
}

func serve(t *testing.T, h http.Handler, method, body string) (int, []byte) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, "/qrl/v1/keystores", strings.NewReader(body)))
	out, _ := io.ReadAll(rec.Result().Body)
	return rec.Code, out
}

// The three routes answer in the contract's shapes: a list, per-keystore
// import results and per-key delete results with the interchange.
func TestHandlersConform(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)
	store := memstore.New()
	gvr := slashing.Root{1}
	if _, err := store.PinGenesisValidatorsRoot(t.Context(), gvr); err != nil {
		t.Fatal(err)
	}
	keys := provider.New(log)
	t.Cleanup(keys.Close)
	sem := argon.New(2, 1<<30)
	dir := filepath.Join(t.TempDir(), "keys")
	if err := km.PrepareDir(dir, true, nil); err != nil {
		t.Fatal(err)
	}
	h := &Handlers{Log: log, Manager: km.New(km.Config{Dir: dir, Keys: keys, Engine: slashing.NewEngine(store),
		Store: store, History: true, Decrypt: sem.Decrypt, Workers: 2, Log: log})}

	sealer, err := keystoretest.NewSealer("pw", keystoretest.Cheapest)
	if err != nil {
		t.Fatal(err)
	}
	seed := keystoretest.Seed("handlers", 0)
	ks, err := sealer.DepositCLI(seed, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	pkHex, _ := keystoretest.PublicKeyHex(seed)
	history := `{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x` + hex.EncodeToString(gvr[:]) +
		`"},"data":[{"pubkey":"0x` + pkHex + `","signed_blocks":[{"slot":"3"}],"signed_attestations":[]}]}`

	code, body := serve(t, h.Import(), http.MethodPost, `{"keystores":[`+quote(string(ks))+`,"{}"],"passwords":["pw","x"],`+
		`"slashing_protection":`+quote(history)+`}`)
	if code != 200 || !bytes.Contains(body, []byte(`{"status":"imported","message":""}`)) {
		t.Fatalf("import: %d %s", code, body)
	}
	conforms(t, "ImportKeystoresResponse", body)

	code, body = serve(t, h.List(), http.MethodGet, "")
	if code != 200 || !bytes.Contains(body, []byte(`"readonly":false`)) ||
		!bytes.Contains(body, []byte(`"derivation_path":"m/12381/238/0/0"`)) {
		t.Fatalf("list: %d %s", code, body)
	}
	conforms(t, "ListKeystoresResponse", body)

	code, body = serve(t, h.Delete(), http.MethodDelete, `{"pubkeys":["0x`+pkHex+`"]}`)
	if code != 200 || !bytes.Contains(body, []byte(`"status":"deleted"`)) {
		t.Fatalf("delete: %d %s", code, body)
	}
	conforms(t, "DeleteKeystoresResponse", body)
	var del struct {
		SlashingProtection string `json:"slashing_protection"`
	}
	if err := json.Unmarshal(body, &del); err != nil || !strings.Contains(del.SlashingProtection, pkHex) {
		t.Fatalf("export: %v %s", err, body)
	}

	code, body = serve(t, h.List(), http.MethodGet, "")
	if code != 200 || string(body) != `{"data":[]}` {
		t.Fatalf("empty list: %d %s", code, body)
	}

	// A history for another network refuses the request with 400.
	other := strings.Replace(history, hex.EncodeToString(gvr[:]), hex.EncodeToString(make([]byte, 32)), 1)
	code, body = serve(t, h.Import(), http.MethodPost, `{"keystores":[`+quote(string(ks))+`],"passwords":["pw"],`+
		`"slashing_protection":`+quote(other)+`}`)
	if code != 400 || !bytes.Contains(body, []byte(`"BAD_FIELD"`)) {
		t.Fatalf("other network: %d %s", code, body)
	}
}
