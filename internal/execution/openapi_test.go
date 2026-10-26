// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package execution

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/theQRL/go-qrl/core/types"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
)

// The tests of api/openapi/execution.yaml against the handler, which
// `make contract` runs with the tests of api/openapi: the methods and
// errors it describes are the handler's, its examples are the handler's
// answers to its example requests, and its signatures verify.

const executionSpec = "../../api/openapi/execution.yaml"

func loadOpenAPI(t *testing.T) *openapi3.T {
	t.Helper()
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = false
	doc, err := loader.LoadFromFile(executionSpec)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// openAPIExample returns a decoded example: of the request body of POST /
// when status is 0, else of its response with that status.
func openAPIExample(t *testing.T, doc *openapi3.T, status int, name string) any {
	t.Helper()
	op := doc.Paths.Value("/").Post
	mt := op.RequestBody.Value.Content.Get("application/json")
	if status != 0 {
		mt = op.Responses.Status(status).Value.Content.Get("application/json")
	}
	ex, ok := mt.Examples[name]
	if !ok {
		t.Fatalf("execution.yaml: no example %s (status %d)", name, status)
	}
	return ex.Value.Value
}

// returnedErrors are the errors the handler returns; Web3Signer's
// ErrMethodNotEnabled is defined but returned by no method.
var returnedErrors = []*Error{ErrParse, ErrInvalidRequest, ErrMethodNotFound, ErrInvalidParams, ErrInternal,
	ErrUnknownAccount, ErrDownstreamConnect, ErrDownstreamTimeout, ErrDownstreamResponse, ErrTxRejected,
	ErrLimitExceeded}

// The methods execution.yaml says the signer answers or never forwards are
// the handler's table, and its error codes and messages are the handler's.
func TestOpenAPIMethodsAndErrorsAreTheHandlers(t *testing.T) {
	doc := loadOpenAPI(t)
	var described []string
	for _, ref := range doc.Components.Schemas["Request"].Value.OneOf {
		s := ref.Value
		if never, ok := s.Extensions["x-never-forwarded"].([]any); ok {
			for _, m := range never {
				described = append(described, m.(string))
			}
			continue
		}
		described = append(described, s.Properties["method"].Value.Enum[0].(string))
	}
	slices.Sort(described)
	h := newFixture(t, 0, nil).handler
	if table := slices.Sorted(maps.Keys(h.methods())); !slices.Equal(described, table) {
		t.Errorf("execution.yaml describes the methods %v, the handler answers %v", described, table)
	}

	rpcError := doc.Components.Schemas["SignerRpcError"].Value
	var codes, messages []string
	for _, c := range rpcError.Properties["code"].Value.Enum {
		codes = append(codes, strconv.Itoa(int(c.(float64))))
	}
	for _, m := range rpcError.Properties["message"].Value.Enum {
		messages = append(messages, m.(string))
	}
	var wantCodes, wantMessages []string
	for _, e := range returnedErrors {
		if c := strconv.Itoa(e.Code); !slices.Contains(wantCodes, c) {
			wantCodes = append(wantCodes, c)
		}
		wantMessages = append(wantMessages, e.Message)
	}
	for _, l := range [][]string{codes, messages, wantCodes, wantMessages} {
		slices.Sort(l)
	}
	if !slices.Equal(codes, wantCodes) || !slices.Equal(messages, wantMessages) {
		t.Errorf("SignerRpcError: codes %v and messages %v, the handler's %v and %v", codes, messages, wantCodes, wantMessages)
	}
}

// openAPIFixture is the fixture the examples were made with: the two test
// accounts, the default allowlist, and a node that answers net_version
// with "1337", qrl_call with gqrl's error for a call that reverted with
// "not the owner", and qrl_sendRawTransaction with the hash of the
// qrl_sendTransaction example, or with sendErr when it is set.
func openAPIFixture(t *testing.T, doc *openapi3.T, sendErr *Error) *fixture {
	t.Helper()
	f := newFixture(t, 2, defaultAllow)
	hash := openAPIExample(t, doc, 200, MethodSendTransaction).(map[string]any)["result"]
	f.node.setHandler(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		var result any = "node:" + req.Method
		var e *Error
		switch req.Method {
		case "net_version":
			result = "1337"
		case "qrl_call":
			e = revertError("not the owner")
		case MethodSendRawTransaction:
			result, e = hash, sendErr
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(encodeResult(req.ID, result, e))
	})
	return f
}

// revertError is gqrl's error for a call that reverted with
// Error(reason): code 3, the reason in the message, and the revert data,
// the ABI encoding of Error(string), in data.
func revertError(reason string) *Error {
	word := func(n int) []byte { return new(big.Int).SetInt64(int64(n)).FillBytes(make([]byte, 32)) }
	data := []byte{0x08, 0xc3, 0x79, 0xa0} // the selector of Error(string)
	data = append(data, word(32)...)
	data = append(data, word(len(reason))...)
	data = append(data, reason...)
	data = append(data, make([]byte, (32-len(reason)%32)%32)...)
	return &Error{Code: 3, Message: "execution reverted: " + reason, Data: "0x" + hex.EncodeToString(data)}
}

// post sends a decoded example to the handler.
func postExample(t *testing.T, f *fixture, v any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return f.post(string(body), nil)
}

// jsonEqual reports whether a response body is the decoded example want.
func jsonEqual(t *testing.T, body []byte, want any) bool {
	t.Helper()
	var got any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("response %q: %v", body, err)
	}
	return reflect.DeepEqual(got, want)
}

// validateResponse checks an answer of POST / against the schema
// execution.yaml gives its status, and the result of a local method
// against the method's x-result-schema.
func validateResponse(t *testing.T, doc *openapi3.T, w *httptest.ResponseRecorder, method string) {
	t.Helper()
	resp := doc.Paths.Value("/").Post.Responses.Status(w.Code)
	if resp == nil {
		t.Fatalf("%s: execution.yaml has no response %d (%s)", method, w.Code, w.Body)
	}
	var v any
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("%s: %q: %v", method, w.Body, err)
	}
	if err := resp.Value.Content.Get("application/json").Schema.Value.VisitJSON(v, openapi3.VisitAsResponse()); err != nil {
		t.Errorf("%s: the answer does not match execution.yaml's %d schema: %v", method, w.Code, err)
	}
	single, _ := v.(map[string]any)
	for _, ref := range doc.Components.Schemas["Request"].Value.OneOf {
		if enum := ref.Value.Properties["method"].Value.Enum; single != nil && len(enum) == 1 && enum[0] == method {
			result := doc.Components.Schemas[ref.Value.Extensions["x-result-schema"].(string)].Value
			if err := result.VisitJSON(single["result"], openapi3.VisitAsResponse()); err != nil {
				t.Errorf("%s: the result does not match its x-result-schema: %v", method, err)
			}
		}
	}
}

// The handler answers each example request of execution.yaml with the
// response example of the same name, except where a hedged signature makes
// the answer differ each time: there the answer matches the schemas. A
// notification gets an empty body.
func TestOpenAPIExamplesAreTheHandlersAnswers(t *testing.T) {
	doc := loadOpenAPI(t)
	f := openAPIFixture(t, doc, nil)
	requests := doc.Paths.Value("/").Post.RequestBody.Value.Content.Get("application/json").Examples
	responseOf := map[string]string{"refused": "methodNotFound"}
	for name, ex := range requests {
		t.Run(name, func(t *testing.T) {
			w := postExample(t, f, ex.Value.Value)
			var method string
			if m, ok := ex.Value.Value.(map[string]any); ok {
				method, _ = m["method"].(string)
			}
			switch name {
			case "notification":
				if w.Code != http.StatusOK || w.Body.Len() != 0 {
					t.Fatalf("%d %q, want an empty 200", w.Code, w.Body)
				}
				return
			case MethodSign, MethodSignTransaction:
				if w.Code != http.StatusOK {
					t.Fatalf("%d %s", w.Code, w.Body)
				}
			default:
				resp := name
				if r, ok := responseOf[name]; ok {
					resp = r
				}
				if want := openAPIExample(t, doc, 200, resp); w.Code != http.StatusOK || !jsonEqual(t, w.Body.Bytes(), want) {
					t.Fatalf("%d %.300s, want the %s example", w.Code, w.Body, resp)
				}
			}
			validateResponse(t, doc, w, method)
		})
	}
}

// The error examples are the handler's answers, status, message and data
// included, to the requests that cause them, and each answer matches the
// schema of its status.
func TestOpenAPIErrorExamplesAreTheHandlersAnswers(t *testing.T) {
	doc := loadOpenAPI(t)
	f := openAPIFixture(t, doc, nil)
	_, a0 := f.key(0)
	_, a1 := f.key(1)
	tx := func(gas, chainID string) map[string]any {
		return map[string]any{"from": a0, "to": a1, "gas": gas, "maxFeePerGas": "0x2e90edd001",
			"maxPriorityFeePerGas": "0x3b9aca00", "nonce": "0x0", "chainId": chainID}
	}
	for _, tt := range []struct {
		status int
		name   string
		body   string
	}{
		{400, "parseError", "{"},
		{400, "invalidRequest", `{"jsonrpc":"1.0","id":1,"method":"x"}`},
		{400, "emptyBatch", "[]"},
		{400, "invalidParams", call(5, MethodSign, a0)},
		{200, "typedData", call(8, MethodSignTypedData)},
		{200, "unknownAccount", call(6, MethodSign, "Q"+strings.Repeat("ab", 64), "0x00")},
		{200, "chainRejected", call(9, MethodSignTransaction, tx("0x5208", "0x1"))},
		{200, "feeRejected", call(10, MethodSignTransaction, tx("0x5208000", "0x539"))},
	} {
		w := f.post(tt.body, nil)
		if want := openAPIExample(t, doc, tt.status, tt.name); w.Code != tt.status || !jsonEqual(t, w.Body.Bytes(), want) {
			t.Errorf("%s: %d %s, want %d and the example", tt.name, w.Code, w.Body, tt.status)
		}
		validateResponse(t, doc, w, tt.name)
	}

	// The node refuses the send, as gqrl refuses a transaction whose cost,
	// gas × maxFeePerGas + value, its sender's balance of 0 does not cover:
	// its own error comes back with 200.
	send := openAPIExample(t, doc, 0, MethodSendTransaction)
	sent := send.(map[string]any)["params"].([]any)[0].(map[string]any)
	quantity := func(m string) *big.Int {
		n, ok := new(big.Int).SetString(strings.TrimPrefix(sent[m].(string), "0x"), 16)
		if !ok {
			t.Fatalf("the qrl_sendTransaction example's %s: %v", m, sent[m])
		}
		return n
	}
	cost := new(big.Int).Add(new(big.Int).Mul(quantity("gas"), quantity("maxFeePerGas")), quantity("value"))
	refused := openAPIFixture(t, doc, &Error{Code: -32000, Message: fmt.Sprintf(
		"insufficient funds for gas * price + value: balance 0, tx cost %v, overshot %v", cost, cost)})
	if w, want := postExample(t, refused, send), openAPIExample(t, doc, 200, "nodeRefused"); w.Code != http.StatusOK ||
		!jsonEqual(t, w.Body.Bytes(), want) {
		t.Errorf("nodeRefused: %d %s", w.Code, w.Body)
	} else {
		validateResponse(t, doc, w, "nodeRefused")
	}

	// The node answers a send with HTTP 500.
	f.node.setHandler(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) })
	if w, want := postExample(t, f, send), openAPIExample(t, doc, 502, "invalidResponse"); w.Code != 502 ||
		!jsonEqual(t, w.Body.Bytes(), want) {
		t.Errorf("invalidResponse: %d %s", w.Code, w.Body)
	} else {
		validateResponse(t, doc, w, "invalidResponse")
	}
	// A node that is not listening, never reached before.
	gone := newNode(t)
	d := downstreamOf(t, gone.Server)
	gone.Close()
	f = newFixtureWith(t, 2, defaultAllow, d, gone)
	if w, want := postExample(t, f, openAPIExample(t, doc, 0, "forwarded")), openAPIExample(t, doc, 504, "connect"); w.Code != 504 ||
		!jsonEqual(t, w.Body.Bytes(), want) {
		t.Errorf("connect: %d %s", w.Code, w.Body)
	} else {
		validateResponse(t, doc, w, "connect")
	}
}

// The public-key example is the handler's listing of the two accounts; the
// qrl_sign example's signature verifies under the first account's listed
// key; the qrl_signTransaction example's raw transaction decodes, with
// go-qrl, to its tx member, signed by its from account for chain 1337.
func TestOpenAPIExampleSignatures(t *testing.T) {
	doc := loadOpenAPI(t)
	f := openAPIFixture(t, doc, nil)
	w := httptest.NewRecorder()
	publicKeys(f.accounts).ServeHTTP(w, httptest.NewRequest(http.MethodGet, PublicKeysPath, nil))
	listing := doc.Paths.Value(PublicKeysPath).Get.Responses.Status(200).Value.Content.Get("application/json").Example
	if !jsonEqual(t, w.Body.Bytes(), listing) {
		t.Fatal("the publicKeys example is not the handler's listing of the test accounts")
	}
	keys := map[string]mldsa87.PublicKey{}
	for _, a := range listing.([]any) {
		m := a.(map[string]any)
		b, err := hex.DecodeString(strings.TrimPrefix(m["public_key"].(string), "0x"))
		if err != nil {
			t.Fatal(err)
		}
		pk, err := mldsa87.ParsePublicKey(b)
		if err != nil {
			t.Fatal(err)
		}
		if mldsa87.ChecksumAddress(pk.Address()) != m["address"] {
			t.Fatalf("%s is not the address of its public key", m["address"])
		}
		keys[m["address"].(string)] = pk
	}

	params := openAPIExample(t, doc, 0, MethodSign).(map[string]any)["params"].([]any)
	data, ok := hexData(params[1].(string))
	sig, err := hex.DecodeString(strings.TrimPrefix(openAPIExample(t, doc, 200, MethodSign).(map[string]any)["result"].(string), "0x"))
	pk, known := keys[params[0].(string)]
	digest := TextHash(data)
	if !ok || err != nil || !known || !mldsa87.Verify(&pk, digest[:], sig) {
		t.Fatalf("the qrl_sign example's signature does not verify under its account's listed key (%v %v %v)", ok, err, known)
	}

	req := openAPIExample(t, doc, 0, MethodSignTransaction).(map[string]any)["params"].([]any)[0].(map[string]any)
	res := openAPIExample(t, doc, 200, MethodSignTransaction).(map[string]any)["result"].(map[string]any)
	raw, err := hex.DecodeString(strings.TrimPrefix(res["raw"].(string), "0x"))
	if err != nil {
		t.Fatal(err)
	}
	signed := new(types.Transaction)
	if err := signed.UnmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}
	from, err := types.Sender(types.NewZondSigner(big.NewInt(testChainID)), signed)
	if err != nil || from.Hex() != req["from"] {
		t.Fatalf("sender %s (%v), want %s", from.Hex(), err, req["from"])
	}
	txJSON, err := signed.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var tx map[string]any
	if err := json.NewDecoder(bytes.NewReader(txJSON)).Decode(&tx); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tx, res["tx"]) {
		t.Fatal("the tx member of the qrl_signTransaction example is not go-qrl's JSON of its raw transaction")
	}
	for _, m := range []string{"to", "value", "gas", "maxFeePerGas", "maxPriorityFeePerGas", "nonce", "chainId"} {
		if !strings.EqualFold(tx[m].(string), req[m].(string)) {
			t.Errorf("the signed transaction's %s is %v, the request's %v", m, tx[m], req[m])
		}
	}
}
