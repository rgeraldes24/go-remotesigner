// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package execution

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/theQRL/go-qrllib/wallet/common"
	walletmldsa87 "github.com/theQRL/go-qrllib/wallet/ml_dsa_87"
	"golang.org/x/crypto/sha3"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
)

var defaultAllow = []string{"qrl_*", "net_*", "web3_*"}

// qrl_accounts lists the loaded addresses in QIP-55 form, sorted by
// address, and takes no parameters.
func TestQRLAccounts(t *testing.T) {
	f := newFixture(t, 3, defaultAllow)
	var want []string
	for _, a := range f.accounts.List() {
		want = append(want, common.ToChecksumAddress(a.Address))
	}
	if !slices.IsSortedFunc(f.accounts.List(), func(x, y Account) int { return bytes.Compare(x.Address[:], y.Address[:]) }) {
		t.Fatal("accounts are not sorted by address")
	}
	for _, body := range []string{
		call(1, MethodAccounts),
		`{"jsonrpc":"2.0","id":1,"method":"qrl_accounts","params":[]}`,
		"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"qrl_accounts\",\"params\": [ \n\t] }",
		`{"jsonrpc":"2.0","id":1,"method":"qrl_accounts","params":null}`,
	} {
		w := f.post(body, nil)
		r := decodeOne(t, w.Body.Bytes())
		var got []string
		if w.Code != http.StatusOK || r.Error != nil || json.Unmarshal(r.Result, &got) != nil {
			t.Fatalf("%s: %d %s", body, w.Code, w.Body)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("%s: accounts %v, want %v", body, got, want)
		}
		for _, a := range got {
			if !common.IsValidChecksumAddress(a) {
				t.Errorf("%s is not a QIP-55 address", a)
			}
		}
	}
	for _, params := range []string{`["x"]`, `{}`, `[[]]`, `"x"`} {
		w := f.post(`{"jsonrpc":"2.0","id":7,"method":"qrl_accounts","params":`+params+`}`, nil)
		if r := decodeOne(t, w.Body.Bytes()); w.Code != http.StatusBadRequest || r.Error == nil ||
			r.Error.Code != ErrInvalidParams.Code || string(r.ID) != "7" {
			t.Errorf("params %s: %d %s, want 400 -32602", params, w.Code, w.Body)
		}
	}
	if n := len(f.node.received()); n != 0 {
		t.Fatalf("qrl_accounts reached the node %d times", n)
	}
}

// qrl_sign signs TextHash(data) with hedged ML-DSA-87: the raw 4,627-byte
// signature verifies with go-qrllib under the account's public key and the
// descriptor 01 00 00, and two signatures of the same data differ.
func TestQRLSignVerifiesWithGoQRLLib(t *testing.T) {
	f := newFixture(t, 2, defaultAllow)
	k, addr := f.key(1)
	pk := k.PublicKey()
	desc, err := walletmldsa87.NewMLDSA87Descriptor()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("message to sign")
	var sigs [][]byte
	for range 2 {
		w := f.post(call(1, MethodSign, addr, "0x"+hex.EncodeToString(data)), nil)
		r := decodeOne(t, w.Body.Bytes())
		var sigHex string
		if w.Code != http.StatusOK || r.Error != nil || json.Unmarshal(r.Result, &sigHex) != nil {
			t.Fatalf("qrl_sign: %d %s", w.Code, w.Body)
		}
		sig, err := hex.DecodeString(strings.TrimPrefix(sigHex, "0x"))
		if err != nil || len(sig) != mldsa87.SignatureSize || mldsa87.SignatureSize != 4627 {
			t.Fatalf("signature of %d bytes (%v)", len(sig), err)
		}
		digest := TextHash(data)
		if !walletmldsa87.Verify(digest[:], sig, (*walletmldsa87.PK)(&pk), [3]byte(desc)) {
			t.Fatal("the qrl_sign signature does not verify with go-qrllib")
		}
		sigs = append(sigs, sig)
	}
	if bytes.Equal(sigs[0], sigs[1]) {
		t.Fatal("two signatures of the same data are identical: not hedged")
	}
	// Either case after the Q finds the account; the Q is never folded.
	lower := "Q" + strings.ToLower(addr[1:])
	if r := decodeOne(t, f.post(call(2, MethodSign, lower, "0x"), nil).Body.Bytes()); r.Error != nil {
		t.Fatalf("lower-case address: %+v", r.Error)
	}
	if n := len(f.node.received()); n != 0 {
		t.Fatalf("qrl_sign reached the node %d times", n)
	}
}

// TextHash is go-qrl's accounts.TextHash: the value for "Hello Joe" is the
// one go-qrl's own accounts test expects, and the empty Keccak-256 is the
// algorithm's published value (not SHA3-256's).
func TestTextHash(t *testing.T) {
	if h := TextHash([]byte("Hello Joe")); hex.EncodeToString(h[:]) !=
		"1e5ec1e5c116994bf377af15a5997a992650145ca8d5b00eb77d4c8aa5f245c4" {
		t.Fatalf("TextHash(Hello Joe) = %x", h)
	}
	k := sha3.NewLegacyKeccak256()
	if got := hex.EncodeToString(k.Sum(nil)); got != "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" {
		t.Fatalf("Keccak-256 of nothing = %s", got)
	}
}

func TestQRLSignRefusals(t *testing.T) {
	f := newFixture(t, 1, defaultAllow)
	_, addr := f.key(0)
	unknown := "Q" + strings.Repeat("ab", 64)
	tests := []struct {
		name   string
		params string
		code   int
		status int
	}{
		{"unknown address", `["` + unknown + `","0x00"]`, ErrUnknownAccount.Code, http.StatusOK},
		{"no params", `[]`, ErrInvalidParams.Code, http.StatusBadRequest},
		{"one param", `["` + addr + `"]`, ErrInvalidParams.Code, http.StatusBadRequest},
		{"three params", `["` + addr + `","0x00","0x00"]`, ErrInvalidParams.Code, http.StatusBadRequest},
		{"object params", `{"address":"` + addr + `"}`, ErrInvalidParams.Code, http.StatusBadRequest},
		{"number address", `[1,"0x00"]`, ErrInvalidParams.Code, http.StatusBadRequest},
		{"0x address", `["0x` + addr[1:] + `","0x00"]`, ErrInvalidParams.Code, http.StatusBadRequest},
		{"lower-case q", `["q` + addr[1:] + `","0x00"]`, ErrInvalidParams.Code, http.StatusBadRequest},
		{"short address", `["` + addr[:40] + `","0x00"]`, ErrInvalidParams.Code, http.StatusBadRequest},
		{"text data", `["` + addr + `","hello"]`, ErrInvalidParams.Code, http.StatusBadRequest},
		{"odd hex", `["` + addr + `","0x123"]`, ErrInvalidParams.Code, http.StatusBadRequest},
		{"bad hex", `["` + addr + `","0xzz"]`, ErrInvalidParams.Code, http.StatusBadRequest},
		{"no params member", ``, ErrInvalidParams.Code, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := `{"jsonrpc":"2.0","id":"s","method":"qrl_sign","params":` + tt.params + `}`
			if tt.params == "" {
				body = call("s", MethodSign)
			}
			w := f.post(body, nil)
			r := decodeOne(t, w.Body.Bytes())
			if w.Code != tt.status || r.Error == nil || r.Error.Code != tt.code || string(r.ID) != `"s"` {
				t.Fatalf("%d %s, want %d error %d", w.Code, w.Body, tt.status, tt.code)
			}
		})
	}
	if n := len(f.node.received()); n != 0 {
		t.Fatalf("a refused qrl_sign reached the node %d times", n)
	}
}

// health_status answers OK; the transaction methods are refused with
// "method not enabled" and typed data with "method not found", and none of
// them reaches the node, even when every method may be forwarded.
func TestLocalMethodsNeverForwarded(t *testing.T) {
	f := newFixture(t, 1, []string{"*"})
	w := f.post(call(1, MethodHealthStatus), nil)
	if r := decodeOne(t, w.Body.Bytes()); string(r.Result) != `"OK"` {
		t.Fatalf("health_status: %s", w.Body)
	}
	for method, code := range map[string]int{
		MethodSignTransaction: ErrMethodNotEnabled.Code,
		MethodSendTransaction: ErrMethodNotEnabled.Code,
		MethodSignTypedData:   ErrMethodNotFound.Code,
	} {
		w := f.post(call(9, method, map[string]any{"from": "Q00"}), nil)
		r := decodeOne(t, w.Body.Bytes())
		if w.Code != http.StatusOK || r.Error == nil || r.Error.Code != code {
			t.Errorf("%s: %d %s, want error %d", method, w.Code, w.Body, code)
		}
	}
	w = f.post(batch(call(1, MethodSendTransaction), call(2, MethodSignTransaction), call(3, MethodSignTypedData)), nil)
	for _, r := range decodeBatch(t, w.Body.Bytes()) {
		if r.Error == nil {
			t.Errorf("batch element %s answered %s", r.ID, r.Result)
		}
	}
	if n := len(f.node.received()); n != 0 {
		t.Fatalf("a local method reached the node %d times", n)
	}
}

// The default allowlist forwards qrl_*, net_* and web3_*; admin_*, debug_*,
// personal_*, miner_*, txpool_*, eth_* and account_* (clef's signing
// methods included) get -32601 and never reach the node.
func TestAllowlistBlocksMethods(t *testing.T) {
	f := newFixture(t, 1, defaultAllow)
	for _, m := range []string{"admin_addPeer", "admin_nodeInfo", "debug_traceTransaction", "personal_unlockAccount",
		"miner_start", "txpool_content", "eth_sendTransaction", "account_signData", "account_signTypedData",
		"QRL_sign", "Qrl_blockNumber"} {
		w := f.post(call(1, m, "x"), nil)
		if r := decodeOne(t, w.Body.Bytes()); w.Code != http.StatusOK || r.Error == nil ||
			r.Error.Code != ErrMethodNotFound.Code || string(r.ID) != "1" {
			t.Errorf("%s: %d %s, want -32601", m, w.Code, w.Body)
		}
	}
	if n := len(f.node.received()); n != 0 {
		t.Fatalf("a refused method reached the node %d times", n)
	}
	for _, m := range []string{"qrl_blockNumber", "net_version", "web3_clientVersion"} {
		w := f.post(call(1, m), nil)
		if r := decodeOne(t, w.Body.Bytes()); string(r.Result) != `"node:`+m+`"` {
			t.Errorf("%s: %s, want the node's answer", m, w.Body)
		}
	}
	if n := len(f.node.received()); n != 3 {
		t.Fatalf("%d forwarded requests, want 3", n)
	}

	all := newFixture(t, 1, []string{"*"})
	if r := decodeOne(t, all.post(call(1, "admin_nodeInfo"), nil).Body.Bytes()); string(r.Result) != `"node:admin_nodeInfo"` {
		t.Fatalf("* did not forward admin_nodeInfo: %+v", r)
	}
}

// The node runs the method the allowlist checked. gqrl decodes a request
// into a struct with encoding/json, which also takes member names in another
// case, the last one winning; the signer reads "method" exactly. Forwarding
// the client's bytes would let a second "METHOD" member carry admin_* or a
// transaction method past the allowlist, so every forwarded request, single
// or in a batch, is the signer's own encoding of the four members it read.
func TestForwardedRequestIsTheCheckedOne(t *testing.T) {
	f := newFixture(t, 0, defaultAllow)
	smuggling := []string{
		`{"jsonrpc":"2.0","id":1,"method":"qrl_blockNumber","METHOD":"admin_addPeer","params":["enode://x"]}`,
		`{"jsonrpc":"2.0","id":1,"method":"qrl_blockNumber","Method":"qrl_signTransaction","params":[{}]}`,
		`{"jsonrpc":"2.0","id":1,"method":"qrl_blockNumber","mEtHoD":"personal_unlockAccount","extra":true}`,
		`{"jsonrpc":"2.0","id":1,"method":"admin_addPeer","method":"qrl_blockNumber"}`,
	}
	for _, body := range smuggling {
		if r := decodeOne(t, f.post(body, nil).Body.Bytes()); string(r.Result) != `"node:qrl_blockNumber"` {
			t.Errorf("%s: %+v %s, want the node's qrl_blockNumber", body, r.Error, r.Result)
		}
	}
	for i, r := range decodeBatch(t, f.post(batch(smuggling...), nil).Body.Bytes()) {
		if string(r.Result) != `"node:qrl_blockNumber"` {
			t.Errorf("batch element %d: %+v %s, want the node's qrl_blockNumber", i, r.Error, r.Result)
		}
	}

	got := f.node.received()
	if len(got) != len(smuggling)+1 {
		t.Fatalf("the node received %d requests, want %d", len(got), len(smuggling)+1)
	}
	var sent []json.RawMessage
	for i, r := range got {
		if i < len(smuggling) {
			sent = append(sent, r.body)
			continue
		}
		var elems []json.RawMessage
		if err := json.Unmarshal(r.body, &elems); err != nil {
			t.Fatal(err)
		}
		sent = append(sent, elems...)
	}
	for _, s := range sent {
		var gqrl struct {
			Method string `json:"method"`
		}
		var members map[string]json.RawMessage
		if json.Unmarshal(s, &gqrl) != nil || json.Unmarshal(s, &members) != nil || gqrl.Method != "qrl_blockNumber" {
			t.Fatalf("the node received %s", s)
		}
		for name := range members {
			if name != "jsonrpc" && name != "id" && name != "method" && name != "params" {
				t.Errorf("the node received member %q: %s", name, s)
			}
		}
	}
}

// A batch is split: local requests are answered by the signer, refused ones
// get -32601 and never reach the node, the rest go to the node as one
// batch, and the responses come back in request order with the client's
// ids, repeated and null ids included.
func TestBatchSplitting(t *testing.T) {
	f := newFixture(t, 2, defaultAllow)
	_, addr := f.key(0)
	body := batch(
		call(1, MethodAccounts),
		call("a", "qrl_blockNumber"),
		call(3, "admin_addPeer", "enode://x"),
		call(4, MethodSign, addr, "0x01"),
		call(1, "net_version"),        // repeats id 1
		call(nil, "qrl_chainId"),      // a notification: forwarded, no response
		call(nil, MethodHealthStatus), // a local notification: no response
		call(nil, "debug_x"),          // a refused notification: no response
		`{"jsonrpc":"1.0","id":9,"method":"qrl_blockNumber"}`,
		`42`,
		call(json.RawMessage("null"), "web3_clientVersion"),
	)
	w := f.post(body, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	rs := decodeBatch(t, w.Body.Bytes())
	want := []struct {
		id     string
		result string // a JSON value, or "" for an error
		code   int
	}{
		{"1", "[", 0},
		{`"a"`, `"node:qrl_blockNumber"`, 0},
		{"3", "", ErrMethodNotFound.Code},
		{"4", `"0x`, 0},
		{"1", `"node:net_version"`, 0},
		{"9", "", ErrInvalidRequest.Code},
		{"null", "", ErrInvalidRequest.Code},
		{"null", `"node:web3_clientVersion"`, 0},
	}
	if len(rs) != len(want) {
		t.Fatalf("%d responses, want %d: %s", len(rs), len(want), w.Body)
	}
	for i, wnt := range want {
		r := rs[i]
		if string(r.ID) != wnt.id {
			t.Errorf("response %d: id %s, want %s", i, r.ID, wnt.id)
		}
		switch {
		case wnt.code != 0 && (r.Error == nil || r.Error.Code != wnt.code):
			t.Errorf("response %d: %s %+v, want error %d", i, r.Result, r.Error, wnt.code)
		case wnt.code == 0 && (r.Error != nil || !strings.HasPrefix(string(r.Result), wnt.result)):
			t.Errorf("response %d: %s %+v, want %s…", i, r.Result, r.Error, wnt.result)
		}
	}

	got := f.node.received()
	if len(got) != 1 {
		t.Fatalf("the node received %d requests, want one batch", len(got))
	}
	var sent []map[string]json.RawMessage
	if err := json.Unmarshal(got[0].body, &sent); err != nil {
		t.Fatal(err)
	}
	var methods []string
	for _, s := range sent {
		var m string
		_ = json.Unmarshal(s["method"], &m)
		methods = append(methods, m+"#"+string(s["id"]))
	}
	if !slices.Equal(methods, []string{"qrl_blockNumber#1", "net_version#4", "qrl_chainId#", "web3_clientVersion#10"}) {
		t.Fatalf("the node received %v", methods)
	}
}

// A batch of forwarded requests only is relayed through the same split, so
// that every response carries the client's id.
func TestBatchAllForwarded(t *testing.T) {
	f := newFixture(t, 0, defaultAllow)
	w := f.post(batch(call(7, "qrl_blockNumber"), call(7, "qrl_gasPrice")), nil)
	rs := decodeBatch(t, w.Body.Bytes())
	if len(rs) != 2 || string(rs[0].ID) != "7" || string(rs[1].ID) != "7" ||
		string(rs[0].Result) != `"node:qrl_blockNumber"` || string(rs[1].Result) != `"node:qrl_gasPrice"` {
		t.Fatalf("responses %s", w.Body)
	}
}

func TestBatchLimits(t *testing.T) {
	f := newFixture(t, 1, defaultAllow)
	for _, tt := range []struct {
		name string
		n    int
		ok   bool
	}{{"empty", 0, false}, {"one", 1, true}, {"the limit", MaxBatch, true}, {"over the limit", MaxBatch + 1, false}} {
		t.Run(tt.name, func(t *testing.T) {
			calls := make([]string, tt.n)
			for i := range calls {
				calls[i] = call(i, MethodHealthStatus)
			}
			w := f.post(batch(calls...), nil)
			if tt.ok {
				if w.Code != http.StatusOK || len(decodeBatch(t, w.Body.Bytes())) != tt.n {
					t.Fatalf("%d %.200s", w.Code, w.Body)
				}
				return
			}
			r := decodeOne(t, w.Body.Bytes())
			if w.Code != http.StatusBadRequest || r.Error == nil || r.Error.Code != ErrInvalidRequest.Code {
				t.Fatalf("%d %s, want 400 -32600", w.Code, w.Body)
			}
		})
	}
}

// An oversized batch is refused before its elements are decoded: a body
// of the largest size, of tiny elements, costs a small part of its own size
// in allocations, not tens of times it. An array that is not valid JSON is
// a parse error at any size.
func TestBatchOversizedAllocation(t *testing.T) {
	f := newFixture(t, 0, defaultAllow)
	for _, elem := range []string{"1", "{}", `"a"`} {
		n := (BodyLimit - 2) / (len(elem) + 1)
		body := []byte("[" + strings.Repeat(elem+",", n-1) + elem + "]")
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		f.handler.serveBatch(w, r, body)
		runtime.ReadMemStats(&after)
		allocated := after.TotalAlloc - before.TotalAlloc
		if allocated > uint64(len(body))/8 {
			t.Errorf("%s: %d bytes allocated for a body of %d", elem, allocated, len(body))
		}
		resp := decodeOne(t, w.Body.Bytes())
		if w.Code != http.StatusBadRequest || resp.Error == nil || resp.Error.Code != ErrInvalidRequest.Code {
			t.Errorf("%s: %d %s, want 400 -32600", elem, w.Code, w.Body)
		}
	}
	w := f.post("["+strings.Repeat("1,", 2*MaxBatch)+"}", nil)
	if r := decodeOne(t, w.Body.Bytes()); w.Code != http.StatusBadRequest || r.Error == nil || r.Error.Code != ErrParse.Code {
		t.Errorf("an invalid oversized array: %d %s, want 400 -32700", w.Code, w.Body)
	}
}

// allocatedBy returns the bytes allocated while fn ran.
func allocatedBy(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// manyMembers renders a call of method of size bytes or a few fewer: its
// own members, then as many tiny members as fit, under the names key(0),
// key(1) and so on, each a JSON string's contents.
func manyMembers(method string, size int, key func(int) string) string {
	var b strings.Builder
	b.WriteString(strings.TrimSuffix(call(1, method), "}"))
	for i := 0; ; i++ {
		m := `,"` + key(i) + `":0`
		if b.Len()+len(m)+1 > size {
			break
		}
		b.WriteString(m)
	}
	b.WriteByte('}')
	return b.String()
}

// The members of a request that it does not define are stepped over, not
// collected, and a batch's elements are found in place, not copied: a
// request of the largest size, of tiny members under distinct names, plain
// or escaped, costs a small part of its own size in allocations, sent alone
// or as a batch of one, and the node gets the four members alone.
func TestManyMembersAllocation(t *testing.T) {
	f := newFixture(t, 0, defaultAllow)
	const forwarded = `{"jsonrpc":"2.0","id":%d,"method":"qrl_blockNumber"}`
	for _, key := range []struct {
		name string
		key  func(int) string
	}{
		{"plain names", func(i int) string { return strconv.FormatInt(int64(i), 16) }},
		{"escaped names", func(i int) string { return `\u0061` + strconv.FormatInt(int64(i), 16) }},
	} {
		for _, form := range []struct {
			name  string
			body  func(size int) []byte
			serve func(w http.ResponseWriter, r *http.Request, body []byte)
			batch bool
			sent  string // what the node gets
		}{
			{"single",
				func(size int) []byte { return []byte(manyMembers("qrl_blockNumber", size, key.key)) },
				f.handler.serveSingle, false, fmt.Sprintf(forwarded, 1)},
			{"batch of one",
				func(size int) []byte { return []byte("[" + manyMembers("qrl_blockNumber", size-2, key.key) + "]") },
				f.handler.serveBatch, true, "[" + fmt.Sprintf(forwarded, 0) + "]"},
		} {
			t.Run(key.name+", "+form.name, func(t *testing.T) {
				body := form.body(BodyLimit)
				before := len(f.node.received())
				w := httptest.NewRecorder()
				allocated := allocatedBy(func() {
					form.serve(w, httptest.NewRequest(http.MethodPost, "/", nil), body)
				})
				if allocated > uint64(len(body))/8 {
					t.Errorf("%d bytes allocated for a body of %d", allocated, len(body))
				}
				var r rpcResponse
				if form.batch {
					if rs := decodeBatch(t, w.Body.Bytes()); len(rs) == 1 {
						r = rs[0]
					}
				} else {
					r = decodeOne(t, w.Body.Bytes())
				}
				if w.Code != http.StatusOK || string(r.ID) != "1" || string(r.Result) != `"node:qrl_blockNumber"` {
					t.Errorf("%d %s", w.Code, w.Body)
				}
				got := f.node.received()
				if len(got) != before+1 || string(got[before].body) != form.sent {
					t.Errorf("the node received %d requests, the last %.200s", len(got)-before, got[len(got)-1].body)
				}
			})
		}
	}
}

// The params of a local method are read no further than the parameters it
// takes: a call of the largest size whose params are an array of tiny
// elements costs a small part of its size in allocations, alone or in a
// batch, and is refused with -32602.
func TestLocalParamsAllocation(t *testing.T) {
	f := newFixture(t, 1, defaultAllow)
	_, addr := f.key(0)
	for _, method := range []string{MethodSign, MethodAccounts} {
		for _, inBatch := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, in a batch %v", method, inBatch), func(t *testing.T) {
				head := `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":["` + addr + `"`
				if inBatch {
					head = "[" + head
				}
				var b strings.Builder
				b.WriteString(head)
				for b.Len()+len(" ,1")+len("]}]") <= BodyLimit {
					b.WriteString(" ,1")
				}
				b.WriteString("]}")
				serve := f.handler.serveSingle
				if inBatch {
					b.WriteString("]")
					serve = f.handler.serveBatch
				}
				body := []byte(b.String())
				w := httptest.NewRecorder()
				allocated := allocatedBy(func() { serve(w, httptest.NewRequest(http.MethodPost, "/", nil), body) })
				if allocated > uint64(len(body))/8 {
					t.Errorf("%d bytes allocated for a body of %d", allocated, len(body))
				}
				var r rpcResponse
				if inBatch {
					if rs := decodeBatch(t, w.Body.Bytes()); len(rs) == 1 {
						r = rs[0]
					}
				} else {
					r = decodeOne(t, w.Body.Bytes())
				}
				if r.Error == nil || r.Error.Code != ErrInvalidParams.Code || string(r.ID) != "1" {
					t.Errorf("%d %s, want -32602", w.Code, w.Body)
				}
			})
		}
	}
	if n := len(f.node.received()); n != 0 {
		t.Fatalf("the node received %d requests", n)
	}
}

// A batch's local work stops when the client goes: no local request runs
// after its context ends, and no response is written.
func TestBatchStopsWhenTheClientGoes(t *testing.T) {
	f := newFixture(t, 0, defaultAllow)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var ran int
	f.handler.table["test_count"] = func(context.Context, *Request) (any, *Error) {
		if ran++; ran == 3 {
			cancel()
		}
		return "ok", nil
	}
	calls := make([]string, 10)
	for i := range calls {
		calls[i] = call(i, "test_count")
	}
	r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/", strings.NewReader(batch(calls...)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	if ran != 3 || w.Body.Len() != 0 {
		t.Fatalf("%d local requests ran, %d bytes written; want 3 and none", ran, w.Body.Len())
	}
}

// When the node fails a batch, each forwarded call gets the error and the
// local calls are still answered.
func TestBatchDownstreamFailures(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		data    string
	}{
		{"status 500", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }, "status 500"},
		{"redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://169.254.169.254/", http.StatusFound)
		}, "status 302"},
		{"single object", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(encodeResult(nullID, nil, ErrInvalidRequest))
		}, "not a JSON-RPC batch response"},
		{"a call unanswered", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`[]`)) },
			"no response to the request"},
		{"a wrong id", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`[{"jsonrpc":"2.0","id":5,"result":"x"}]`))
		}, "no response to the request"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, 1, defaultAllow)
			f.node.setHandler(tt.handler)
			rs := decodeBatch(t, f.post(batch(call(1, MethodHealthStatus), call(2, "qrl_blockNumber")), nil).Body.Bytes())
			if len(rs) != 2 || string(rs[0].Result) != `"OK"` {
				t.Fatalf("responses %+v", rs)
			}
			e := rs[1].Error
			if e == nil || e.Code != ErrDownstreamResponse.Code || e.Data != tt.data || string(rs[1].ID) != "2" {
				t.Fatalf("forwarded call: %+v, want -32000 %q", e, tt.data)
			}
		})
	}
}

// Requests that are not JSON-RPC 2.0 are refused before any method runs.
func TestInvalidRequests(t *testing.T) {
	f := newFixture(t, 1, []string{"*"})
	tests := []struct {
		body   string
		status int
		code   int
		id     string
	}{
		{`{`, http.StatusBadRequest, ErrParse.Code, "null"},
		{`not json`, http.StatusBadRequest, ErrParse.Code, "null"},
		{`[{`, http.StatusBadRequest, ErrParse.Code, "null"},
		{`"x"`, http.StatusBadRequest, ErrInvalidRequest.Code, "null"},
		{`{"username":"u","password":"p"}`, http.StatusBadRequest, ErrInvalidRequest.Code, "null"},
		{`{"jsonrpc":"2.0","id":1}`, http.StatusBadRequest, ErrInvalidRequest.Code, "1"},
		{`{"jsonrpc":"2.0","id":1,"method":""}`, http.StatusBadRequest, ErrInvalidRequest.Code, "1"},
		{`{"jsonrpc":"2.0","id":1,"method":7}`, http.StatusBadRequest, ErrInvalidRequest.Code, "1"},
		{`{"jsonrpc":"1.0","id":"x","method":"qrl_accounts"}`, http.StatusBadRequest, ErrInvalidRequest.Code, `"x"`},
		{`{"id":1,"method":"qrl_accounts"}`, http.StatusBadRequest, ErrInvalidRequest.Code, "1"},
		{`{"jsonrpc":"2.0","id":{"a":1},"method":"qrl_accounts"}`, http.StatusBadRequest, ErrInvalidRequest.Code, "null"},
		{`{"jsonrpc":"2.0","id":true,"method":"qrl_accounts"}`, http.StatusBadRequest, ErrInvalidRequest.Code, "null"},
	}
	for _, tt := range tests {
		w := f.post(tt.body, nil)
		r := decodeOne(t, w.Body.Bytes())
		if w.Code != tt.status || r.Error == nil || r.Error.Code != tt.code || string(r.ID) != tt.id {
			t.Errorf("%s: %d %s, want %d error %d id %s", tt.body, w.Code, w.Body, tt.status, tt.code, tt.id)
		}
	}
	if n := len(f.node.received()); n != 0 {
		t.Fatalf("an invalid request reached the node %d times", n)
	}
}

// Notifications get no response: a single one an empty 200, a batch of
// them an empty 200 too. Forwarded notifications still reach the node.
func TestNotifications(t *testing.T) {
	f := newFixture(t, 1, defaultAllow)
	for _, body := range []string{call(nil, MethodHealthStatus), call(nil, "admin_addPeer"),
		batch(call(nil, MethodAccounts), call(nil, "debug_x"))} {
		if w := f.post(body, nil); w.Code != http.StatusOK || w.Body.Len() != 0 {
			t.Errorf("%s: %d %q, want an empty 200", body, w.Code, w.Body)
		}
	}
	if n := len(f.node.received()); n != 0 {
		t.Fatalf("the node received %d requests", n)
	}
	if w := f.post(batch(call(nil, "qrl_chainId")), nil); w.Code != http.StatusOK || w.Body.Len() != 0 {
		t.Fatalf("forwarded notification: %d %q", w.Code, w.Body)
	}
	if n := len(f.node.received()); n != 1 {
		t.Fatalf("the forwarded notification reached the node %d times", n)
	}
}

func TestStatusOf(t *testing.T) {
	for e, want := range map[*Error]int{
		nil: 200, ErrParse: 400, ErrInvalidRequest: 400, ErrInvalidParams: 400, ErrInternal: 500,
		ErrMethodNotFound: 200, ErrMethodNotEnabled: 200, ErrUnknownAccount: 200, ErrInvalidParams.with("x"): 400,
	} {
		if got := statusOf(e); got != want {
			t.Errorf("statusOf(%v) = %d, want %d", e, got, want)
		}
	}
}
