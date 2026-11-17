// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package execution

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/theQRL/go-qrl/common"
	"github.com/theQRL/go-qrl/common/hexutil"
	"github.com/theQRL/go-qrl/core/types"
)

// sendFixture is a Handler in front of the fake gqrl node.
func sendFixture(t *testing.T, accounts int) (*fixture, *fakeGQRL) {
	t.Helper()
	g, nd := newFakeGQRL(t)
	return newFixtureWith(t, accounts, defaultAllow, downstreamOf(t, nd.Server), nd), g
}

// sendTx sends a qrl_sendTransaction and returns the response.
func (f *fixture) sendTx(t *testing.T, id any, tx map[string]any) (int, rpcResponse) {
	t.Helper()
	w := f.post(call(id, MethodSendTransaction, tx), nil)
	return w.Code, decodeOne(t, w.Body.Bytes())
}

// A complete transaction is signed and sent with qrl_sendRawTransaction
// under the client's id, and the node's answer is relayed; the node is not
// asked to fill anything.
func TestSendTransactionComplete(t *testing.T) {
	f, g := sendFixture(t, 1)
	_, addr := f.key(0)
	code, r := f.sendTx(t, "client-7", fullTx(addr))
	if code != http.StatusOK || r.Error != nil || string(r.ID) != `"client-7"` {
		t.Fatalf("%d %+v %s", code, r.Error, r.ID)
	}
	sent := g.sentTxs()
	if len(sent) != 1 || `"`+sent[0].Hash().Hex()+`"` != string(r.Result) {
		t.Fatalf("result %s, sent %d", r.Result, len(sent))
	}
	if got := g.methods(); !slices.Equal(got, []string{MethodSendRawTransaction}) {
		t.Fatalf("the node got %v", got)
	}
	if raw := g.callsOf(MethodSendRawTransaction)[0]; string(raw.ID) != `"client-7"` {
		t.Fatalf("qrl_sendRawTransaction id %s, want the client's", raw.ID)
	}
	// The node's encoder writes <, >, &, U+2028 and U+2029 in the id as \u
	// escapes, and the client may have written them raw or escaped: the
	// answer is still the node's answer to that id, and the client gets it.
	params, _ := json.Marshal([]any{fullTx(addr, "nonce", "")})
	for _, id := range []string{`"<a&b>"`, "\"\u2028\u2029\"", `"\u003ca\u0026b\u003e"`, `"a\/b"`, `-1.50`, `null`} {
		sent := len(g.sentTxs())
		w := f.post(`{"jsonrpc":"2.0","id":`+id+`,"method":"`+MethodSendTransaction+`","params":`+string(params)+`}`, nil)
		r := decodeOne(t, w.Body.Bytes())
		if w.Code != http.StatusOK || r.Error != nil || !sameID(r.ID, json.RawMessage(id)) {
			t.Fatalf("id %s: %d %s", id, w.Code, w.Body)
		}
		if got := g.sentTxs(); len(got) != sent+1 || `"`+got[sent].Hash().Hex()+`"` != string(r.Result) {
			t.Fatalf("id %s: result %s, %d sent", id, r.Result, len(got)-sent)
		}
	}
}

// Two ids are the same id when they decode alike, whatever escapes the
// encoders chose; a string is never a number, and a number is compared as
// written.
func TestSameID(t *testing.T) {
	for _, tt := range []struct {
		a, b string
		same bool
	}{
		{`"a&b"`, `"a\u0026b"`, true},
		{`"<\u2028>"`, `"\u003c\u2028\u003e"`, true},
		{`"\u00e9"`, `"é"`, true},
		{`7`, `7`, true},
		{`null`, ` null `, true},
		{`"7"`, `7`, false},
		{`7`, `7.0`, false},
		{`"a"`, `"b"`, false},
		{`null`, `"null"`, false},
		{`{}`, `{}`, false},
		{`[1]`, `[1]`, false},
		{``, ``, false},
		{`1 2`, `1 2`, false},
	} {
		if got := sameID(json.RawMessage(tt.a), json.RawMessage(tt.b)); got != tt.same {
			t.Errorf("sameID(%s, %s) = %v", tt.a, tt.b, got)
		}
	}
}

// Without a nonce, gas, a fee cap or a chain ID the signer asks the node
// with qrl_fillTransaction, sending its own encoding of the request; it
// takes the nonce, gas and fees from the answer, cross-checks a filled
// nonce with qrl_getTransactionCount(from, "pending"), and signs.
func TestSendTransactionFill(t *testing.T) {
	f, g := sendFixture(t, 1)
	_, addr := f.key(0)
	g.set(func(g *fakeGQRL) { g.nonces[common.Address(f.accounts.List()[0].Address)] = 5 })
	tx := txObject("from", addr, "to", recipient, "value", "0x1", "data", "0xabcd")
	code, r := f.sendTx(t, 1, tx)
	if code != http.StatusOK || r.Error != nil {
		t.Fatalf("%d %+v", code, r.Error)
	}
	if got := g.methods(); !slices.Equal(got, []string{MethodFillTransaction, MethodGetTransactionCount, MethodSendRawTransaction}) {
		t.Fatalf("the node got %v", got)
	}
	var fill []map[string]json.RawMessage
	if err := json.Unmarshal(g.callsOf(MethodFillTransaction)[0].Params, &fill); err != nil || len(fill) != 1 {
		t.Fatalf("fill params: %v", err)
	}
	var members []string
	for k := range fill[0] {
		members = append(members, k)
	}
	slices.Sort(members)
	if !slices.Equal(members, []string{"from", "input", "to", "value"}) || string(fill[0]["input"]) != `"0xabcd"` {
		t.Fatalf("fill args %v", members)
	}
	sent := g.sentTxs()
	if len(sent) != 1 || sent[0].Nonce() != 5 || sent[0].Gas() != 21_000 || sent[0].GasFeeCap().Int64() != 3 ||
		sent[0].GasTipCap().Int64() != 1 || sent[0].ChainId().Int64() != testChainID {
		t.Fatalf("sent %+v", sent)
	}
	// Each field the request has is the request's, whatever the node answers.
	g.set(func(g *fakeGQRL) {
		g.onFill = func(_ map[string]json.RawMessage, tx *types.DynamicFeeTx) {
			tx.Gas, tx.GasFeeCap, tx.GasTipCap = 99_999, big.NewInt(50), big.NewInt(40)
		}
	})
	code, r = f.sendTx(t, 2, fullTx(addr, "nonce", "0x6", "chainId", ""))
	if code != http.StatusOK || r.Error != nil {
		t.Fatalf("%d %+v", code, r.Error)
	}
	if s := g.sentTxs()[1]; s.Gas() != 21000 || s.GasFeeCap().String() != "200000000001" || s.Nonce() != 6 {
		t.Fatalf("sent %+v", s)
	}
}

// The payload check: a node that answers qrl_fillTransaction with another
// to, value, input, access list or chain ID, or with another type of
// transaction, is refused, and nothing is signed or sent. An absent access
// list is empty and an absent chainId is --chain-id. The sender is always
// the request's from, whatever the answer names.
func TestSendTransactionPayloadCheck(t *testing.T) {
	other := common.Address{0x22}
	tests := []struct {
		name  string
		field string
		edit  func(tx *types.DynamicFeeTx)
	}{
		{"to", "to", func(tx *types.DynamicFeeTx) { tx.To = &other }},
		{"to removed", "to", func(tx *types.DynamicFeeTx) { tx.To = nil }},
		{"value", "value", func(tx *types.DynamicFeeTx) { tx.Value = new(big.Int).Add(tx.Value, big.NewInt(1)) }},
		{"input", "input", func(tx *types.DynamicFeeTx) { tx.Data = append(tx.Data, 0) }},
		{"input dropped", "input", func(tx *types.DynamicFeeTx) { tx.Data = nil }},
		{"access list", "accessList", func(tx *types.DynamicFeeTx) {
			tx.AccessList = types.AccessList{{Address: other}}
		}},
		{"chain ID", "chainId", func(tx *types.DynamicFeeTx) { tx.ChainID = big.NewInt(1) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, g := sendFixture(t, 1)
			_, addr := f.key(0)
			g.set(func(g *fakeGQRL) {
				g.onFill = func(_ map[string]json.RawMessage, tx *types.DynamicFeeTx) { tt.edit(tx) }
			})
			code, r := f.sendTx(t, 1, txObject("from", addr, "to", recipient, "value", "0x10", "input", "0x01"))
			if code != http.StatusOK || r.Error == nil || r.Error.Code != ErrTxRejected.Code ||
				r.Error.Data != "the node's qrl_fillTransaction answer changed the transaction's "+tt.field {
				t.Fatalf("%d %+v", code, r.Error)
			}
			if g.callsOf(MethodSendRawTransaction) != nil {
				t.Fatal("a refused transaction was sent")
			}
		})
	}
	t.Run("defaults", func(t *testing.T) {
		f, g := sendFixture(t, 1)
		_, addr := f.key(0)
		if code, r := f.sendTx(t, 1, txObject("from", addr, "to", recipient)); code != http.StatusOK || r.Error != nil {
			t.Fatalf("%d %+v", code, r.Error)
		}
		s := g.sentTxs()[0]
		if s.Value().Sign() != 0 || len(s.AccessList()) != 0 || s.ChainId().Int64() != testChainID || len(s.Data()) != 0 {
			t.Fatalf("sent %+v", s)
		}
	})
	t.Run("from is the request's", func(t *testing.T) {
		// go-qrl's transaction has no from. A node that names another loaded
		// account as from in its answer changes nothing: the request's from
		// selects the key, and the sent transaction is that account's.
		f, g := sendFixture(t, 2)
		_, addr := f.key(0)
		_, other := f.key(1)
		g.set(func(g *fakeGQRL) { g.nonces[common.Address(f.accounts.List()[1].Address)] = 9 })
		var mu sync.Mutex
		rewrote := false
		f.node.setHandler(func(w http.ResponseWriter, r *http.Request) {
			rec := httptest.NewRecorder()
			g.serve(rec, r)
			data := rec.Body.Bytes()
			var resp, result, tx map[string]json.RawMessage
			if json.Unmarshal(data, &resp) == nil && json.Unmarshal(resp["result"], &result) == nil &&
				result["raw"] != nil && json.Unmarshal(result["tx"], &tx) == nil {
				q, _ := json.Marshal(other)
				tx["from"], result["from"] = q, q
				result["tx"], _ = json.Marshal(tx)
				resp["result"], _ = json.Marshal(result)
				data, _ = json.Marshal(resp)
				mu.Lock()
				rewrote = true
				mu.Unlock()
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(data)
		})
		if code, r := f.sendTx(t, 1, txObject("from", addr, "to", recipient, "value", "0x1")); code != http.StatusOK || r.Error != nil {
			t.Fatalf("%d %+v", code, r.Error)
		}
		mu.Lock()
		defer mu.Unlock()
		if !rewrote {
			t.Fatal("the node's fill answer named no from")
		}
		var fill []map[string]json.RawMessage
		if err := json.Unmarshal(g.callsOf(MethodFillTransaction)[0].Params, &fill); err != nil ||
			!strings.EqualFold(strings.Trim(string(fill[0]["from"]), `"`), addr) {
			t.Fatalf("fill from %s (%v), want %s", fill[0]["from"], err, addr)
		}
		sent := g.sentTxs()
		if len(sent) != 1 {
			t.Fatalf("%d sent", len(sent))
		}
		from, err := types.Sender(types.NewZondSigner(big.NewInt(testChainID)), sent[0])
		if err != nil || !strings.EqualFold(from.Hex(), addr) || sent[0].Nonce() != 0 {
			t.Fatalf("sent from %s nonce %d (%v), want %s nonce 0", from.Hex(), sent[0].Nonce(), err, addr)
		}
	})
	t.Run("not type 0x2", func(t *testing.T) {
		f, g := sendFixture(t, 1)
		_, addr := f.key(0)
		f.node.setHandler(func(w http.ResponseWriter, r *http.Request) {
			var c fakeCall
			_ = json.NewDecoder(r.Body).Decode(&c)
			_, _ = w.Write(encodeResult(c.ID, map[string]string{"raw": "0x01c0"}, nil))
		})
		code, r := f.sendTx(t, 1, txObject("from", addr, "to", recipient))
		if code != http.StatusOK || r.Error == nil || r.Error.Code != ErrTxRejected.Code ||
			!strings.Contains(r.Error.Data.(string), "is not a dynamic-fee (0x2) transaction") {
			t.Fatalf("%d %+v", code, r.Error)
		}
		_ = g
	})
	t.Run("the node's own refusal", func(t *testing.T) {
		f, g := sendFixture(t, 1)
		_, addr := f.key(0)
		g.set(func(g *fakeGQRL) { g.chainID = big.NewInt(5) })
		code, r := f.sendTx(t, 1, txObject("from", addr, "to", recipient, "chainId", "0x539"))
		if code != http.StatusOK || r.Error == nil || r.Error.Code != -32000 ||
			!strings.Contains(r.Error.Message, "chainId does not match node's") {
			t.Fatalf("%d %+v", code, r.Error)
		}
	})
}

// --execution-nonce-crosscheck refuses a filled nonce more than 64 above
// the node's pending nonce; 64 above passes, and without the check any
// nonce passes. A nonce the client chose is never cross-checked.
func TestSendTransactionNonceCrosscheck(t *testing.T) {
	for _, tt := range []struct {
		name       string
		filled     uint64
		crosscheck bool
		userNonce  bool
		ok         bool
	}{
		{"64 above", 64 + 3, true, false, true},
		{"65 above", 65 + 3, true, false, false},
		{"far above, check off", 1 << 40, false, false, true},
		{"client's nonce", 1000, true, true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f, g := sendFixture(t, 1)
			f.txs.crosscheck = tt.crosscheck
			_, addr := f.key(0)
			from := common.Address(f.accounts.List()[0].Address)
			g.set(func(g *fakeGQRL) {
				g.nonces[from] = tt.filled // the pool accepts it
				g.pending = func(common.Address) uint64 { return 3 }
			})
			tx := txObject("from", addr, "to", recipient)
			if tt.userNonce {
				tx["nonce"] = hexutil.EncodeUint64(tt.filled)
			}
			code, r := f.sendTx(t, 1, tx)
			if tt.ok != (r.Error == nil) {
				t.Fatalf("%d %+v", code, r.Error)
			}
			if !tt.ok && (r.Error.Code != ErrTxRejected.Code ||
				r.Error.Data != "the node's qrl_fillTransaction answer has nonce 68, more than 64 above the node's pending nonce 3") {
				t.Fatalf("%+v", r.Error)
			}
			if asked := len(g.callsOf(MethodGetTransactionCount)) > 0; asked != (tt.crosscheck && !tt.userNonce) {
				t.Fatalf("qrl_getTransactionCount asked: %v", asked)
			}
		})
	}
}

// The fee cap applies to the filled transaction.
func TestSendTransactionFeeCapAfterFill(t *testing.T) {
	f, g := sendFixture(t, 1)
	_, addr := f.key(0)
	g.set(func(g *fakeGQRL) {
		g.onFill = func(_ map[string]json.RawMessage, tx *types.DynamicFeeTx) {
			tx.Gas, tx.GasFeeCap = 10_000_000, big.NewInt(1_000_000_000_000) // 10^19 Planck
		}
	})
	code, r := f.sendTx(t, 1, txObject("from", addr, "to", recipient))
	if code != http.StatusOK || r.Error == nil || r.Error.Code != ErrTxRejected.Code ||
		!strings.Contains(r.Error.Data.(string), "fee (gas × maxFeePerGas) of 10000000000000000000 Planck is above the cap") {
		t.Fatalf("%d %+v", code, r.Error)
	}
	if g.callsOf(MethodSendRawTransaction) != nil {
		t.Fatal("sent")
	}
}

// When the client did not choose the nonce, each of gqrl's three messages
// for a taken nonce makes the signer fill, sign and send again; after 10
// retries it gives up with -32603 and HTTP 400. A nonce the client chose,
// and any other error, is relayed at once.
func TestSendTransactionRetry(t *testing.T) {
	for _, msg := range []string{"nonce too low: next nonce 4, tx nonce 3", "already known", "replacement transaction underpriced"} {
		t.Run(msg, func(t *testing.T) {
			f, g := sendFixture(t, 1)
			_, addr := f.key(0)
			refusals := 3
			g.set(func(g *fakeGQRL) {
				g.onSend = func(*types.Transaction) *Error {
					if refusals > 0 {
						refusals--
						return &Error{Code: -32000, Message: msg}
					}
					return nil
				}
			})
			code, r := f.sendTx(t, 1, txObject("from", addr, "to", recipient))
			if code != http.StatusOK || r.Error != nil {
				t.Fatalf("%d %+v", code, r.Error)
			}
			if n := len(g.callsOf(MethodFillTransaction)); n != 4 {
				t.Fatalf("%d fills, want 4", n)
			}
			sends := g.callsOf(MethodSendRawTransaction)
			if len(sends) != 4 || len(g.sentTxs()) != 1 {
				t.Fatalf("%d sends", len(sends))
			}
			if string(sends[0].Params) == string(sends[1].Params) {
				t.Fatal("a retry resent the same bytes")
			}
		})
	}
	t.Run("gives up after 10 retries", func(t *testing.T) {
		f, g := sendFixture(t, 1)
		_, addr := f.key(0)
		g.set(func(g *fakeGQRL) {
			g.onSend = func(*types.Transaction) *Error { return &Error{Code: -32000, Message: "nonce too low"} }
		})
		code, r := f.sendTx(t, 1, txObject("from", addr, "to", recipient))
		if code != http.StatusBadRequest || r.Error == nil || r.Error.Code != ErrInternal.Code {
			t.Fatalf("%d %+v", code, r.Error)
		}
		if n := len(g.callsOf(MethodSendRawTransaction)); n != MaxNonceRetries+1 {
			t.Fatalf("%d sends, want %d", n, MaxNonceRetries+1)
		}
	})
	for _, tt := range []struct {
		name string
		tx   func(addr string) map[string]any
		err  *Error
	}{
		{"the client's nonce", func(addr string) map[string]any { return fullTx(addr) }, &Error{Code: -32000, Message: "nonce too low"}},
		{"another code", func(addr string) map[string]any { return txObject("from", addr, "to", recipient) }, &Error{Code: -32001, Message: "nonce too low"}},
		{"another message", func(addr string) map[string]any { return txObject("from", addr, "to", recipient) }, &Error{Code: -32000, Message: "insufficient funds for gas * price + value"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f, g := sendFixture(t, 1)
			_, addr := f.key(0)
			g.set(func(g *fakeGQRL) { g.onSend = func(*types.Transaction) *Error { return tt.err } })
			code, r := f.sendTx(t, "x", tt.tx(addr))
			if code != http.StatusOK || r.Error == nil || r.Error.Code != tt.err.Code || r.Error.Message != tt.err.Message {
				t.Fatalf("%d %+v", code, r.Error)
			}
			if n := len(g.callsOf(MethodSendRawTransaction)); n != 1 {
				t.Fatalf("%d sends", n)
			}
		})
	}
}

// The sender's lock is held from the fill to the node's answer: calls for
// one account never interleave, so each takes the next nonce; calls for
// two accounts run side by side.
func TestSendTransactionSenderLock(t *testing.T) {
	f, g := sendFixture(t, 2)
	_, a0 := f.key(0)
	_, a1 := f.key(1)
	var mu sync.Mutex
	inFlight := map[string]bool{}
	overlap := false
	both := make(chan struct{})
	var once sync.Once
	var active int
	f.node.setHandler(func(w http.ResponseWriter, r *http.Request) {
		var c fakeCall
		_ = json.NewDecoder(r.Body).Decode(&c)
		var who string
		var params []map[string]json.RawMessage
		if c.Method == MethodFillTransaction && json.Unmarshal(c.Params, &params) == nil {
			who = string(params[0]["from"])
			mu.Lock()
			if inFlight[who] {
				overlap = true
			}
			inFlight[who] = true
			active++
			if active == 2 {
				once.Do(func() { close(both) })
			}
			mu.Unlock()
			select { // give a second call for the same account the chance to overlap
			case <-both:
			case <-time.After(50 * time.Millisecond):
			}
		}
		result, e := g.answer(c)
		if c.Method == MethodSendRawTransaction {
			var raw hexutil.Bytes
			_ = json.Unmarshal(c.Params[1:len(c.Params)-1], &raw)
			tx := new(types.Transaction)
			_ = tx.UnmarshalBinary(raw)
			from, _ := types.Sender(types.NewZondSigner(big.NewInt(testChainID)), tx)
			mu.Lock()
			delete(inFlight, `"`+from.Hex()+`"`)
			active--
			mu.Unlock()
		}
		_, _ = w.Write(encodeResult(c.ID, result, e))
	})
	var wg sync.WaitGroup
	errs := make(chan string, 8)
	for i := range 8 {
		addr := a0
		if i%4 == 3 {
			addr = a1
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, r := f.sendTx(t, i, txObject("from", addr, "to", recipient)); r.Error != nil {
				errs <- r.Error.Message
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if overlap {
		t.Fatal("two calls for one account were between fill and send at once")
	}
	nonces := map[common.Address][]uint64{}
	for _, tx := range g.sentTxs() {
		from, _ := types.Sender(types.NewZondSigner(big.NewInt(testChainID)), tx)
		nonces[from] = append(nonces[from], tx.Nonce())
	}
	for from, n := range nonces {
		slices.Sort(n)
		for i, v := range n {
			if v != uint64(i) {
				t.Fatalf("%s: nonces %v", from.Hex()[:9], n)
			}
		}
	}
	if len(nonces) != 2 {
		t.Fatalf("senders %d", len(nonces))
	}
}

// A wait for the sender's lock ends with the request.
func TestSenderLockWaitEnds(t *testing.T) {
	var s senderLocks
	var a Address
	unlock, err := s.lock(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if _, err := s.lock(ctx, a); err == nil {
		t.Fatal("a second lock was taken")
	}
	unlock()
	unlock2, err := s.lock(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	unlock2()
}

// A node that cannot be reached during the fill gets the proxy's 504.
func TestSendTransactionNodeDown(t *testing.T) {
	f, g := sendFixture(t, 1)
	_, addr := f.key(0)
	f.node.Close()
	code, r := f.sendTx(t, 1, txObject("from", addr, "to", recipient))
	if code != http.StatusGatewayTimeout || r.Error == nil || r.Error.Message != ErrDownstreamConnect.Message {
		t.Fatalf("%d %+v", code, r.Error)
	}
	_ = g
}
