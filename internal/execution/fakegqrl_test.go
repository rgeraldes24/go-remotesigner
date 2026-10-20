// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package execution

import (
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/theQRL/go-qrl/common"
	"github.com/theQRL/go-qrl/common/hexutil"
	"github.com/theQRL/go-qrl/core/types"
)

// fakeGQRL answers the node methods the signer calls for transactions as
// gqrl does: qrl_chainId, qrl_fillTransaction (gqrl's defaults: the pool
// nonce, 21,000 gas, a tip of 1 and a fee cap of 2 + tip), qrl_getTransactionCount
// and qrl_sendRawTransaction, which takes a transaction whose nonce is the
// account's next and refuses the others with gqrl's messages. Hooks can
// change each answer.
type fakeGQRL struct {
	t       *testing.T
	chainID *big.Int

	mu      sync.Mutex
	nonces  map[common.Address]uint64 // next nonce per account
	sent    []*types.Transaction
	calls   []fakeCall
	onFill  func(args map[string]json.RawMessage, tx *types.DynamicFeeTx) // may edit the filled transaction
	onSend  func(tx *types.Transaction) *Error                            // a non-nil error refuses tx
	pending func(common.Address) uint64                                   // qrl_getTransactionCount override
}

// fakeCall is one call the fake node received.
type fakeCall struct {
	ID     json.RawMessage
	Method string
	Params json.RawMessage
}

func newFakeGQRL(t *testing.T) (*fakeGQRL, *node) {
	t.Helper()
	g := &fakeGQRL{t: t, chainID: big.NewInt(testChainID), nonces: map[common.Address]uint64{}}
	nd := newNode(t)
	nd.setHandler(g.serve)
	return g, nd
}

func (g *fakeGQRL) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var c fakeCall
	if err := json.Unmarshal(body, &c); err != nil {
		http.Error(w, "not one call", http.StatusBadRequest)
		return
	}
	g.mu.Lock()
	g.calls = append(g.calls, c)
	g.mu.Unlock()
	result, e := g.answer(c)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(encodeResult(c.ID, result, e))
}

func (g *fakeGQRL) answer(c fakeCall) (any, *Error) {
	var params []json.RawMessage
	_ = json.Unmarshal(c.Params, &params)
	g.mu.Lock()
	defer g.mu.Unlock()
	switch c.Method {
	case MethodChainID:
		return (*hexutil.Big)(g.chainID), nil
	case MethodGetTransactionCount:
		var addr common.Address
		if err := json.Unmarshal(params[0], &addr); err != nil || string(params[1]) != `"pending"` {
			return nil, &Error{Code: -32602, Message: "bad params"}
		}
		if g.pending != nil {
			return hexutil.Uint64(g.pending(addr)), nil
		}
		return hexutil.Uint64(g.nonces[addr]), nil
	case MethodFillTransaction:
		return g.fill(params[0])
	case MethodSendRawTransaction:
		var raw hexutil.Bytes
		tx := new(types.Transaction)
		if json.Unmarshal(params[0], &raw) != nil || tx.UnmarshalBinary(raw) != nil {
			return nil, &Error{Code: -32000, Message: "rlp: invalid transaction"}
		}
		from, err := types.Sender(types.NewZondSigner(g.chainID), tx)
		if err != nil {
			return nil, &Error{Code: -32000, Message: "invalid sender"}
		}
		if g.onSend != nil {
			if e := g.onSend(tx); e != nil {
				return nil, e
			}
		}
		switch next := g.nonces[from]; {
		case tx.Nonce() < next:
			return nil, &Error{Code: -32000, Message: "nonce too low: next nonce " + itoa(next) + ", tx nonce " + itoa(tx.Nonce())}
		case tx.Nonce() > next:
			return nil, &Error{Code: -32000, Message: "nonce too high"}
		}
		g.nonces[from]++
		g.sent = append(g.sent, tx)
		return tx.Hash(), nil
	}
	return nil, &Error{Code: -32601, Message: "the method " + c.Method + " does not exist/is not available"}
}

func itoa(v uint64) string { return new(big.Int).SetUint64(v).String() }

// fill is gqrl's qrl_fillTransaction over the fake state.
func (g *fakeGQRL) fill(raw json.RawMessage) (any, *Error) {
	var args map[string]json.RawMessage
	var a txArgs
	if json.Unmarshal(raw, &args) != nil || json.Unmarshal(raw, &a) != nil || a.From == nil {
		return nil, &Error{Code: -32602, Message: "bad transaction args"}
	}
	if a.ChainID != nil && a.ChainID.ToInt().Cmp(g.chainID) != 0 {
		return nil, &Error{Code: -32000, Message: "chainId does not match node's (have=" + a.ChainID.ToInt().String() +
			", want=" + g.chainID.String() + ")"}
	}
	tx := &types.DynamicFeeTx{ChainID: new(big.Int).Set(g.chainID), To: a.To, Value: a.value(), Data: a.data(),
		AccessList: a.accessList(), Nonce: g.nonces[*a.From], Gas: 21_000, GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(3)}
	if a.Nonce != nil {
		tx.Nonce = uint64(*a.Nonce)
	}
	if a.Gas != nil {
		tx.Gas = uint64(*a.Gas)
	}
	if a.MaxPriorityFeePerGas != nil {
		tx.GasTipCap = a.MaxPriorityFeePerGas.ToInt()
	}
	if a.MaxFeePerGas != nil {
		tx.GasFeeCap = a.MaxFeePerGas.ToInt()
	}
	if g.onFill != nil {
		g.onFill(args, tx)
	}
	signed := types.NewTx(tx)
	data, err := signed.MarshalBinary()
	if err != nil {
		return nil, &Error{Code: -32000, Message: err.Error()}
	}
	return signTransactionResult{Raw: data, Tx: signed}, nil
}

// callsOf returns the calls of a method the fake node received.
func (g *fakeGQRL) callsOf(method string) []fakeCall {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []fakeCall
	for _, c := range g.calls {
		if c.Method == method {
			out = append(out, c)
		}
	}
	return out
}

// methods returns the methods the fake node received, in order, without
// the chain-ID checks.
func (g *fakeGQRL) methods() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []string
	for _, c := range g.calls {
		if c.Method != MethodChainID {
			out = append(out, c.Method)
		}
	}
	return out
}

func (g *fakeGQRL) sentTxs() []*types.Transaction {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]*types.Transaction(nil), g.sent...)
}

func (g *fakeGQRL) set(fn func(g *fakeGQRL)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	fn(g)
}

// txObject renders a transaction object with the given members.
func txObject(members ...string) map[string]any {
	m := map[string]any{}
	for i := 0; i+1 < len(members); i += 2 {
		m[members[i]] = members[i+1]
	}
	return m
}

// recipient is a recipient address for the tests.
var recipient = "Q" + strings.Repeat("11", 64)
