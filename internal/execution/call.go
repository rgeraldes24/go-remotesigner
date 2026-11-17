// Copyright 2020 ConsenSys AG.
// Copyright 2026 The go-remotesigner Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//
// Modified by The go-remotesigner Authors, 2026: translated from Java to Go and adapted for QRL.
// Derived from Web3Signer
// core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/sendtransaction/transaction/VertxNonceRequestTransmitter.java
// and core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/sendtransaction/transaction/EthNonceProvider.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

//go:build !noexecution

package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/theQRL/go-qrl/common"
	"github.com/theQRL/go-qrl/common/hexutil"
)

// The node methods the signer calls itself.
const (
	MethodChainID             = "qrl_chainId"
	MethodFillTransaction     = "qrl_fillTransaction"
	MethodGetTransactionCount = "qrl_getTransactionCount"
	MethodSendRawTransaction  = "qrl_sendRawTransaction"
)

// callIDs numbers the signer's own calls to the node.
var callIDs atomic.Uint64

// nextCallID returns a fresh id for one of the signer's own calls.
func nextCallID() json.RawMessage {
	data, _ := json.Marshal(callIDs.Add(1))
	return data
}

// nodeAnswer is the node's answer to one call: its result, or the JSON-RPC
// error it returned.
type nodeAnswer struct {
	result json.RawMessage
	err    *Error // the node's own error object, relayed with HTTP 200
}

// call makes one JSON-RPC call to the node and returns its answer. The
// request carries none of the client's headers, only the signer's own
// downstream credential; id is the request's id. A node that cannot be
// reached, that does not answer in time or that answers with anything but
// a JSON-RPC response to this id is an error of the call, with the HTTP
// status a single response would have.
func (p *proxy) call(ctx context.Context, id json.RawMessage, method string, params ...any) (nodeAnswer, *Error) {
	if params == nil {
		params = []any{}
	}
	rawParams, err := json.Marshal(params)
	if err != nil {
		return nodeAnswer{}, ErrInternal
	}
	body, err := json.Marshal(wireRequest{JSONRPC: Version, ID: id, Method: method, Params: rawParams})
	if err != nil {
		return nodeAnswer{}, ErrInternal
	}
	data, e := p.exchange(ctx, nil, body)
	if e != nil {
		return nodeAnswer{}, e
	}
	var resp struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   *struct {
			Code    int             `json:"code"`
			Message string          `json:"message"`
			Data    json.RawMessage `json:"data"`
		} `json:"error"`
	}
	bad := ErrDownstreamResponse.withStatus(http.StatusBadGateway)
	if err := json.Unmarshal(data, &resp); err != nil {
		return nodeAnswer{}, bad.with("not a JSON-RPC response to " + method)
	}
	switch {
	case resp.JSONRPC != Version || !sameID(resp.ID, id):
		return nodeAnswer{}, bad.with("not the answer to the signer's " + method)
	case resp.Error != nil:
		ne := &Error{Code: resp.Error.Code, Message: resp.Error.Message, status: http.StatusOK}
		if len(resp.Error.Data) > 0 && !bytes.Equal(resp.Error.Data, nullID) {
			ne.Data = resp.Error.Data
		}
		return nodeAnswer{err: ne}, nil
	case resp.Result == nil:
		return nodeAnswer{}, bad.with("no result from " + method)
	}
	return nodeAnswer{result: resp.Result}, nil
}

// sameID reports whether two JSON-RPC ids are the same id: two strings
// that decode to the same text, two numbers written alike, or two nulls.
// The bytes may differ: encoding/json, the signer's and gqrl's, writes <, >,
// &, U+2028 and U+2029 in a string as \u escapes, so a client id "a&b"
// comes back as "a\u0026b".
func sameID(a, b json.RawMessage) bool {
	x, okA := decodeID(a)
	y, okB := decodeID(b)
	return okA && okB && x == y
}

// decodeID decodes an id: a string, a json.Number or nil for null. Any
// other JSON is no id.
func decodeID(raw json.RawMessage) (any, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil || dec.More() {
		return nil, false
	}
	switch v.(type) {
	case string, json.Number, nil:
		return v, true
	}
	return nil, false
}

// quantity decodes a result that is a 0x hex quantity.
func quantity(result json.RawMessage, method string) (*hexutil.Big, *Error) {
	var q hexutil.Big
	if err := json.Unmarshal(result, &q); err != nil {
		return nil, ErrDownstreamResponse.with(method + " did not return a quantity").withStatus(http.StatusBadGateway)
	}
	return &q, nil
}

// pendingNonce asks the node for the next nonce of from, counting its pool:
// qrl_getTransactionCount(from, "pending").
func (p *proxy) pendingNonce(ctx context.Context, from common.Address) (uint64, *Error) {
	a, e := p.call(ctx, nextCallID(), MethodGetTransactionCount, from, "pending")
	if e != nil {
		return 0, e
	}
	if a.err != nil {
		return 0, ErrDownstreamResponse.with(MethodGetTransactionCount + " failed: " + cut(a.err.Message)).
			withStatus(http.StatusBadGateway)
	}
	var n hexutil.Uint64
	if err := json.Unmarshal(a.result, &n); err != nil {
		return 0, ErrDownstreamResponse.with(MethodGetTransactionCount + " did not return a quantity").
			withStatus(http.StatusBadGateway)
	}
	return uint64(n), nil
}

// cut shortens a message from the node for an error's data and the logs.
func cut(s string) string {
	const limit = 200
	if len(s) <= limit {
		return s
	}
	return strings.ToValidUTF8(s[:limit], "") + "…"
}
