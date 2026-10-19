// Copyright 2018 ConsenSys AG.
// Copyright 2019 ConsenSys AG.
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
// core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/JsonRpcRequest.java,
// core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/JsonRpcRequestId.java,
// core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/response/JsonRpcError.java,
// core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/response/JsonRpcErrorResponse.java and
// core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/response/JsonRpcSuccessResponse.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

//go:build !noexecution

package execution

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Version is the only JSON-RPC version served.
const Version = "2.0"

// MaxBatch is the largest batch served, gqrl's own batch limit.
const MaxBatch = 1000

// Error is a JSON-RPC error object.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *Error) Error() string { return fmt.Sprintf("JSON-RPC error %d: %s", e.Code, e.Message) }

// with returns a copy of e that carries data.
func (e *Error) with(data any) *Error {
	c := *e
	c.Data = data
	return &c
}

// The errors this signer answers with: the JSON-RPC 2.0 codes, Web3Signer's
// method-not-enabled and downstream codes, and the unknown-account refusal.
// The messages are fixed; the optional data says more.
var (
	ErrParse              = &Error{Code: -32700, Message: "Parse error"}
	ErrInvalidRequest     = &Error{Code: -32600, Message: "Invalid Request"}
	ErrMethodNotFound     = &Error{Code: -32601, Message: "Method not found"}
	ErrInvalidParams      = &Error{Code: -32602, Message: "Invalid params"}
	ErrInternal           = &Error{Code: -32603, Message: "Internal error"}
	ErrMethodNotEnabled   = &Error{Code: -32604, Message: "Method not enabled"}
	ErrUnknownAccount     = &Error{Code: -32000, Message: "No unlocked account matches the Sender"}
	ErrDownstreamTimeout  = &Error{Code: -32000, Message: "Connection to downstream node timed out"}
	ErrDownstreamConnect  = &Error{Code: -32000, Message: "Failed to connect to downstream node"}
	ErrDownstreamResponse = &Error{Code: -32000, Message: "Invalid response from downstream node"}
)

// Request is one decoded JSON-RPC request. ID is the raw id: a string, a
// number or null; it is nil for a notification, which has no id member and
// gets no response. Params is the raw params member, nil when absent.
type Request struct {
	ID     json.RawMessage
	Method string
	Params json.RawMessage
}

// Notification reports whether the request has no id.
func (r *Request) Notification() bool { return r.ID == nil }

// nullID is the id of a response to a request whose id is unknown.
var nullID = json.RawMessage("null")

// responseID returns the id a response to r carries.
func (r *Request) responseID() json.RawMessage {
	if r == nil || r.ID == nil {
		return nullID
	}
	return r.ID
}

// decodeRequest reads one request object. A body that is not JSON is a
// parse error; JSON that is not a valid request is an invalid request, with
// the request's id when it has a valid one, so that the error response can
// carry it.
func decodeRequest(data []byte) (*Request, *Error) {
	if !json.Valid(data) {
		return nil, ErrParse
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		return nil, ErrInvalidRequest.with("a request must be a JSON object")
	}
	req := &Request{}
	if id, ok := members["id"]; ok {
		if !validID(id) {
			return nil, ErrInvalidRequest.with("id must be a string, a number or null")
		}
		req.ID = id
	}
	var version string
	if v, ok := members["jsonrpc"]; !ok || json.Unmarshal(v, &version) != nil || version != Version {
		return req, ErrInvalidRequest.with(`jsonrpc must be "2.0"`)
	}
	if m, ok := members["method"]; !ok || json.Unmarshal(m, &req.Method) != nil || req.Method == "" {
		return req, ErrInvalidRequest.with("method must be a non-empty string")
	}
	if p, ok := members["params"]; ok && !bytes.Equal(p, nullID) {
		req.Params = p
	}
	return req, nil
}

// wireRequest is a request as the signer forwards it to the node: the
// members the signer decoded, under their exact names, and nothing else.
// The node never sees the client's bytes. gqrl decodes a request into a
// struct with encoding/json, which also matches member names in another
// case ("METHOD"), the last one winning, while the allowlist checks the
// "method" member alone: a forwarded copy of the client's bytes could run a
// method the allowlist never saw.
type wireRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"` // absent for a notification
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// wire returns the request as it is forwarded, with id in place of the
// client's id; a notification stays one whatever id is.
func (r *Request) wire(id json.RawMessage) wireRequest {
	w := wireRequest{JSONRPC: Version, Method: r.Method, Params: r.Params}
	if !r.Notification() {
		w.ID = id
	}
	return w
}

// validID reports whether a raw id is a string, a number or null.
func validID(id json.RawMessage) bool {
	if len(id) == 0 {
		return false
	}
	switch c := id[0]; {
	case c == '"', c == '-', '0' <= c && c <= '9':
		return true
	default:
		return bytes.Equal(id, nullID)
	}
}

// successResponse is a JSON-RPC result.
type successResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result"`
}

// errorResponse is a JSON-RPC error response.
type errorResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   *Error          `json:"error"`
}

// encodeResult renders the response to a request: its result, or e.
func encodeResult(id json.RawMessage, result any, e *Error) json.RawMessage {
	var v any = successResponse{JSONRPC: Version, ID: id, Result: result}
	if e != nil {
		v = errorResponse{JSONRPC: Version, ID: id, Error: e}
	}
	data, err := json.Marshal(v)
	if err != nil {
		// A result that cannot be encoded is a fault of this signer.
		data, _ = json.Marshal(errorResponse{JSONRPC: Version, ID: id, Error: ErrInternal})
	}
	return data
}
