// Copyright 2019 ConsenSys AG.
// Copyright 2023 ConsenSys AG.
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
// core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/JsonRpcHandler.java,
// core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/RequestMapper.java,
// core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/internalresponse/InternalResponseHandler.java,
// core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/JsonRpcErrorHandler.java,
// core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/HttpResponseFactory.java and
// core/src/main/java/tech/pegasys/web3signer/core/util/ResponseCodeSelector.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

//go:build !noexecution

package execution

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/server"
)

// Handler serves the JSON-RPC 2.0 endpoint, POST /. It answers the methods
// of its table itself, forwards the methods the allowlist allows to the
// downstream node, and refuses the rest with -32601. A batch of up to
// MaxBatch requests is split: its local requests are answered here, its
// forwarded requests go to the node as one batch, and the responses come
// back in the order of the requests.
type Handler struct {
	accounts *Accounts
	allow    *Allowlist
	proxy    *proxy
	table    map[string]method
	log      logrus.FieldLogger
}

// newHandler builds the endpoint's handler.
func newHandler(accounts *Accounts, allow *Allowlist, p *proxy, log logrus.FieldLogger) *Handler {
	h := &Handler{accounts: accounts, allow: allow, proxy: p, log: log}
	h.table = h.methods()
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, e := server.ReadBody(r)
	if e != nil {
		server.WriteError(w, h.log, r, e)
		return
	}
	if isBatch(body) {
		h.serveBatch(w, r, body)
		return
	}
	h.serveSingle(w, r, body)
}

// isBatch reports whether a body is a JSON array.
func isBatch(body []byte) bool {
	b := bytes.TrimLeft(body, " \t\r\n")
	return len(b) > 0 && b[0] == '['
}

// statusOf is the HTTP status of a single response, as Web3Signer chooses
// it: 400 for a parse error, an invalid request and invalid params, 500
// for an internal error, 200 otherwise.
func statusOf(e *Error) int {
	if e == nil {
		return http.StatusOK
	}
	switch e.Code {
	case ErrParse.Code, ErrInvalidRequest.Code, ErrInvalidParams.Code:
		return http.StatusBadRequest
	case ErrInternal.Code:
		return http.StatusInternalServerError
	default:
		return http.StatusOK
	}
}

// serveSingle answers one request. A notification of a local or refused
// method gets an empty response, as JSON-RPC requires, and runs nothing.
func (h *Handler) serveSingle(w http.ResponseWriter, r *http.Request, body []byte) {
	req, e := decodeRequest(body)
	if e != nil {
		writeResponse(w, statusOf(e), encodeResult(req.responseID(), nil, e))
		return
	}
	m, local := h.table[req.Method]
	switch {
	case local && req.Notification(), !local && !h.allow.Allows(req.Method) && req.Notification():
		w.WriteHeader(http.StatusOK)
	case local:
		result, e := m(r.Context(), req)
		writeResponse(w, statusOf(e), encodeResult(req.ID, result, e))
	case !h.allow.Allows(req.Method):
		writeResponse(w, http.StatusOK, encodeResult(req.ID, nil, ErrMethodNotFound))
	default:
		h.proxy.forward(w, r, req)
	}
}

// slot is one request of a batch and its response; a nil response is
// none (a notification).
type slot struct {
	req      *Request
	response json.RawMessage
}

// serveBatch answers a batch. The batch itself must be a JSON array of 1 to
// MaxBatch elements; each element is then answered on its own, and an
// element the allowlist refuses never reaches the node.
func (h *Handler) serveBatch(w http.ResponseWriter, r *http.Request, body []byte) {
	elems, e := splitBatch(body)
	if e != nil {
		writeResponse(w, statusOf(e), encodeResult(nullID, nil, e))
		return
	}

	slots := make([]slot, len(elems))
	var forwarded []int // indexes of the requests to forward
	for i, raw := range elems {
		req, e := decodeRequest(raw)
		slots[i].req = req
		switch {
		case e != nil:
			slots[i].response = encodeResult(req.responseID(), nil, e)
		case h.table[req.Method] != nil:
		case h.allow.Allows(req.Method):
			forwarded = append(forwarded, i)
		case !req.Notification():
			slots[i].response = encodeResult(req.ID, nil, ErrMethodNotFound)
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if len(forwarded) > 0 {
			h.forwardBatch(r, slots, forwarded)
		}
	}()
	for i := range slots {
		s := &slots[i]
		if m := h.methodOf(s.req); m != nil && !s.req.Notification() && s.response == nil {
			result, e := m(r.Context(), s.req)
			s.response = encodeResult(s.req.ID, result, e)
		}
	}
	<-done

	var out bytes.Buffer
	for _, s := range slots {
		if s.response == nil {
			continue
		}
		if out.Len() == 0 {
			out.WriteByte('[')
		} else {
			out.WriteByte(',')
		}
		out.Write(s.response)
	}
	if out.Len() == 0 {
		w.WriteHeader(http.StatusOK) // only notifications
		return
	}
	out.WriteByte(']')
	writeResponse(w, http.StatusOK, out.Bytes())
}

// splitBatch returns the elements of a batch: a JSON array of 1 to MaxBatch
// elements. A body that is not JSON is a parse error. The elements are
// counted as they are read, so that an oversized batch is refused before
// it is materialised: a 5 MiB array of tiny elements, decoded whole, would
// take some 60 times its size.
func splitBatch(body []byte) ([]json.RawMessage, *Error) {
	if !json.Valid(body) {
		return nil, ErrParse
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if _, err := dec.Token(); err != nil { // the '['
		return nil, ErrInvalidRequest
	}
	var elems []json.RawMessage
	for dec.More() {
		if len(elems) == MaxBatch {
			return nil, ErrInvalidRequest.with("batch of more than " + strconv.Itoa(MaxBatch) + " requests")
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, ErrInvalidRequest
		}
		elems = append(elems, raw)
	}
	if len(elems) == 0 {
		return nil, ErrInvalidRequest.with("empty batch")
	}
	return elems, nil
}

// methodOf returns the local method of a decoded request, or nil.
func (h *Handler) methodOf(req *Request) method {
	if req == nil || req.Method == "" {
		return nil
	}
	return h.table[req.Method]
}

// forwardBatch sends the forwarded requests to the node as one batch and
// puts each response in its request's slot. Each forwarded request is the
// signer's own encoding (wireRequest) and carries its position in the
// client's batch as its id, so that the responses are matched whatever ids
// the client chose (they may repeat, or be null); the client's id is put
// back into each response. Notifications stay notifications. A request the
// node does not answer gets an error.
func (h *Handler) forwardBatch(r *http.Request, slots []slot, forwarded []int) {
	out := make([]wireRequest, len(forwarded))
	for k, i := range forwarded {
		out[k] = slots[i].req.wire(json.RawMessage(strconv.Itoa(i)))
	}
	fail := func(e *Error) {
		for _, i := range forwarded {
			if s := &slots[i]; !s.req.Notification() && s.response == nil {
				s.response = encodeResult(s.req.ID, nil, e)
			}
		}
	}
	body, err := json.Marshal(out)
	if err != nil {
		fail(ErrInternal)
		return
	}
	data, e := h.proxy.exchange(r.Context(), r, body)
	if e != nil {
		fail(e)
		return
	}
	var responses []map[string]json.RawMessage
	if err := json.Unmarshal(data, &responses); err != nil {
		fail(ErrDownstreamResponse.with("not a JSON-RPC batch response"))
		return
	}
	want := make(map[int]bool, len(forwarded))
	for _, i := range forwarded {
		want[i] = !slots[i].req.Notification()
	}
	for _, resp := range responses {
		var i int
		if json.Unmarshal(resp["id"], &i) != nil || !want[i] {
			continue // not an answer to a forwarded call, or a second one
		}
		want[i] = false
		resp["id"] = slots[i].req.ID
		if data, err := json.Marshal(resp); err == nil {
			slots[i].response = data
		}
	}
	fail(ErrDownstreamResponse.with("no response to the request"))
}
