// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package execution

import (
	"encoding/json"
	"testing"
)

func TestDecodeRequest(t *testing.T) {
	tests := []struct {
		body     string
		err      *Error
		id       string // "" for none
		method   string
		params   string
		notified bool
	}{
		{`{"jsonrpc":"2.0","id":1,"method":"m","params":[1]}`, nil, "1", "m", "[1]", false},
		{`{"jsonrpc":"2.0","id":"x","method":"m"}`, nil, `"x"`, "m", "", false},
		{`{"jsonrpc":"2.0","id":null,"method":"m","params":null}`, nil, "null", "m", "", false},
		{`{"jsonrpc":"2.0","id":-1.5e3,"method":"m","params":{"a":1}}`, nil, "-1.5e3", "m", `{"a":1}`, false},
		{`{"jsonrpc":"2.0","method":"m","extra":1}`, nil, "", "m", "", true},
		{`{`, ErrParse, "", "", "", false},
		{`[]`, ErrInvalidRequest, "", "", "", false},
		{`{"jsonrpc":"2.0","id":[1],"method":"m"}`, ErrInvalidRequest, "", "", "", false},
		{`{"jsonrpc":"2.0","id":false,"method":"m"}`, ErrInvalidRequest, "", "", "", false},
		{`{"jsonrpc":2.0,"id":1,"method":"m"}`, ErrInvalidRequest, "1", "", "", false},
		{`{"jsonrpc":"2.0","id":1,"method":null}`, ErrInvalidRequest, "1", "", "", false},
	}
	for _, tt := range tests {
		req, err := decodeRequest([]byte(tt.body))
		if (err == nil) != (tt.err == nil) || err != nil && err.Code != tt.err.Code {
			t.Errorf("%s: error %v, want %v", tt.body, err, tt.err)
			continue
		}
		if string(req.responseID()) != map[bool]string{true: "null", false: tt.id}[tt.id == ""] {
			t.Errorf("%s: response id %s, want %s", tt.body, req.responseID(), tt.id)
		}
		if err != nil {
			continue
		}
		if req.Method != tt.method || string(req.Params) != tt.params || req.Notification() != tt.notified {
			t.Errorf("%s: %+v", tt.body, req)
		}
	}
}

func TestEncodeResult(t *testing.T) {
	if got := string(encodeResult(json.RawMessage(`"a"`), []string{"x"}, nil)); got != `{"jsonrpc":"2.0","id":"a","result":["x"]}` {
		t.Errorf("success: %s", got)
	}
	if got := string(encodeResult(nullID, nil, ErrParse)); got != `{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}` {
		t.Errorf("error: %s", got)
	}
	if got := string(encodeResult(json.RawMessage(`1`), nil, ErrMethodNotEnabled.with("why"))); got != `{"jsonrpc":"2.0","id":1,"error":{"code":-32604,"message":"Method not enabled","data":"why"}}` {
		t.Errorf("error with data: %s", got)
	}
	if got := string(encodeResult(json.RawMessage(`1`), func() {}, nil)); got != `{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"Internal error"}}` {
		t.Errorf("unencodable result: %s", got)
	}
	if ErrMethodNotEnabled.with("x") == ErrMethodNotEnabled || ErrMethodNotEnabled.Data != nil {
		t.Error("with changed the shared error")
	}
}
