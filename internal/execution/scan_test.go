// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package execution

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

// decodeRequestMap is decodeRequest as it was, decoding every member into
// a map: the oracle that decodeRequest must agree with. null, which
// encoding/json decodes into a nil map, is not an object.
func decodeRequestMap(data []byte) (*Request, *Error) {
	if !json.Valid(data) {
		return nil, ErrParse
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil || members == nil {
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

var scanSeeds = []string{
	`{"jsonrpc":"2.0","id":1,"method":"m","params":[1]}`,
	`{"jsonrpc":"2.0","method":"m","extra":1}`,
	`{"jsonrpc":"2.0","id":1,"METHOD":"x","Method":"y","method":"m"}`,
	`{"jsonrpc":"2.0","id":1,"\u006dethod":"m","p\u0061r\u0061ms":[2]}`,
	`{"jsonrpc":"2.0","id":1,"\u004dethod":"m","\ud83d\ude00":1,"\/":2,"\"":3}`,
	`{"jsonrpc":"2\u002e0","id":-1.5e3,"method":"a","method":"m","params":null}`,
	`{"x":{"a":"}\"],{","b":[{"c":"\\"},[]],"d":"\u005d"},"jsonrpc":"2.0","y":[1,"]",{}],"id":"i","method":"m"}`,
	" \t{ \"jsonrpc\" : \"2.0\" ,\n\"id\" : null , \"method\" : \"m\" , \"params\" : [ 1 , { } ] , \"z\" : true }\r\n",
	`{"jsonrpc":"2.0","id":[1],"method":"m"}`,
	`{"jsonrpc":2.0,"id":false,"method":"m"}`,
	`{}`, `[]`, `null`, `1`, `"x"`, `{`, `{"a"`, `{"a":`, `[1,`, `[}`, `{x`, `"`, `\`, ``,
	`[{"jsonrpc":"2.0","id":1,"method":"m"}, 1, "]", [[]], {"a":[]}, null ,true,false,-0.1e-2]`,
}

// decodeRequest agrees with the map-based decoder on every input, and the
// scanners stay within their input, valid JSON or not.
func FuzzDecodeRequest(f *testing.F) {
	for _, s := range scanSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		got, gotErr := decodeRequest(data)
		want, wantErr := decodeRequestMap(data)
		if !reflect.DeepEqual(gotErr, wantErr) {
			t.Fatalf("%q: error %v, want %v", data, gotErr, wantErr)
		}
		if (got == nil) != (want == nil) {
			t.Fatalf("%q: request %+v, want %+v", data, got, want)
		}
		if got != nil && (!bytes.Equal(got.ID, want.ID) || (got.ID == nil) != (want.ID == nil) ||
			got.Method != want.Method || !bytes.Equal(got.Params, want.Params) || (got.Params == nil) != (want.Params == nil)) {
			t.Fatalf("%q: request %+v, want %+v", data, got, want)
		}

		// Any input, even invalid JSON: no panic, spans within data.
		members(data, func(name, value []byte) {
			var buf [len("jsonrpc")]byte
			memberName(name, &buf)
		})
		for i := range data {
			if end := valueEnd(data, i); end < i || end > len(data) {
				t.Fatalf("%q: value at %d ends at %d", data, i, end)
			}
		}
	})
}
