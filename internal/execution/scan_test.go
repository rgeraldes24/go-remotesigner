// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package execution

import (
	"bytes"
	"encoding/json"
	"reflect"
	"slices"
	"strconv"
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

// splitBatchDecoder is splitBatch as it was, reading the elements with a
// json.Decoder: the oracle that splitBatch must agree with on a body that
// isBatch accepts.
func splitBatchDecoder(body []byte) ([]json.RawMessage, *Error) {
	if !json.Valid(body) {
		return nil, ErrParse
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if _, err := dec.Token(); err != nil {
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

// equalRaw reports whether two lists of raw values hold the same bytes.
func equalRaw(a, b []json.RawMessage) bool {
	return slices.EqualFunc(a, b, func(x, y json.RawMessage) bool { return bytes.Equal(x, y) })
}

// elements finds an array's elements as encoding/json does, stops past its
// limit, and finds none in anything else.
func TestElements(t *testing.T) {
	for _, tt := range []struct {
		data  string
		limit int
		want  []string // nil: refused
	}{
		{`[]`, 0, []string{}},
		{" [ ] ", 0, []string{}},
		{`[1]`, 0, nil},
		{`[1]`, 1, []string{`1`}},
		{" [ 1 , \"]\" ,\n[2,[3]] , {\"a\":\"}\\\"\"} , null ] ", 5,
			[]string{`1`, `"]"`, `[2,[3]]`, `{"a":"}\""}`, `null`}},
		{" [ 1 , \"]\" ,\n[2,[3]] , {\"a\":\"}\\\"\"} , null ] ", 4, nil},
		{`[1,2,3]`, 2, nil},
		{`{}`, 1, nil},
		{`{"a":[1]}`, 1, nil},
		{`null`, 1, nil},
		{`"[]"`, 1, nil},
		{`1`, 1, nil},
	} {
		got, ok := elements([]byte(tt.data), tt.limit)
		if ok != (tt.want != nil) || len(got) != len(tt.want) {
			t.Errorf("%q, limit %d: %q, %v; want %q", tt.data, tt.limit, got, ok, tt.want)
			continue
		}
		for i := range got {
			if string(got[i]) != tt.want[i] {
				t.Errorf("%q, limit %d: element %d is %q, want %q", tt.data, tt.limit, i, got[i], tt.want[i])
			}
		}
	}
	if _, e := splitBatch([]byte(`{"jsonrpc":"2.0","id":1,"method":"m"}`)); e == nil || e.Code != ErrInvalidRequest.Code {
		t.Errorf("an object as a batch: %v, want -32600", e)
	}
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

// decodeRequest agrees with the map-based decoder, splitBatch with the
// json.Decoder one, and elements with encoding/json, on every input, and
// the scanners stay within their input, valid JSON or not.
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

		if isBatch(data) {
			got, gotErr := splitBatch(data)
			want, wantErr := splitBatchDecoder(data)
			if !reflect.DeepEqual(gotErr, wantErr) || !equalRaw(got, want) {
				t.Fatalf("%q: batch %q, %v; want %q, %v", data, got, gotErr, want, wantErr)
			}
		}
		if json.Valid(data) {
			var all []json.RawMessage
			isArray := json.Unmarshal(data, &all) == nil && all != nil // null is not an array
			for _, limit := range []int{0, 1, 2, max(len(all)-1, 0), len(all)} {
				got, ok := elements(data, limit)
				if ok != (isArray && len(all) <= limit) || ok && !equalRaw(got, all) {
					t.Fatalf("%q, limit %d: %q, %v; want %q (an array: %v)", data, limit, got, ok, all, isArray)
				}
			}
		}

		// Any input, even invalid JSON: no panic, spans within data.
		members(data, func(name, value []byte) {
			var buf [len("jsonrpc")]byte
			memberName(name, &buf)
		})
		if got, _ := elements(data, len(data)); len(got) > len(data) {
			t.Fatalf("%q: %d elements", data, len(got))
		}
		for i := range data {
			if end := valueEnd(data, i); end < i || end > len(data) {
				t.Fatalf("%q: value at %d ends at %d", data, i, end)
			}
		}
	})
}
