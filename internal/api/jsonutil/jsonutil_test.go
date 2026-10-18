// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package jsonutil

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
)

// reasonOf returns the reason of err, or "" for nil.
func reasonOf(t *testing.T, err error) apierr.Reason {
	t.Helper()
	if err == nil {
		return ""
	}
	r, ok := apierr.ReasonOf(err)
	if !ok {
		t.Fatalf("error without a reason: %v", err)
	}
	return r
}

const (
	pass       = apierr.Reason("")
	bad        = apierr.BadField
	mal        = apierr.MalformedJSON
	unknownFld = apierr.UnknownField
)

func TestUint64String(t *testing.T) {
	tests := []struct {
		in   string
		want uint64
		r    apierr.Reason
	}{
		{`"0"`, 0, pass},
		{`"1234"`, 1234, pass},
		{`"18446744073709551615"`, 1<<64 - 1, pass},
		{`"12"`, 12, pass}, // escapes are decoded before the check
		{`"18446744073709551616"`, 0, bad},
		{`"99999999999999999999"`, 0, bad},
		{`"100000000000000000000"`, 0, bad},
		{`""`, 0, bad},
		{`"01"`, 0, bad},
		{`"00"`, 0, bad},
		{`"+1"`, 0, bad},
		{`"-1"`, 0, bad},
		{`" 1"`, 0, bad},
		{`"1.0"`, 0, bad},
		{`"1e3"`, 0, bad},
		{`"0x10"`, 0, bad},
		{`1234`, 0, bad}, // a JSON number
		{`null`, 0, bad},
		{`true`, 0, bad},
		{`["1"]`, 0, bad},
		{`{"v":"1"}`, 0, bad},
	}
	for _, tt := range tests {
		var u Uint64String
		err := u.UnmarshalJSON([]byte(tt.in))
		if got := reasonOf(t, err); got != tt.r {
			t.Errorf("%s: reason %q, want %q (%v)", tt.in, got, tt.r, err)
			continue
		}
		if err == nil && uint64(u) != tt.want {
			t.Errorf("%s: got %d", tt.in, uint64(u))
		}
	}
	out, _ := Uint64String(1<<64 - 1).MarshalJSON()
	if string(out) != `"18446744073709551615"` {
		t.Errorf("marshal: %s", out)
	}
}

func TestHexBytesN(t *testing.T) {
	tests := []struct {
		in  string
		n   int
		r   apierr.Reason
		out string
	}{
		{`"0x000000fd"`, 4, pass, "000000fd"},
		{`"0xAbCdEf01"`, 4, pass, "abcdef01"},
		{`"0x000000"`, 4, bad, ""},     // short
		{`"0x0000000000"`, 4, bad, ""}, // long
		{`"0x000000f"`, 4, bad, ""},    // odd
		{`"000000fd"`, 4, bad, ""},     // no prefix
		{`"0X000000fd"`, 4, bad, ""},   // upper-case prefix
		{`"0x000000fg"`, 4, bad, ""},   // not hex
		{`"0x"`, 4, bad, ""},
		{`253`, 4, bad, ""},
		{`null`, 4, bad, ""},
		{`"` + "0x" + strings.Repeat("ab", 4627) + `"`, 4627, pass, strings.Repeat("ab", 4627)},
		{`"` + "0x" + strings.Repeat("ab", 4626) + `"`, 4627, bad, ""},
	}
	for _, tt := range tests {
		dst := make([]byte, tt.n)
		err := HexBytesN(dst).UnmarshalJSON([]byte(tt.in))
		if got := reasonOf(t, err); got != tt.r {
			t.Errorf("%.40s: reason %q, want %q (%v)", tt.in, got, tt.r, err)
			continue
		}
		if err != nil {
			continue
		}
		out, _ := HexBytesN(dst).MarshalJSON()
		if want := `"0x` + tt.out + `"`; string(out) != want {
			t.Errorf("%.40s: round trip %.40s", tt.in, out)
		}
	}
}

func TestBitlist32(t *testing.T) {
	tests := []struct {
		in string
		r  apierr.Reason
	}{
		{`"0x01"`, pass},         // empty bitlist
		{`"0x1f"`, pass},         // 4 bits, all set
		{`"0x14"`, pass},         // 4 bits, one set
		{`"0xffffffff"`, pass},   // 31 bits
		{`"0xffffffff01"`, pass}, // 32 bits: the 5-byte edge
		{`"0x0000000001"`, pass}, // 32 bits, none set
		{`"0xffffffff02"`, bad},
		{`"0xffffffff80"`, bad},
		{`"0x00"`, bad}, // no delimiter
		{`"0x1f00"`, bad},
		{`"0x"`, bad},
		{`"0x0101010101 "`, bad},
		{`"0x010101010101"`, bad}, // 6 bytes
		{`"0x1"`, bad},
		{`"1f"`, bad},
		{`31`, bad},
	}
	for _, tt := range tests {
		var l Bitlist32
		err := l.UnmarshalJSON([]byte(tt.in))
		if got := reasonOf(t, err); got != tt.r {
			t.Errorf("%s: reason %q, want %q (%v)", tt.in, got, tt.r, err)
			continue
		}
		if err == nil {
			out, _ := l.MarshalJSON()
			if string(out) != tt.in {
				t.Errorf("%s: round trip %s", tt.in, out)
			}
		}
	}
}

func TestBitvectorN(t *testing.T) {
	tests := []struct {
		in string
		n  uint64
		r  apierr.Reason
	}{
		{`"0x0500"`, 16, pass},
		{`"0xffff"`, 16, pass},
		{`"0x0000"`, 16, pass},
		{`"0x` + strings.Repeat("ff", 16) + `"`, 128, pass},
		{`"0x05"`, 16, bad},
		{`"0x050000"`, 16, bad},
		{`"0x0500"`, 128, bad}, // a minimal-preset value on mainnet
		{`"0x` + strings.Repeat("00", 16) + `"`, 16, bad},
		{`"0x07"`, 3, pass},
		{`"0x0f"`, 3, bad}, // a bit past N
		{`"0500"`, 16, bad},
		{`5`, 16, bad},
	}
	for _, tt := range tests {
		var bits []byte
		err := BitvectorN{Bits: &bits, N: tt.n}.UnmarshalJSON([]byte(tt.in))
		if got := reasonOf(t, err); got != tt.r {
			t.Errorf("%s/%d: reason %q, want %q (%v)", tt.in, tt.n, got, tt.r, err)
			continue
		}
		if err == nil {
			out, _ := BitvectorN{Bits: &bits}.MarshalJSON()
			if string(out) != tt.in {
				t.Errorf("%s: round trip %s", tt.in, out)
			}
		}
	}
	var bits []byte
	if r := reasonOf(t, BitvectorN{Bits: &bits}.UnmarshalJSON([]byte(`"0x00"`))); r != apierr.Internal {
		t.Errorf("unconfigured bitvector: reason %q", r)
	}
}

func TestQAddress(t *testing.T) {
	hex128 := strings.Repeat("aB", 64)
	tests := []struct {
		in string
		r  apierr.Reason
	}{
		{`"Q` + hex128 + `"`, pass},
		{`"Q` + strings.ToLower(hex128) + `"`, pass},
		{`"0x` + hex128 + `"`, bad},
		{`"q` + hex128 + `"`, bad},
		{`"Z` + hex128 + `"`, bad},
		{`"` + hex128 + `"`, bad},
		{`"Q` + hex128[:126] + `"`, bad},
		{`"Q` + hex128 + `00"`, bad},
		{`"Q` + hex128[:127] + `g"`, bad},
		{`"0x` + strings.Repeat("ab", 20) + `"`, bad}, // an Ethereum address
		{`""`, bad},
		{`null`, bad},
	}
	for _, tt := range tests {
		var a QAddress
		err := a.UnmarshalJSON([]byte(tt.in))
		if got := reasonOf(t, err); got != tt.r {
			t.Errorf("%.20s: reason %q, want %q (%v)", tt.in, got, tt.r, err)
			continue
		}
		if err == nil {
			out, _ := a.MarshalJSON()
			if want := `"Q` + strings.ToLower(hex128) + `"`; string(out) != want {
				t.Errorf("round trip %s", out)
			}
			if a.String() != "Q"+strings.ToLower(hex128) {
				t.Errorf("String() = %s", a)
			}
		}
	}
	if _, err := ParseQAddress("Q" + hex128); err != nil {
		t.Error(err)
	}
}

func TestString(t *testing.T) {
	var s String
	if err := s.UnmarshalJSON([]byte(`"ZOND"`)); err != nil || s != "ZOND" {
		t.Errorf("got %q, %v", s, err)
	}
	for _, in := range []string{`5`, `null`, `{}`, `[]`, `"a"b"`} {
		if err := s.UnmarshalJSON([]byte(in)); err == nil {
			t.Errorf("%s accepted", in)
		}
	}
}

// Bytes decodes every escape as encoding/json decodes it into a string,
// into a buffer of its own, and keeps bytes that are not UTF-8.
func TestBytes(t *testing.T) {
	for _, in := range []string{
		`""`, `"plain"`, `"q\"uote"`, `"\\\/\b\f\n\r\t"`, `"\u00e9t\u00C9"`, `"\ud83d\ude00 smile"`,
		`"lone \ud83d high"`, `"lone \ude00 low"`, `"\ud83d\u0041 not a pair"`, `"end \ud83d"`, `"ß ünïcödé"`,
		`"{\"version\":1,\"crypto\":{}}"`,
	} {
		var want string
		if err := json.Unmarshal([]byte(in), &want); err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		raw := []byte(in)
		var got Bytes
		if err := got.UnmarshalJSON(raw); err != nil || string(got) != want {
			t.Errorf("%s: got %q, %v; want %q", in, got, err, want)
		}
		if len(got) > 0 && len(raw) > 2 && &got[0] == &raw[1] {
			t.Errorf("%s: the result aliases the input", in)
		}
	}
	var b Bytes
	if err := b.UnmarshalJSON([]byte("\"\xff\xfe\"")); err != nil || string(b) != "\xff\xfe" {
		t.Errorf("non-UTF-8 bytes: %q, %v", b, err)
	}
	for _, in := range []string{`5`, `null`, `{}`, `[]`, `"a"b"`, `"\x"`, `"\u12"`, `"\u12zz"`} {
		if err := b.UnmarshalJSON([]byte(in)); err == nil {
			t.Errorf("%s accepted", in)
		}
	}
	if out, err := (Bytes("a\"b")).MarshalJSON(); err != nil || string(out) != `"a\"b"` {
		t.Errorf("MarshalJSON = %s, %v", out, err)
	}
}

// point is a two-field object for the DecodeObject tables.
type point struct {
	X, Y Uint64String
	Tag  String
}

func (p *point) fields() []Field {
	return []Field{
		{Name: "x", Value: &p.X},
		{Name: "y", Value: &p.Y},
		{Name: "tag", Value: &p.Tag, Optional: true},
	}
}

func TestDecodeObject(t *testing.T) {
	tests := []struct {
		in    string
		r     apierr.Reason
		field string
	}{
		{`{"x":"1","y":"2"}`, pass, ""},
		{` { "y" : "2" , "x" : "1" , "tag" : "t" } `, pass, ""},
		{`{"x":"1","y":"2","z":"3"}`, unknownFld, "z"},
		{`{"X":"1","y":"2"}`, unknownFld, "X"}, // keys are case-sensitive
		{`{"x":"1","Y":"2","y":"2"}`, unknownFld, "Y"},
		{`{"x":"1","y":"2"}`, pass, ""}, // an escaped key is unescaped first
		{`{"x":"1","x":"1","y":"2"}`, mal, "x"},
		{`{"x":"1"}`, bad, "y"}, // missing required field
		{`{"x":1,"y":"2"}`, bad, "x"},
		{`{"x":null,"y":"2"}`, bad, "x"},
		{`{"x":"1","y":"2","tag":null}`, bad, "tag"},
		{`[]`, bad, ""},
		{`"x"`, bad, ""},
		{`null`, bad, ""},
		{`{"x":"1","y":"2"`, mal, ""},
		{`{"x":"1","y":"2"} {}`, mal, ""},
		{`{"x":"1" "y":"2"}`, mal, ""},
		{`{"x" "1"}`, mal, ""},
		{`{"x":"1",}`, mal, ""},
		{`{"sig\u0000":"1"}`, unknownFld, `"sig?"`},
		{`{"` + strings.Repeat("k", 100) + `":"1"}`, unknownFld, `"` + strings.Repeat("k", 40) + `"`},
	}
	for _, tt := range tests {
		var p point
		err := DecodeObject([]byte(tt.in), p.fields()...)
		if got := reasonOf(t, err); got != tt.r {
			t.Errorf("%s: reason %q, want %q (%v)", tt.in, got, tt.r, err)
			continue
		}
		if err != nil {
			if f := err.(*apierr.Error).Field; f != tt.field {
				t.Errorf("%s: field %q, want %q", tt.in, f, tt.field)
			}
		} else if p.X != 1 || p.Y != 2 {
			t.Errorf("%s: decoded %+v", tt.in, p)
		}
	}
}

func TestEncodeObject(t *testing.T) {
	p := point{X: 1, Y: 2}
	f := p.fields()
	f[2].Value = nil
	out, err := EncodeObject(f...)
	if err != nil || string(out) != `{"x":"1","y":"2"}` {
		t.Fatalf("got %s, %v", out, err)
	}
	f[0].Value = nil
	if _, err := EncodeObject(f...); err == nil {
		t.Error("a required field without a value was encoded")
	}
}

func TestDecodeArray(t *testing.T) {
	tests := []struct {
		in    string
		n     int
		r     apierr.Reason
		field string
	}{
		{`[]`, 0, pass, ""},
		{` [ "1" , "2" , "3" ] `, 3, pass, ""},
		{`["1",2]`, 0, bad, "[1]"},
		{`{}`, 0, bad, ""},
		{`["1",]`, 0, mal, ""},
		{`["1"`, 0, mal, ""},
	}
	for _, tt := range tests {
		var got []Uint64String
		n, err := DecodeArray([]byte(tt.in), func(i int, raw []byte) error {
			var u Uint64String
			if err := u.UnmarshalJSON(raw); err != nil {
				return err
			}
			got = append(got, u)
			return nil
		})
		if r := reasonOf(t, err); r != tt.r {
			t.Errorf("%s: reason %q, want %q (%v)", tt.in, r, tt.r, err)
			continue
		}
		if err != nil {
			if f := err.(*apierr.Error).Field; f != tt.field {
				t.Errorf("%s: field %q, want %q", tt.in, f, tt.field)
			}
			continue
		}
		if n != tt.n || len(got) != tt.n {
			t.Errorf("%s: %d elements, decoded %d", tt.in, n, len(got))
		}
		if count, _ := DecodeArray([]byte(tt.in), nil); count != n {
			t.Errorf("%s: counted %d", tt.in, count)
		}
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		in string
		r  apierr.Reason
	}{
		{`{"a":1,"b":{"a":1,"b":[{"a":1},{"a":2}]}}`, pass},
		{`{"a":"x","b":"a"}`, pass}, // a value equal to a key is not a key
		{`{"a":{"c":1},"b":{"c":1}}`, pass},
		{`[{"a":1},{"a":1}]`, pass},
		{`{"a":1,"a":2}`, mal},
		{`{"a":1,"b":{"c":1,"c":1}}`, mal},
		{`[{"a":1,"a":1}]`, mal},
		{`{"a":1,"a":2}`, mal},
		{`{"a\"b":1,"a\"b":2}`, mal},
		{`{"a\\":1,"a\\\\":2}`, pass},
		{``, mal},
		{`{`, mal},
		{`{"a":1,}`, mal},
		{`{'a':1}`, mal},
		{"\xef\xbb\xbf{}", mal}, // byte order mark
		{`{"a":01}`, mal},
	}
	for _, tt := range tests {
		if got := reasonOf(t, Validate([]byte(tt.in))); got != tt.r {
			t.Errorf("%s: reason %q, want %q", tt.in, got, tt.r)
		}
	}
}

// A large object switches the key set to a map and still finds duplicates.
func TestValidateLargeObject(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i := range 5000 {
		if i > 0 {
			buf.WriteByte(',')
		}
		key, _ := json.Marshal(strings.Repeat("k", i%7) + string(rune('a'+i%26)) + Uint64String(uint64(i)).str())
		buf.Write(key)
		buf.WriteString(":0")
	}
	distinct := append(bytes.Clone(buf.Bytes()), '}')
	if err := Validate(distinct); err != nil {
		t.Fatalf("distinct keys refused: %v", err)
	}
	dup := append(bytes.Clone(buf.Bytes()), []byte(`,"a0":1}`)...)
	if r := reasonOf(t, Validate(dup)); r != mal {
		t.Errorf("duplicate in a large object: reason %q", r)
	}
}

func (u Uint64String) str() string {
	b, _ := u.MarshalJSON()
	return string(b[1 : len(b)-1])
}

func TestRawValue(t *testing.T) {
	in := []byte(`{"a":{"b":[1,2]},"c":"d"}`)
	var a, c RawValue
	if err := DecodeObject(in, Field{Name: "a", Value: &a}, Field{Name: "c", Value: &c}); err != nil {
		t.Fatal(err)
	}
	if string(a) != `{"b":[1,2]}` || string(c) != `"d"` {
		t.Errorf("a=%s c=%s", a, c)
	}
	var none RawValue
	if out, _ := none.MarshalJSON(); string(out) != "null" {
		t.Errorf("nil raw value marshals to %s", out)
	}
}
