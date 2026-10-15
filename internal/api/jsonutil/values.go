// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package jsonutil

import (
	"encoding/hex"
	"math/bits"
	"strconv"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
)

func badField(detail string) *apierr.Error { return apierr.New(apierr.BadField, detail) }

// Uint64String is a uint64 written as a decimal string, "0" to
// "18446744073709551615": no sign, no leading zeros, not empty. JSON numbers
// are rejected.
type Uint64String uint64

// UnmarshalJSON accepts only the canonical decimal string.
func (u *Uint64String) UnmarshalJSON(b []byte) error {
	s, err := stringContent(b)
	if err != nil {
		return wrongType("a decimal string")
	}
	v, ok := parseUint64(s)
	if !ok {
		return badField("not a canonical decimal uint64")
	}
	*u = Uint64String(v)
	return nil
}

// MarshalJSON writes the quoted decimal value.
func (u Uint64String) MarshalJSON() ([]byte, error) {
	out := make([]byte, 0, 22)
	out = append(out, '"')
	out = strconv.AppendUint(out, uint64(u), 10)
	return append(out, '"'), nil
}

// parseUint64 parses a canonical decimal uint64.
func parseUint64(s []byte) (uint64, bool) {
	if len(s) == 0 || len(s) > 20 || (s[0] == '0' && len(s) > 1) {
		return 0, false
	}
	var v uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		d := uint64(c - '0')
		if v > (^uint64(0)-d)/10 {
			return 0, false
		}
		v = v*10 + d
	}
	return v, true
}

// HexBytesN is a fixed-size byte string written as "0x" followed by exactly
// 2*len hex digits in either case. It decodes into its own backing array, so
// it is used as a view of a fixed-size array:
//
//	jsonutil.HexBytesN(header.ParentRoot[:])
type HexBytesN []byte

// UnmarshalJSON decodes exactly len(h) bytes into h.
func (h HexBytesN) UnmarshalJSON(b []byte) error {
	s, err := stringContent(b)
	if err != nil {
		return err
	}
	if len(s) < 2 || s[0] != '0' || s[1] != 'x' {
		return badField("missing 0x prefix")
	}
	if len(s)-2 != 2*len(h) {
		return badField("wrong length, want " + strconv.Itoa(len(h)) + " bytes")
	}
	if _, err := hex.Decode(h, s[2:]); err != nil {
		return badField("not hex")
	}
	return nil
}

// MarshalJSON writes "0x" and lowercase hex.
func (h HexBytesN) MarshalJSON() ([]byte, error) {
	return quotedHex("0x", h), nil
}

func quotedHex(prefix string, b []byte) []byte {
	out := make([]byte, 1+len(prefix)+2*len(b)+1)
	out[0] = '"'
	copy(out[1:], prefix)
	hex.Encode(out[1+len(prefix):], b)
	out[len(out)-1] = '"'
	return out
}

// decodeHex decodes a "0x"-prefixed hex string of minLen to maxLen bytes.
func decodeHex(b []byte, minLen, maxLen int) ([]byte, error) {
	s, err := stringContent(b)
	if err != nil {
		return nil, err
	}
	if len(s) < 2 || s[0] != '0' || s[1] != 'x' {
		return nil, badField("missing 0x prefix")
	}
	s = s[2:]
	if len(s)%2 != 0 || len(s)/2 < minLen || len(s)/2 > maxLen {
		want := strconv.Itoa(minLen)
		if maxLen != minLen {
			want += "-" + strconv.Itoa(maxLen)
		}
		return nil, badField("wrong length, want " + want + " bytes")
	}
	out := make([]byte, len(s)/2)
	if _, err := hex.Decode(out, s); err != nil {
		return nil, badField("not hex")
	}
	return out, nil
}

// Bitlist32MaxBits is the limit of Attestation.aggregation_bits.
const Bitlist32MaxBits = 32

// Bitlist32 is an SSZ Bitlist[32] in its serialized form, delimiter bit
// included: 1-5 bytes, the last one non-zero, at most 32 bits before the
// delimiter.
type Bitlist32 []byte

// UnmarshalJSON accepts "0x" and the hex of a valid Bitlist[32].
func (l *Bitlist32) UnmarshalJSON(b []byte) error {
	raw, err := decodeHex(b, 1, Bitlist32MaxBits/8+1)
	if err != nil {
		return err
	}
	last := raw[len(raw)-1]
	if last == 0 {
		return badField("bitlist has no delimiter bit")
	}
	if n := (len(raw)-1)*8 + bits.Len8(last) - 1; n > Bitlist32MaxBits {
		return badField("bitlist longer than 32 bits")
	}
	*l = raw
	return nil
}

// MarshalJSON writes "0x" and lowercase hex.
func (l Bitlist32) MarshalJSON() ([]byte, error) {
	return quotedHex("0x", l), nil
}

// BitvectorN is an SSZ Bitvector[N] in its serialized form: exactly
// ceil(N/8) bytes, with the bits past N zero. N comes from the network
// (the sync subcommittee size), so the value carries it.
type BitvectorN struct {
	Bits *[]byte
	N    uint64
}

// UnmarshalJSON accepts "0x" and the hex of exactly ceil(N/8) bytes.
func (v BitvectorN) UnmarshalJSON(b []byte) error {
	if v.N == 0 || v.N > 1<<20 {
		return apierr.New(apierr.Internal, "bitvector length not configured")
	}
	want := int((v.N + 7) / 8)
	raw, err := decodeHex(b, want, want)
	if err != nil {
		return err
	}
	if rem := v.N % 8; rem != 0 && raw[len(raw)-1]>>rem != 0 {
		return badField("bitvector has bits set past its length")
	}
	*v.Bits = raw
	return nil
}

// MarshalJSON writes "0x" and lowercase hex. N is not checked.
func (v BitvectorN) MarshalJSON() ([]byte, error) {
	return quotedHex("0x", *v.Bits), nil
}

// AddressLength is the length of a QRL execution address.
const AddressLength = 64

// QAddress is a 64-byte QRL address written as "Q" followed by 128 hex
// digits in either case. The QIP-55 mixed-case checksum is not enforced,
// matching go-qrl's own JSON decoder. "0x" and every other prefix are
// rejected.
type QAddress [AddressLength]byte

// UnmarshalJSON accepts only the Q form.
func (a *QAddress) UnmarshalJSON(b []byte) error {
	s, err := stringContent(b)
	if err != nil {
		return err
	}
	v, err := parseQAddress(s)
	if err != nil {
		return err
	}
	*a = v
	return nil
}

// MarshalJSON writes "Q" and lowercase hex.
func (a QAddress) MarshalJSON() ([]byte, error) {
	return quotedHex("Q", a[:]), nil
}

// String returns "Q" and lowercase hex.
func (a QAddress) String() string {
	q := quotedHex("Q", a[:])
	return string(q[1 : len(q)-1])
}

// ParseQAddress parses the Q form of an address.
func ParseQAddress(s string) (QAddress, error) {
	return parseQAddress([]byte(s))
}

func parseQAddress(s []byte) (QAddress, error) {
	var a QAddress
	if len(s) == 0 || s[0] != 'Q' {
		return a, badField("address must start with Q")
	}
	if len(s) != 1+2*AddressLength {
		return a, badField("wrong length, want 64 bytes")
	}
	if _, err := hex.Decode(a[:], s[1:]); err != nil {
		return a, badField("not hex")
	}
	return a, nil
}
