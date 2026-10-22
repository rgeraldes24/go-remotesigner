// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package boltstore

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

func p(v uint64) *uint64 { return &v }

func TestLowWatermarkRoundTrip(t *testing.T) {
	for _, w := range []slashing.LowWatermark{
		{},
		{Slot: p(0)},
		{Slot: p(math.MaxUint64)},
		{SourceEpoch: p(0), TargetEpoch: p(0)},
		{Slot: p(7), SourceEpoch: p(3), TargetEpoch: p(4)},
	} {
		got, err := decodeLowWatermark(encodeLowWatermark(w))
		if err != nil || !reflect.DeepEqual(got, w) {
			t.Errorf("round trip of %s: %s, %v", fmtLow(w), fmtLow(got), err)
		}
	}
	if got, err := decodeLowWatermark(nil); err != nil || got != (slashing.LowWatermark{}) {
		t.Errorf("absent low watermark: %+v %v", got, err)
	}
}

func TestHighWatermarkRoundTrip(t *testing.T) {
	for _, h := range []slashing.HighWatermark{
		{},
		{Epoch: p(0), Slot: p(0)},
		{Epoch: p(10), Slot: p(1280)},
		{Epoch: p(math.MaxUint64), Slot: p(math.MaxUint64)},
	} {
		got, err := decodeHighWatermark(encodeHighWatermark(h))
		if err != nil || !reflect.DeepEqual(got, h) {
			t.Errorf("round trip of %+v: %+v, %v", h, got, err)
		}
	}
	// A file that holds one part alone was written around the store: it is
	// reported as damaged.
	for _, h := range []slashing.HighWatermark{{Epoch: p(0)}, {Slot: p(math.MaxUint64)}} {
		if _, err := decodeHighWatermark(encodeHighWatermark(h)); !errors.Is(err, ErrCorrupt) ||
			!errors.Is(err, slashing.ErrPartialHighWatermark) {
			t.Errorf("decode of %+v: %v, want ErrCorrupt and ErrPartialHighWatermark", h, err)
		}
	}
}

func TestRecordRoundTrip(t *testing.T) {
	for _, a := range []slashing.SignedAttestation{
		{SourceEpoch: 1, TargetEpoch: 2, SigningRoot: slashingtest.RootPtr(3)},
		{SourceEpoch: math.MaxUint64, TargetEpoch: math.MaxUint64},
	} {
		got, err := decodeAttestation(u64(a.TargetEpoch), encodeAttestation(a))
		if err != nil || !reflect.DeepEqual(got, a) {
			t.Errorf("attestation round trip of %+v: %+v, %v", a, got, err)
		}
	}
	s := slashing.RandaoState{Index: 1 << 20, Reveal: slashingtest.RootOf(5), LastSlot: math.MaxUint64}
	if got, err := decodeRandao(encodeRandao(s)); err != nil || got != s {
		t.Errorf("RANDAO round trip of %+v: %+v, %v", s, got, err)
	}
	for _, v := range []bool{false, true} {
		if got, err := decodeBool("enabled", encodeBool(v)); err != nil || got != v {
			t.Errorf("bool round trip of %v: %v, %v", v, got, err)
		}
	}
}

func TestDecodeRejectsCorruptValues(t *testing.T) {
	for name, err := range map[string]error{
		"version":         errOf(decodeVersion([]byte{1})),
		"root flag":       errOf(decodeRoot("root", []byte{2})),
		"root length":     errOf(decodeRoot("root", make([]byte, 32))),
		"empty root":      errOf(decodeRoot("root", nil)),
		"gvr":             errOf(decodeRoot32("gvr", make([]byte, 31))),
		"bool":            errOf(decodeBool("enabled", []byte{2})),
		"attestation":     errOf(decodeAttestation(u64(1), []byte{0})),
		"attestation key": errOf(decodeAttestation([]byte{1}, encodeAttestation(slashing.SignedAttestation{}))),
		"low length":      errOf(decodeLowWatermark(make([]byte, 24))),
		"low flags":       errOf(decodeLowWatermark(append([]byte{4}, make([]byte, 24)...))),
		"high length":     errOf(decodeHighWatermark(make([]byte, 16))),
		"randao":          errOf(decodeRandao(make([]byte, 47))),
	} {
		if !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: %v, want ErrCorrupt", name, err)
		}
	}
}

func errOf[T any](_ T, err error) error { return err }

func fmtLow(w slashing.LowWatermark) string {
	f := func(p *uint64) any {
		if p == nil {
			return "nil"
		}
		return *p
	}
	return fmt.Sprintf("{slot %v source %v target %v}", f(w.Slot), f(w.SourceEpoch), f(w.TargetEpoch))
}
