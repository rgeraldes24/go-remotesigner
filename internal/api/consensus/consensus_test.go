// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package consensus

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"iter"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/signingroot"
	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/network"
)

func TestParseIdentifier(t *testing.T) {
	var pk [mldsa87.PublicKeySize]byte
	for i := range pk {
		pk[i] = byte(i * 7)
	}
	id := sha256.Sum256(pk[:])
	canonical := "0x" + hex.EncodeToString(pk[:])
	short := "0x" + hex.EncodeToString(id[:])

	for _, s := range []string{canonical, strings.ToUpper(canonical[:2]) + canonical[2:], "0x" + strings.ToUpper(canonical[2:]), short} {
		if s[1] == 'X' {
			continue // "0X" is not a valid prefix; covered below
		}
		got, e := ParseIdentifier(s)
		if e != nil || got != id {
			t.Errorf("ParseIdentifier(%.12s…) = %x, %v; want %x", s, got, e, id)
		}
	}

	bad := []struct {
		name string
		s    string
	}{
		{"5,188 characters", canonical + "ab"}, // G4 S7: rejected before decoding
		{"5,185 characters", canonical[:5185]}, // odd length
		{"empty", ""},
		{"no prefix, canonical length", "ab" + canonical[2:]},
		{"0X prefix", "0X" + short[2:]},
		{"non-hex", short[:10] + "g" + short[11:]},
		{"non-hex canonical", canonical[:100] + "z" + canonical[101:]},
		{"40 hex", "0x" + strings.Repeat("a", 40)},
	}
	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			if _, e := ParseIdentifier(tt.s); e == nil || e.Reason != apierr.BadIdentifier || e.Status() != 400 {
				t.Fatalf("ParseIdentifier = %v, want 400 BAD_IDENTIFIER", e)
			}
		})
	}
}

// BenchmarkParseIdentifierTooLong shows the precheck costs no decoding.
func BenchmarkParseIdentifierTooLong(b *testing.B) {
	s := "0x" + strings.Repeat("a", 5186)
	for b.Loop() {
		_, _ = ParseIdentifier(s)
	}
}

func randomKeys(n int) []*mldsa87.PublicKey {
	out := make([]*mldsa87.PublicKey, n)
	for i := range out {
		out[i] = new(mldsa87.PublicKey)
		_, _ = rand.Read(out[i][:])
	}
	slices.SortFunc(out, func(a, b *mldsa87.PublicKey) int { return bytes.Compare(a[:], b[:]) })
	return out
}

func seq(keys []*mldsa87.PublicKey) func() iter.Seq[*mldsa87.PublicKey] {
	return func() iter.Seq[*mldsa87.PublicKey] { return slices.Values(keys) }
}

func TestPublicKeys(t *testing.T) {
	keys := randomKeys(5)
	h := PublicKeys(seq(keys))
	want := make([]string, len(keys))
	for i, k := range keys {
		want[i] = "0x" + hex.EncodeToString(k[:])
	}

	for _, enc := range []string{"", "gzip", "br, gzip;q=0.5", "gzip;q=0"} {
		t.Run("Accept-Encoding "+enc, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/api/v1/consensus/publicKeys", nil)
			if enc != "" {
				r.Header.Set("Accept-Encoding", enc)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			var body io.Reader = rec.Body
			gzipped := rec.Header().Get("Content-Encoding") == "gzip"
			if gzipped != acceptsGzip(enc) {
				t.Fatalf("Content-Encoding %q for %q", rec.Header().Get("Content-Encoding"), enc)
			}
			if gzipped {
				zr, err := gzip.NewReader(rec.Body)
				if err != nil {
					t.Fatal(err)
				}
				body = zr
			}
			var got []string
			if err := json.NewDecoder(body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, want) {
				t.Fatalf("got %d keys, not the sorted canonical identifiers", len(got))
			}
			if rec.Header().Get("Content-Type") != "application/json; charset=utf-8" {
				t.Fatalf("Content-Type %q", rec.Header().Get("Content-Type"))
			}
		})
	}

	rec := httptest.NewRecorder()
	PublicKeys(seq(nil)).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Body.String() != "[]" {
		t.Fatalf("no keys: %q", rec.Body)
	}
}

func TestAcceptsGzip(t *testing.T) {
	tests := map[string]bool{
		"":                  false,
		"gzip":              true,
		"GZIP":              true,
		"deflate, gzip":     true,
		"gzip;q=0":          false,
		"gzip; q=0.001":     true,
		"gzip;q=bad":        false,
		"x-gzip":            false,
		"identity, br;q=1":  false,
		" gzip ; q=1.0 ,br": true,
	}
	for in, want := range tests {
		if got := acceptsGzip(in); got != want {
			t.Errorf("acceptsGzip(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestCapabilities(t *testing.T) {
	n, err := network.Load(network.Sources{Network: "end-to-end"})
	if err != nil {
		t.Fatal(err)
	}
	var pinned *[32]byte
	c := Capabilities{
		Network: n,
		Types:   func() []signingroot.ArtifactType { return []signingroot.ArtifactType{signingroot.BlockV2} },
		GenesisValidatorsRoot: func() ([32]byte, bool) {
			if pinned == nil {
				return [32]byte{}, false
			}
			return *pinned, true
		},
		SelectionProofMode: "deterministic",
		SlashingProtection: ProtectionBolt,
	}
	get := func() map[string]any {
		rec := httptest.NewRecorder()
		c.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		var m map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}

	m := get()
	netw := m["network"].(map[string]any)
	if m["api_version"] != "1.0.0" || m["randao_reveal"] != false || netw["genesis_time"] != nil ||
		netw["genesis_validators_root"] != nil || netw["genesis_fork_version"] != "0x000000fd" ||
		netw["slots_per_epoch"] != "6" || netw["seconds_per_slot"] != "10" || netw["config_name"] != "end-to-end" {
		t.Fatalf("capabilities without genesis: %v", m)
	}

	n.GenesisTime, n.GenesisTimeSource = 1760000000, network.SourceFlag
	pinned = &[32]byte{0xab}
	m = get()
	netw = m["network"].(map[string]any)
	if m["randao_reveal"] != true || netw["genesis_time"] != "1760000000" ||
		netw["genesis_validators_root"] != "0xab"+strings.Repeat("0", 62) {
		t.Fatalf("capabilities with genesis: %v", m)
	}
	if got := m["types"].([]any); len(got) != 1 || got[0] != "BLOCK_V2" {
		t.Fatalf("types %v", got)
	}
}

// B15: GET publicKeys for 10,000 keys, plain and gzip. Threshold (G6 §8):
// at most 2 s, and at most 64 MB of transient allocation, per request.
func BenchmarkPublicKeys10k(b *testing.B) {
	keys := randomKeys(10_000)
	h := PublicKeys(seq(keys))
	for _, enc := range []string{"plain", "gzip"} {
		b.Run(enc, func(b *testing.B) {
			r := httptest.NewRequest(http.MethodGet, "/api/v1/consensus/publicKeys", nil)
			if enc == "gzip" {
				r.Header.Set("Accept-Encoding", "gzip")
			}
			b.ReportAllocs()
			for b.Loop() {
				h.ServeHTTP(discard{h: http.Header{}}, r)
			}
		})
	}
}

// discard is a ResponseWriter that drops the body, so the benchmark measures
// the handler, not a recorder's buffer.
type discard struct{ h http.Header }

func (d discard) Header() http.Header       { return d.h }
func (discard) Write(b []byte) (int, error) { return len(b), nil }
func (discard) WriteHeader(int)             {}
