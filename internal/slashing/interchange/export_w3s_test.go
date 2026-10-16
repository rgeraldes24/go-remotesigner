// Copyright 2020 ConsenSys AG.
// Copyright 2022 ConsenSys AG.
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
// slashing-protection/src/integration-test/java/tech/pegasys/web3signer/slashingprotection/InterchangeExportIntegrationTestBase.java
// and slashing-protection/src/test/java/tech/pegasys/web3signer/slashingprotection/interchange/InterchangeV5ExporterTest.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package interchange_test

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/interchange"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

// These tests port Web3Signer's interchange export tests. The incremental exporter of Web3Signer (used by its
// keymanager) is covered by the key filter here.

// seedLadder registers key i with blocks at slots 0..blocks-1 and attestations (a, a) for a in 0..atts-1, all with
// root 100, and watermark 0.
func seedLadder(t *testing.T, s slashing.Store, i, blocks, atts int) {
	t.Helper()
	id := slashing.KeyIDOf(slashingtest.Key(i))
	must(t, s.RegisterValidators(bg, [][]byte{slashingtest.Key(i)}))
	must(t, s.UpdateHistory(bg, []slashing.KeyID{id}, func(_ slashing.KeyID, tx slashing.HistoryTx) error {
		for b := range blocks {
			if err := tx.InsertBlock(sb(uint64(b), slashingtest.RootPtr(100))); err != nil {
				return err
			}
		}
		for a := range atts {
			if err := tx.InsertAttestation(sa(uint64(a), uint64(a), slashingtest.RootPtr(100))); err != nil {
				return err
			}
		}
		return errors.Join(tx.RaiseSlotLowWatermark(0), tx.RaiseEpochLowWatermarks(0, 0))
	}))
}

// export returns the decoded export of s.
func export(t *testing.T, s slashing.Store, opts interchange.ExportOptions) (decoded, interchange.ExportResult) {
	t.Helper()
	var buf bytes.Buffer
	res, err := interchange.Export(bg, s, &buf, opts)
	must(t, err)
	got, err := decode(buf.String())
	must(t, err)
	if len(got.errs) != 0 {
		t.Fatalf("the export does not decode: %v", got.errs)
	}
	return got, res
}

// byKey returns the exported entries in the test-key order 0..15 (the export itself is in KeyID order).
func byKey(t *testing.T, d decoded) map[int]interchange.Entry {
	t.Helper()
	out := map[int]interchange.Entry{}
	for _, e := range d.entries {
		i := -1
		for k := range 16 {
			if bytes.Equal(e.PublicKey, slashingtest.Key(k)) {
				i = k
			}
		}
		if i < 0 {
			t.Fatal("exported an unknown key")
		}
		out[i] = e
	}
	return out
}

func TestExportedEntitiesRepresentTheStore(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		_, err := s.PinGenesisValidatorsRoot(bg, gvr)
		must(t, err)
		for i := 1; i <= 2; i++ {
			seedLadder(t, s, i, 6, 8)
		}
		got, res := export(t, s, interchange.ExportOptions{})
		if got.meta.GenesisValidatorsRoot != gvr || len(got.entries) != 2 || res.Validators != 2 || res.Blocks != 12 || res.Attestations != 16 {
			t.Fatalf("export %+v, result %+v", got, res)
		}
		for i, e := range byKey(t, got) {
			if len(e.Blocks) != 6 || len(e.Attestations) != 8 {
				t.Fatalf("validator %d: %d blocks, %d attestations", i, len(e.Blocks), len(e.Attestations))
			}
			for b, blk := range e.Blocks {
				if blk.Slot != uint64(b) || *blk.SigningRoot != slashingtest.RootOf(100) {
					t.Fatalf("validator %d block %d: %+v", i, b, blk)
				}
			}
			for a, at := range e.Attestations {
				if at.SourceEpoch != uint64(a) || at.TargetEpoch != uint64(a) || *at.SigningRoot != slashingtest.RootOf(100) {
					t.Fatalf("validator %d attestation %d: %+v", i, a, at)
				}
			}
		}
	})
}

func TestExportOnlySpecifiedValidators(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		_, err := s.PinGenesisValidatorsRoot(bg, gvr)
		must(t, err)
		for i := 1; i <= 6; i++ {
			seedLadder(t, s, i, 6, 8)
		}
		// Key 7 is registered but has no history; key 9 is unknown. Both are reported missing.
		must(t, s.RegisterValidators(bg, [][]byte{slashingtest.Key(7)}))
		keys := []slashing.KeyID{slashing.KeyIDOf(slashingtest.Key(1)), slashing.KeyIDOf(slashingtest.Key(3)),
			slashing.KeyIDOf(slashingtest.Key(5)), slashing.KeyIDOf(slashingtest.Key(9)), slashing.KeyIDOf(slashingtest.Key(7))}
		got, res := export(t, s, interchange.ExportOptions{Keys: keys})
		entries := byKey(t, got)
		if len(entries) != 3 || len(entries[1].Blocks) != 6 || len(entries[3].Attestations) != 8 || len(entries[5].Blocks) != 6 {
			t.Fatalf("exported %d validators: %+v", len(entries), entries)
		}
		if len(res.Missing) != 2 || res.Missing[0] != keys[3] || res.Missing[1] != keys[4] {
			t.Fatalf("missing %v", res.Missing)
		}
	})
}

// Web3Signer refuses to export without a genesis validators root, and its empty exporter then omits the root.
// go-remotesigner refuses only when no root is known at all; given the network's root it writes it.
func TestExportWithoutGenesisValidatorsRoot(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		var buf bytes.Buffer
		if _, err := interchange.Export(bg, s, &buf, interchange.ExportOptions{}); !errors.Is(err, slashing.ErrNoGenesisValidatorsRoot) {
			t.Fatalf("export of an unpinned store: %v", err)
		}
		if buf.Len() != 0 {
			t.Fatalf("a refused export wrote %q", buf.String())
		}
	})
}

func TestExportOnlyBlocksAtOrAboveTheWatermark(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		_, err := s.PinGenesisValidatorsRoot(bg, gvr)
		must(t, err)
		seedLadder(t, s, 1, 6, 0)
		must(t, s.UpdateHistory(bg, []slashing.KeyID{slashing.KeyIDOf(slashingtest.Key(1))},
			func(_ slashing.KeyID, tx slashing.HistoryTx) error { return tx.RaiseSlotLowWatermark(3) }))
		got, _ := export(t, s, interchange.ExportOptions{})
		e := byKey(t, got)[1]
		if len(e.Blocks) != 3 || e.Blocks[0].Slot != 3 {
			t.Fatalf("blocks %+v", e.Blocks)
		}
	})
}

// Web3Signer writes only the attestations whose source and target epochs are both at or above the watermarks. Here
// the target watermark alone filters (X54): an attestation with a source below the source watermark still rules
// out a double vote at its target, and leaving it out let the importing signer sign another one there.
func TestExportAttestationsFromTheTargetWatermark(t *testing.T) {
	// The store holds the attestations (a, a+10) for a in 0..5.
	ladder := func(from uint64) []slashing.SignedAttestation {
		var out []slashing.SignedAttestation
		for a := from; a < 6; a++ {
			out = append(out, sa(a, a+10, slashingtest.RootPtr(100)))
		}
		return out
	}
	for _, tc := range []struct {
		name           string
		source, target uint64
		want           []slashing.SignedAttestation
		watermarks     int
	}{
		{"the source watermark does not filter", 3, 10, ladder(0), 0},
		{"the target watermark filters", 0, 12, ladder(2), 0},
		{"a target watermark no record sits at is written as an attestation of its own", 3, 9,
			append([]slashing.SignedAttestation{sa(3, 9, nil)}, ladder(0)...), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forEachStore(t, func(t *testing.T, s slashing.Store) {
				_, err := s.PinGenesisValidatorsRoot(bg, gvr)
				must(t, err)
				id := slashing.KeyIDOf(slashingtest.Key(1))
				must(t, s.RegisterValidators(bg, [][]byte{slashingtest.Key(1)}))
				must(t, s.UpdateHistory(bg, []slashing.KeyID{id}, func(_ slashing.KeyID, tx slashing.HistoryTx) error {
					for a := range uint64(6) {
						if err := tx.InsertAttestation(sa(a, a+10, slashingtest.RootPtr(100))); err != nil {
							return err
						}
					}
					// Watermarks that signing alone would not produce, so that each epoch is tested on its own.
					return tx.RaiseEpochLowWatermarks(tc.source, tc.target)
				}))
				got, res := export(t, s, interchange.ExportOptions{})
				if atts := byKey(t, got)[1].Attestations; !reflect.DeepEqual(atts, tc.want) || res.Watermarks != tc.watermarks {
					t.Fatalf("exported %+v (%d watermark records), want %+v (%d)", atts, res.Watermarks, tc.want, tc.watermarks)
				}
			})
		})
	}
}

// InterchangeV5ExporterTest: a write failure surfaces as the export's error.
func TestExportWriteFailure(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		_, err := s.PinGenesisValidatorsRoot(bg, gvr)
		must(t, err)
		for i := range 4 {
			seedLadder(t, s, i, 600, 600)
		}
		fake := errors.New("fake write error")
		if _, err := interchange.Export(bg, s, failingWriter{fake}, interchange.ExportOptions{}); !errors.Is(err, fake) {
			t.Fatalf("export to a failing writer: %v", err)
		}
	})
}

type failingWriter struct{ err error }

func (f failingWriter) Write([]byte) (int, error) { return 0, f.err }
