// Copyright 2020 ConsenSys AG.
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
// slashing-protection/src/integration-test/java/tech/pegasys/web3signer/slashingprotection/InterchangeImportConflictsIntegrationTestBase.java,
// slashing-protection/src/integration-test/java/tech/pegasys/web3signer/slashingprotection/InterchangeImportBadJsonFormattingIntegrationTestBase.java,
// slashing-protection/src/integration-test/java/tech/pegasys/web3signer/slashingprotection/InterchangeImportBadLogicalContentIntegrationTestBase.java
// and slashing-protection/src/integration-test/java/tech/pegasys/web3signer/slashingprotection/WatermarkImportingIntegrationTestBase.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package interchange_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/interchange"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

// These tests port Web3Signer's interchange import integration tests, with 2,592-byte keys and 32-byte roots in
// place of the upstream fixtures. Where go-remotesigner differs, the test asserts the deviation (X16): a failed
// validator is reported and its key is registered disabled instead of being silently skipped.

func TestImportConflicts(t *testing.T) {
	singleBlock := jEntry{Pubkey: pk(0), Blocks: []jBlock{blk(12345, root(1))}}
	singleAtt := jEntry{Pubkey: pk(0), Atts: []jAtt{att(5, 6, root(2))}}
	for _, tc := range []struct {
		name  string
		entry jEntry
		twice bool
		want  state
	}{
		{"duplicate entries are not inserted", singleBlock, true,
			state{blocks: []slashing.SignedBlock{sb(12345, slashingtest.RootPtr(1))}, low: lw(u64(12345), nil, nil)}},
		{"conflicting blocks in the same slot are not inserted",
			jEntry{Pubkey: pk(0), Blocks: []jBlock{blk(12345, root(1)), blk(12345, root(9))}}, false,
			state{blocks: []slashing.SignedBlock{sb(12345, slashingtest.RootPtr(1))}, low: lw(u64(12345), nil, nil)}},
		{"a file with duplicate blocks loads", jEntry{Pubkey: pk(0), Blocks: []jBlock{blk(12345, root(1)), blk(12345, root(1))}}, true,
			state{blocks: []slashing.SignedBlock{sb(12345, slashingtest.RootPtr(1))}, low: lw(u64(12345), nil, nil)}},
		{"attestations are not duplicated", singleAtt, true,
			state{atts: []slashing.SignedAttestation{sa(5, 6, slashingtest.RootPtr(2))}, low: lw(nil, u64(5), u64(6))}},
		{"duplicate attestations in a file insert one",
			jEntry{Pubkey: pk(0), Atts: []jAtt{att(5, 6, root(2)), att(5, 6, root(2))}}, true,
			state{atts: []slashing.SignedAttestation{sa(5, 6, slashingtest.RootPtr(2))}, low: lw(nil, u64(5), u64(6))}},
		{"blocks without a signing root", jEntry{Pubkey: pk(0), Blocks: []jBlock{blk(12345, nil), blk(12346, nil)}}, false,
			state{blocks: []slashing.SignedBlock{sb(12345, nil), sb(12346, nil)}, low: lw(u64(12345), nil, nil)}},
		{"blocks without a signing root are not duplicated on re-import",
			jEntry{Pubkey: pk(0), Blocks: []jBlock{blk(12345, nil), blk(12346, nil)}}, true,
			state{blocks: []slashing.SignedBlock{sb(12345, nil), sb(12346, nil)}, low: lw(u64(12345), nil, nil)}},
		{"attestations without a signing root", jEntry{Pubkey: pk(0), Atts: []jAtt{att(5, 6, nil), att(7, 8, nil)}}, false,
			state{atts: []slashing.SignedAttestation{sa(5, 6, nil), sa(7, 8, nil)}, low: lw(nil, u64(5), u64(6))}},
		{"attestations without a signing root are not duplicated on re-import",
			jEntry{Pubkey: pk(0), Atts: []jAtt{att(5, 6, nil), att(7, 8, nil)}}, true,
			state{atts: []slashing.SignedAttestation{sa(5, 6, nil), sa(7, 8, nil)}, low: lw(nil, u64(5), u64(6))}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forEachStore(t, func(t *testing.T, s slashing.Store) {
				d := doc(gvr, tc.entry)
				importDoc(t, s, d)
				if tc.twice {
					importDoc(t, s, d)
				}
				wantState(t, dump(t, s), 0, tc.want)
			})
		})
	}
}

func TestImportNewBlockForExistingValidator(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		must(t, s.RegisterValidators(bg, [][]byte{slashingtest.Key(0)}))
		importDoc(t, s, doc(gvr, jEntry{Pubkey: pk(0), Blocks: []jBlock{blk(12345, root(1))}}))
		wantState(t, dump(t, s), 0, state{blocks: []slashing.SignedBlock{sb(12345, slashingtest.RootPtr(1))}, low: lw(u64(12345), nil, nil)})
	})
}

func TestImportBadJSONFormatting(t *testing.T) {
	meta := `{"metadata":{"interchange_format_version":"5","genesis_validators_root":"` + hx(gvr[:]) + `"}`
	t.Run("a data field that is not an array fails the import", func(t *testing.T) {
		forEachStore(t, func(t *testing.T, s slashing.Store) {
			_, err := interchange.Import(bg, s, strings.NewReader(meta+`,"data":"5"}`), interchange.ImportOptions{})
			if !errors.Is(err, interchange.ErrFormat) {
				t.Fatalf("import: %v", err)
			}
			if got := dump(t, s); len(got) != 0 {
				t.Fatalf("store is not empty: %+v", got)
			}
		})
	})
	for name, d := range map[string]string{
		"a missing data section imports nothing": meta + `}`,
		"an empty data section imports nothing":  meta + `,"data":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			forEachStore(t, func(t *testing.T, s slashing.Store) {
				if res := importDoc(t, s, d); len(res.Validators) != 0 {
					t.Fatalf("result %+v", res)
				}
				if got := dump(t, s); len(got) != 0 {
					t.Fatalf("store is not empty: %+v", got)
				}
			})
		})
	}
	// Web3Signer rolls the validator back and logs; here it is reported, and its key is registered disabled.
	t.Run("an error in a later block rolls the validator back", func(t *testing.T) {
		forEachStore(t, func(t *testing.T, s slashing.Store) {
			bad := `{"pubkey":"` + pk(0) + `","signed_blocks":[{"slot":"12345","signing_root":"` + *root(1) +
				`"},{"signing_root":"` + *root(1) + `"}],"signed_attestations":[]}`
			res := importDoc(t, s, doc(gvr, bad))
			if f := res.Failed(); len(f) != 1 || f[0].Index != 0 || !strings.Contains(f[0].Err.Error(), "slot is missing") {
				t.Fatalf("failures %+v", f)
			}
			wantState(t, dump(t, s), 0, state{})
			if st := enabled(t, s, 0); !st.Registered || st.Enabled {
				t.Fatalf("failed key: %+v, want registered and disabled", st)
			}
		})
	})
	t.Run("an error in one validator does not stop the others", func(t *testing.T) {
		forEachStore(t, func(t *testing.T, s slashing.Store) {
			bad := `{"pubkey":"` + pk(1) + `","signed_blocks":[{"slot":"12346","signing_root":"` + *root(1) +
				`"}],"signed_attestations":[{"source_epoch":"6","signing_root":"` + *root(1) + `"}]}`
			res := importDoc(t, s, doc(gvr,
				jEntry{Pubkey: pk(0), Blocks: []jBlock{blk(12345, root(1))}, Atts: []jAtt{att(5, 6, root(2))}},
				bad,
				jEntry{Pubkey: pk(2), Blocks: []jBlock{blk(12347, root(3))}, Atts: []jAtt{att(7, 8, root(4))}}))
			if f := res.Failed(); len(f) != 1 || f[0].Index != 1 {
				t.Fatalf("failures %+v", f)
			}
			got := dump(t, s)
			wantState(t, got, 0, state{blocks: []slashing.SignedBlock{sb(12345, slashingtest.RootPtr(1))},
				atts: []slashing.SignedAttestation{sa(5, 6, slashingtest.RootPtr(2))}, low: lw(u64(12345), u64(5), u64(6))})
			wantState(t, got, 1, state{})
			wantState(t, got, 2, state{blocks: []slashing.SignedBlock{sb(12347, slashingtest.RootPtr(3))},
				atts: []slashing.SignedAttestation{sa(7, 8, slashingtest.RootPtr(4))}, low: lw(u64(12347), u64(7), u64(8))})
			if !enabled(t, s, 0).Enabled || enabled(t, s, 1).Enabled || !enabled(t, s, 2).Enabled {
				t.Fatal("want keys 0 and 2 enabled and key 1 disabled")
			}
		})
	})
	t.Run("a missing public key fails that element and registers nothing", func(t *testing.T) {
		forEachStore(t, func(t *testing.T, s slashing.Store) {
			res := importDoc(t, s, doc(gvr, `{"signed_blocks":[],"signed_attestations":[]}`))
			if f := res.Failed(); len(f) != 1 || f[0].PublicKey != nil {
				t.Fatalf("failures %+v", f)
			}
			if got := dump(t, s); len(got) != 0 {
				t.Fatalf("store is not empty: %+v", got)
			}
		})
	})
}

func TestImportBadLogicalContent(t *testing.T) {
	// Web3Signer's "source greater than target" test actually fails on its 3-byte genesis validators root; both
	// are covered here. A root of the wrong length fails the whole file.
	t.Run("a short genesis validators root", func(t *testing.T) {
		forEachStore(t, func(t *testing.T, s slashing.Store) {
			d := `{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x123456"},"data":[]}`
			if _, err := interchange.Import(bg, s, strings.NewReader(d), interchange.ImportOptions{}); !errors.Is(err, interchange.ErrFormat) {
				t.Fatalf("import: %v", err)
			}
			if _, ok, _ := s.GenesisValidatorsRoot(bg); ok {
				t.Fatal("the store was pinned")
			}
		})
	})
	// Like Web3Signer, an attestation whose source is after its target is imported: it can only make the history
	// stricter, and the rule engine refuses such a request anyway.
	t.Run("an attestation with source after target", func(t *testing.T) {
		forEachStore(t, func(t *testing.T, s slashing.Store) {
			importDoc(t, s, doc(gvr, jEntry{Pubkey: pk(0), Atts: []jAtt{att(6, 5, root(1))}}))
			wantState(t, dump(t, s), 0, state{atts: []slashing.SignedAttestation{sa(6, 5, slashingtest.RootPtr(1))},
				low: lw(nil, u64(6), u64(5))})
		})
	})
	t.Run("a genesis validators root that conflicts with the store's", func(t *testing.T) {
		forEachStore(t, func(t *testing.T, s slashing.Store) {
			_, err := s.PinGenesisValidatorsRoot(bg, slashing.Root{})
			must(t, err)
			_, err = interchange.Import(bg, s, strings.NewReader(doc(gvr, jEntry{Pubkey: pk(0)})), interchange.ImportOptions{})
			if !errors.Is(err, slashing.ErrGenesisValidatorsRootMismatch) {
				t.Fatalf("import: %v", err)
			}
			if got := dump(t, s); len(got) != 0 {
				t.Fatalf("store is not empty: %+v", got)
			}
		})
	})
}

// seedHistory registers key 0 with records and a watermark, as the Web3Signer tests insert rows directly.
func seedHistory(t *testing.T, s slashing.Store, blocks []uint64, atts [][2]uint64, low slashing.LowWatermark) {
	t.Helper()
	id := slashing.KeyIDOf(slashingtest.Key(0))
	must(t, s.RegisterValidators(bg, [][]byte{slashingtest.Key(0)}))
	must(t, s.UpdateHistory(bg, []slashing.KeyID{id}, func(_ slashing.KeyID, tx slashing.HistoryTx) error {
		for _, b := range blocks {
			if err := tx.InsertBlock(sb(b, slashingtest.RootPtr(100))); err != nil {
				return err
			}
		}
		for _, a := range atts {
			if err := tx.InsertAttestation(sa(a[0], a[1], slashingtest.RootPtr(100))); err != nil {
				return err
			}
		}
		if low.Slot != nil {
			if err := tx.RaiseSlotLowWatermark(*low.Slot); err != nil {
				return err
			}
		}
		if low.SourceEpoch != nil {
			return tx.RaiseEpochLowWatermarks(*low.SourceEpoch, *low.TargetEpoch)
		}
		return nil
	}))
}

func TestWatermarkImporting(t *testing.T) {
	for _, tc := range []struct {
		name       string
		seedBlocks []uint64
		seedAtts   [][2]uint64
		seedLow    slashing.LowWatermark
		blocks     []uint64
		atts       [][2]uint64
		want       *slashing.LowWatermark // nil: no watermark at all
	}{
		{name: "the block watermark is the lowest imported slot in an empty store",
			blocks: []uint64{5, 4}, want: &slashing.LowWatermark{Slot: u64(4)}},
		{name: "the block watermark rises when the lowest imported slot is above it",
			seedBlocks: []uint64{3, 10}, seedLow: lw(u64(3), nil, nil), blocks: []uint64{4, 8},
			want: &slashing.LowWatermark{Slot: u64(4)}},
		{name: "the block watermark stays when the lowest imported slot is below it",
			seedBlocks: []uint64{3, 10}, seedLow: lw(u64(3), nil, nil), blocks: []uint64{2, 50},
			want: &slashing.LowWatermark{Slot: u64(3)}},
		{name: "the block watermark stays when any imported slot is below it",
			seedBlocks: []uint64{3, 10}, seedLow: lw(u64(3), nil, nil), blocks: []uint64{50, 2},
			want: &slashing.LowWatermark{Slot: u64(3)}},
		{name: "the attestation watermarks are the imported minima in an empty store",
			atts: [][2]uint64{{3, 4}, {2, 5}}, want: &slashing.LowWatermark{SourceEpoch: u64(2), TargetEpoch: u64(4)}},
		{name: "the attestation watermarks rise when the import is above them",
			seedAtts: [][2]uint64{{3, 4}, {7, 8}}, seedLow: lw(nil, u64(3), u64(4)), atts: [][2]uint64{{8, 10}, {9, 15}},
			want: &slashing.LowWatermark{SourceEpoch: u64(8), TargetEpoch: u64(10)}},
		{name: "the attestation watermarks stay when the import is below them",
			seedAtts: [][2]uint64{{3, 4}, {9, 10}}, seedLow: lw(nil, u64(3), u64(4)), atts: [][2]uint64{{1, 2}},
			want: &slashing.LowWatermark{SourceEpoch: u64(3), TargetEpoch: u64(4)}},
		{name: "only the target epoch rises",
			seedAtts: [][2]uint64{{3, 4}, {9, 10}}, seedLow: lw(nil, u64(3), u64(4)), atts: [][2]uint64{{3, 12}},
			want: &slashing.LowWatermark{SourceEpoch: u64(3), TargetEpoch: u64(12)}},
		{name: "only the source epoch rises",
			seedAtts: [][2]uint64{{3, 6}, {7, 10}}, seedLow: lw(nil, u64(3), u64(6)), atts: [][2]uint64{{4, 5}},
			want: &slashing.LowWatermark{SourceEpoch: u64(4), TargetEpoch: u64(6)}},
		{name: "an empty import leaves the watermarks",
			seedBlocks: []uint64{6}, seedAtts: [][2]uint64{{3, 4}}, seedLow: lw(u64(6), u64(3), u64(4)),
			want: &slashing.LowWatermark{Slot: u64(6), SourceEpoch: u64(3), TargetEpoch: u64(4)}},
		{name: "an empty import into an empty store sets no watermark", want: &slashing.LowWatermark{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forEachStore(t, func(t *testing.T, s slashing.Store) {
				if tc.seedBlocks != nil || tc.seedAtts != nil || tc.seedLow != (slashing.LowWatermark{}) {
					seedHistory(t, s, tc.seedBlocks, tc.seedAtts, tc.seedLow)
				}
				e := jEntry{Pubkey: pk(0)}
				for _, b := range tc.blocks {
					e.Blocks = append(e.Blocks, blk(b, nil))
				}
				for _, a := range tc.atts {
					e.Atts = append(e.Atts, att(a[0], a[1], nil))
				}
				importDoc(t, s, doc(gvr, e))
				got := dump(t, s)[0].low
				if !equalLow(got, *tc.want) {
					t.Fatalf("low watermark %s, want %s", fmtLow(got), fmtLow(*tc.want))
				}
			})
		})
	}
}

func equalLow(a, b slashing.LowWatermark) bool { return fmtLow(a) == fmtLow(b) }

func fmtLow(w slashing.LowWatermark) string {
	f := func(p *uint64) string {
		if p == nil {
			return "-"
		}
		return u(*p)
	}
	return "{slot " + f(w.Slot) + ", source " + f(w.SourceEpoch) + ", target " + f(w.TargetEpoch) + "}"
}
