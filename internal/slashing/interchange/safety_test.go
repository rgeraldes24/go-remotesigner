// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package interchange_test

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/interchange"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/memstore"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

// These tests check the property an export exists for: the signer that imports it refuses every block and
// attestation that the exporting key's history makes slashable, and the file itself holds no slashable pair.

// signed is one key's whole signing history: what its signer recorded, pruned or not, and what the key signed
// elsewhere before a watermark repair. Signing roots are the request roots of the tests.
type signed struct {
	blocks map[uint64]uint64 // slot to root
	atts   []request
}

// slashable reports whether signing r would make the history slashable: a second block at a slot, a second
// attestation at a target, or an attestation that surrounds or is surrounded by a signed one.
func (h *signed) slashable(r request) bool {
	if r.block {
		root, ok := h.blocks[r.slot]
		return ok && root != r.root
	}
	for _, a := range h.atts {
		if (a.target == r.target && a.root != r.root) || (a.source < r.source && a.target > r.target) ||
			(a.source > r.source && a.target < r.target) {
			return true
		}
	}
	return false
}

func (h *signed) add(r request) {
	if r.block {
		h.blocks[r.slot] = r.root
	} else if !slices.Contains(h.atts, r) {
		h.atts = append(h.atts, r)
	}
}

// selfSlashable returns a pair of records in an entry that make it slashable, or "" when there is none.
func selfSlashable(e interchange.Entry) string {
	for i, a := range e.Attestations {
		if a.SourceEpoch > a.TargetEpoch {
			return fmt.Sprintf("%+v has its source after its target", a)
		}
		for _, b := range e.Attestations[i+1:] {
			if a.TargetEpoch == b.TargetEpoch || (a.SourceEpoch < b.SourceEpoch && a.TargetEpoch > b.TargetEpoch) ||
				(a.SourceEpoch > b.SourceEpoch && a.TargetEpoch < b.TargetEpoch) {
				return fmt.Sprintf("%+v and %+v", a, b)
			}
		}
	}
	for i, a := range e.Blocks {
		for _, b := range e.Blocks[i+1:] {
			if a.Slot == b.Slot {
				return fmt.Sprintf("%+v and %+v", a, b)
			}
		}
	}
	return ""
}

// checkExport decodes an export, requires it to hold no slashable pair, and imports it into an empty store, which
// must take every record and count none slashable.
func checkExport(t *testing.T, file string) {
	t.Helper()
	got, err := decode(file)
	must(t, err)
	if len(got.errs) != 0 {
		t.Fatalf("the export does not decode: %v\n%s", got.errs, file)
	}
	for _, e := range got.entries {
		if pair := selfSlashable(e); pair != "" {
			t.Fatalf("the export is slashable: %s\n%s", pair, file)
		}
	}
	res := importDoc(t, memstore.New(), file)
	for _, v := range res.Validators {
		if v.Err != nil || v.Blocks.Conflicts != 0 || v.Attestations.Conflicts != 0 || v.Attestations.Slashable != 0 {
			t.Fatalf("re-import of the export: %+v\n%s", v, file)
		}
	}
}

// importer imports file into an empty store and returns a signer on it.
func importer(t *testing.T, file string, keys [][]byte) *slashing.Engine {
	t.Helper()
	s := memstore.New()
	importDoc(t, s, file)
	e := slashing.NewEngine(s)
	must(t, e.RegisterValidators(bg, keys))
	return e
}

// probe runs every request on a signer that imported file, each on its own fresh import, and fails on the first
// one the importer allows that would make h slashable.
func probe(t *testing.T, file string, keys [][]byte, h *signed, reqs []request) {
	t.Helper()
	e := importer(t, file, keys)
	for _, r := range reqs {
		if d := decide(t, e, r); d.Allowed {
			if h.slashable(r) {
				t.Fatalf("the importing signer allows %+v, which the exported history makes slashable\n%s", r, file)
			}
			e = importer(t, file, keys) // the allowed request is recorded: start again from the file
		}
	}
}

// A watermark repair below the newest attestation, with that attestation's source below the repaired epoch and its
// target above it. The epoch watermarks are not written as an attestation of their own: (150, 150) would be
// surrounded by (149, 151), and the file would be slashable (qrysm marks such a key slashable on import). The
// attestation at 151 gives the importer stricter watermarks; the importer then allows a source of 149, which this
// signer refuses below its repaired watermark, and which no signed attestation makes slashable.
func TestRepairBelowTheNewestAttestation(t *testing.T) {
	keys := [][]byte{slashingtest.Key(0)}
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		e := slashing.NewEngine(s)
		must(t, e.RegisterValidators(bg, keys))
		h := &signed{blocks: map[uint64]uint64{}}
		for _, r := range []request{blockReq(0, 100, 1), attReq(0, 148, 149, 1), attReq(0, 149, 151, 1)} {
			if d := decide(t, e, r); !d.Allowed {
				t.Fatalf("seeding %+v: %+v", r, d)
			}
			h.add(r)
		}
		if n, err := slashing.RepairLowWatermarks(bg, s, 100, 150); err != nil || n != 1 {
			t.Fatalf("repair: %d, %v", n, err)
		}
		var buf bytes.Buffer
		res, err := interchange.Export(bg, s, &buf, interchange.ExportOptions{})
		must(t, err)
		file := buf.String()
		if res.Blocks != 1 || res.Attestations != 1 || res.Watermarks != 0 ||
			!strings.Contains(file, `{"source_epoch": "149", "target_epoch": "151", "signing_root": "`) {
			t.Fatalf("export result %+v:\n%s", res, file)
		}
		checkExport(t, file)

		// Every attestation the history makes slashable has a target from 149 up; the grid covers 140 to 159.
		var all []request
		for target := uint64(140); target < 160; target++ {
			for source := range target + 1 {
				all = append(all, attReq(0, source, target, 2))
			}
		}
		for slot := range uint64(110) {
			all = append(all, blockReq(0, slot, 2))
		}
		probe(t, file, keys, h, all)
		for _, r := range []request{attReq(0, 148, 152, 2), attReq(0, 150, 151, 2), attReq(0, 150, 150, 2),
			blockReq(0, 100, 2)} {
			if d := decide(t, importer(t, file, keys), r); d.Allowed {
				t.Fatalf("the importing signer allows %+v", r)
			}
		}
		for _, r := range []request{attReq(0, 149, 152, 2), attReq(0, 151, 152, 2), blockReq(0, 101, 2)} {
			if d := decide(t, importer(t, file, keys), r); !d.Allowed {
				t.Fatalf("the importing signer refuses %+v: %s", r, d.Reason)
			}
		}
	})
}

// Random histories: sign; repair the watermarks (the key having signed elsewhere below them), prune, both or
// neither, in either order; sign again; then export and import. The export holds no slashable pair, and the
// importing signer allows no block at any slot and no attestation at any epochs that the key's history makes
// slashable. The exporting signer is held to the same.
func TestExportNeverAllowsASlashableSigning(t *testing.T) {
	const (
		maxEpoch = 16
		maxSlot  = 24
	)
	histories := 300
	if testing.Short() {
		histories = 30
	}
	keys := [][]byte{slashingtest.Key(0)}
	var all []request
	for target := range uint64(maxEpoch + 3) {
		for source := range target + 1 {
			all = append(all, attReq(0, source, target, probeRoot(source, target)))
		}
	}
	for slot := range uint64(maxSlot + 3) {
		all = append(all, blockReq(0, slot, probeRoot(slot, 0)))
	}
	for seed := range uint64(histories) {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			t.Parallel()
			rnd := rand.New(rand.NewPCG(seed, 0x5eed))
			s := memstore.New()
			e := slashing.NewEngine(s)
			must(t, e.RegisterValidators(bg, keys))
			h := &signed{blocks: map[uint64]uint64{}}
			var steps []string
			sign := func() {
				for range rnd.IntN(12) {
					r := randomRequest(rnd, maxEpoch, maxSlot)
					d := decide(t, e, r)
					steps = append(steps, fmt.Sprintf("%+v allowed=%v", r, d.Allowed))
					if d.Allowed {
						if h.slashable(r) {
							t.Fatalf("the exporting signer allows %+v, which its history makes slashable\n%s", r,
								strings.Join(steps, "\n"))
						}
						h.add(r)
					}
				}
			}
			sign()
			repair := func() {
				// Mostly at or above the current watermarks, so that the repair is not refused, and half the time
				// strictly between the source and the target of a signed attestation.
				low := dump(t, s)[0].low
				slot, epoch := above(rnd, low.Slot, maxSlot), above(rnd, low.TargetEpoch, maxEpoch)
				var inside []uint64
				for _, a := range h.atts {
					for e := a.source + 1; e < a.target; e++ {
						if low.TargetEpoch == nil || e >= *low.TargetEpoch {
							inside = append(inside, e)
						}
					}
				}
				if len(inside) > 0 && rnd.IntN(2) == 0 {
					epoch = inside[rnd.IntN(len(inside))]
				}
				_, err := slashing.RepairLowWatermarks(bg, s, slot, epoch)
				steps = append(steps, fmt.Sprintf("repair %d %d: %v", slot, epoch, err))
				if err != nil && !errors.Is(err, slashing.ErrLowerWatermark) {
					t.Fatal(err)
				}
				if err == nil {
					signedElsewhere(rnd, h, slot, epoch)
				}
			}
			prune := func() {
				keep := 1 + rnd.Uint64N(4)
				_, err := slashing.Prune(bg, s, slashing.PruneConfig{EpochsToKeep: keep, SlotsPerEpoch: 2})
				must(t, err)
				steps = append(steps, fmt.Sprintf("prune keeping %d epochs", keep))
			}
			// Either, both, or neither, in either order.
			ops := []func(){repair, prune}
			rnd.Shuffle(len(ops), func(i, j int) { ops[i], ops[j] = ops[j], ops[i] })
			for _, op := range ops {
				if rnd.IntN(3) != 0 {
					op()
				}
			}
			sign()

			root := gvr
			var buf bytes.Buffer
			_, err := interchange.Export(bg, s, &buf, interchange.ExportOptions{GenesisValidatorsRoot: &root})
			must(t, err)
			file := buf.String()
			t.Logf("history:\n%s", strings.Join(steps, "\n"))
			checkExport(t, file)
			probe(t, file, keys, h, all)
			for _, r := range []request{attReq(0, maxEpoch+3, maxEpoch+4, 1), blockReq(0, maxSlot+3, 1)} {
				if d := decide(t, importer(t, file, keys), r); !d.Allowed {
					t.Fatalf("the importing signer refuses %+v, above every record: %s", r, d.Reason)
				}
			}
		})
	}
}

// randomRequest returns a block or an attestation with a source a few epochs, now and then many, below its target.
// Its root names the epochs or the slot and one of two variants, so that two requests share a root only when they
// sign the same message.
func randomRequest(rnd *rand.Rand, maxEpoch, maxSlot uint64) request {
	v := rnd.Uint64N(2)
	if rnd.IntN(4) == 0 {
		slot := rnd.Uint64N(maxSlot + 1)
		return blockReq(0, slot, rootFor(slot, 0, v))
	}
	target := rnd.Uint64N(maxEpoch + 1)
	source := target - rnd.Uint64N(min(target, 5)+1)
	if rnd.IntN(6) == 0 {
		source = rnd.Uint64N(target + 1)
	}
	return attReq(0, source, target, rootFor(source, target, v))
}

// signedElsewhere adds to h a few blocks and attestations that the key signed with another signer, at or below a
// repaired watermark (slot, epoch), as long as they leave the history unslashable: what a watermark repair stands
// for.
func signedElsewhere(rnd *rand.Rand, h *signed, slot, epoch uint64) {
	for range rnd.IntN(4) {
		target := rnd.Uint64N(epoch + 1)
		r := attReq(0, rnd.Uint64N(target+1), target, 0)
		r.root = rootFor(r.source, r.target, 2)
		if !h.slashable(r) {
			h.add(r)
		}
		b := blockReq(0, rnd.Uint64N(slot+1), 0)
		b.root = rootFor(b.slot, 0, 2)
		if !h.slashable(b) {
			h.add(b)
		}
	}
}

// above returns a value from the watermark w, or 0 when unset, up to limit; now and then one from 0.
func above(rnd *rand.Rand, w *uint64, limit uint64) uint64 {
	from := uint64(0)
	if w != nil && *w <= limit && rnd.IntN(8) != 0 {
		from = *w
	}
	return from + rnd.Uint64N(limit-from+1)
}

// rootFor is the root of variant v of the message at a, b (source and target epochs, or a slot and 0).
func rootFor(a, b, v uint64) uint64 { return a<<32 | b<<8 | v }

// probeRoot is a root that no history request has.
func probeRoot(a, b uint64) uint64 { return rootFor(a, b, 0xff) }
