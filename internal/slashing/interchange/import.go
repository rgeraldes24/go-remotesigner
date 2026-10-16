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
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/interchange/InterchangeV5Importer.java,
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/interchange/BlockImporter.java,
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/interchange/AttestationImporter.java
// and slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/interchange/OptionalMinValueTracker.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package interchange

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// Batch limits of Import: a transaction covers at most this many validators, and is cut early once it holds this
// many records.
const (
	DefaultBatch      = 64
	DefaultBatchItems = 1 << 16
)

// ImportOptions configure Import.
type ImportOptions struct {
	// Batch is how many validators share one transaction; zero means DefaultBatch.
	Batch int
}

// Counts are one validator's records of one kind.
type Counts struct {
	// Imported records were written.
	Imported int
	// Duplicates were already covered: the store holds the same record, or the file's record has no signing root
	// and the store holds any record at that slot or target epoch.
	Duplicates int
	// Conflicts differ from the record the store holds at that slot or target epoch; they are not written, and the
	// stored record keeps refusing anything else there.
	Conflicts int
}

// ValidatorResult is the outcome of one data element.
type ValidatorResult struct {
	// Index is the element's position in the data array.
	Index int
	// PublicKey is the element's public key; nil when the element has none that is valid.
	PublicKey    []byte
	Blocks       Counts
	Attestations Counts
	// Err is why the element was not imported. The key, when known, is then disabled.
	Err error
}

// ImportResult reports an import, element by element in file order.
type ImportResult struct {
	Validators []ValidatorResult
}

// Failed returns the results whose element was not imported.
func (r ImportResult) Failed() []ValidatorResult {
	var failed []ValidatorResult
	for _, v := range r.Validators {
		if v.Err != nil {
			failed = append(failed, v)
		}
	}
	return failed
}

// Import reads an interchange file from r into s.
//
// The file's genesis validators root must match the store's; a store that has none is pinned to it. Each
// validator's history is then written in one transaction: its key is registered, every block and attestation that
// the store does not already cover is inserted, and the low watermarks are raised, each on its own, to the minimum
// of the newly inserted records when that is higher (the history before the oldest imported record is unknown, so
// nothing below it is signed). Validators are written in batches that share a transaction; when one fails, the batch
// is written again validator by validator, so that only the failing ones are lost.
//
// A validator whose element imports is enabled; one whose element fails is disabled, so that its key cannot sign
// without the history the file meant to give it, and it is reported in the result. Import returns an error when the
// file stops being readable, when the roots differ, or when ctx ends. The elements read before such an error are
// still written, as far as the store allows: each is whole, and history only adds protection. An element that could
// not be written is reported as failed, like any other.
func Import(ctx context.Context, s slashing.Store, r io.Reader, opts ImportOptions) (ImportResult, error) {
	im := &importer{ctx: ctx, s: s, batch: opts.Batch}
	if im.batch <= 0 {
		im.batch = DefaultBatch
	}
	err := Decode(r, im.metadata, im.entry)
	if ferr := im.flush(); err == nil {
		err = ferr
	}
	im.disableFailed()
	return ImportResult{Validators: im.results}, err
}

type importer struct {
	ctx     context.Context
	s       slashing.Store
	batch   int
	results []ValidatorResult
	pending []pendingEntry
	items   int
	failed  []int // results whose key is disabled at the end
}

type pendingEntry struct {
	id     slashing.KeyID
	entry  Entry
	result int // index into results
}

func (im *importer) metadata(m Metadata) error {
	pinned, err := im.s.PinGenesisValidatorsRoot(im.ctx, m.GenesisValidatorsRoot)
	if err != nil {
		return fmt.Errorf("pin the genesis validators root: %w", err)
	}
	if pinned != m.GenesisValidatorsRoot {
		return fmt.Errorf("%w: the file has %#x, the store %#x", slashing.ErrGenesisValidatorsRootMismatch,
			m.GenesisValidatorsRoot[:], pinned[:])
	}
	return nil
}

func (im *importer) entry(index int, e Entry, eerr *EntryError) error {
	if err := im.ctx.Err(); err != nil {
		return err
	}
	if eerr != nil {
		im.results = append(im.results, ValidatorResult{Index: index, PublicKey: eerr.PublicKey, Err: eerr.Err})
		im.fail(len(im.results) - 1)
		return nil
	}
	id := slashing.KeyIDOf(e.PublicKey)
	for _, p := range im.pending {
		if p.id == id { // a repeated key: write the earlier element first
			if err := im.flush(); err != nil {
				return err
			}
			break
		}
	}
	im.results = append(im.results, ValidatorResult{Index: index, PublicKey: e.PublicKey})
	im.pending = append(im.pending, pendingEntry{id: id, entry: e, result: len(im.results) - 1})
	im.items += len(e.Blocks) + len(e.Attestations)
	if len(im.pending) >= im.batch || im.items >= DefaultBatchItems {
		return im.flush()
	}
	return nil
}

// flush writes the pending validators in one transaction, or one by one when that fails. When it returns an error,
// the pending validators it did not write are reported as failed.
func (im *importer) flush() error {
	pending := im.pending
	im.pending, im.items = nil, 0
	if len(pending) == 0 {
		return nil
	}
	pubkeys := make([][]byte, len(pending))
	for i, p := range pending {
		pubkeys[i] = p.entry.PublicKey
	}
	if err := im.s.RegisterValidators(im.ctx, pubkeys); err != nil {
		err = fmt.Errorf("register validators: %w", err)
		im.abandon(pending, err)
		return err
	}
	if err := im.write(pending); err == nil {
		return nil
	}
	for i, p := range pending {
		if err := im.ctx.Err(); err != nil {
			im.abandon(pending[i:], err)
			return err
		}
		if err := im.write([]pendingEntry{p}); err != nil {
			im.failPending(p, err)
		}
	}
	return nil
}

// abandon reports pending validators that were not written because of err as failed.
func (im *importer) abandon(pending []pendingEntry, err error) {
	for _, p := range pending {
		im.failPending(p, fmt.Errorf("not imported: %w", err))
	}
}

// failPending reports a pending validator as failed with err, and as having written nothing.
func (im *importer) failPending(p pendingEntry, err error) {
	res := &im.results[p.result]
	res.Err, res.Blocks, res.Attestations = err, Counts{}, Counts{}
	im.fail(p.result)
}

// write imports entries in one transaction and records their counts.
func (im *importer) write(entries []pendingEntry) error {
	ids := make([]slashing.KeyID, len(entries))
	for i, p := range entries {
		ids[i] = p.id
	}
	next := 0
	return im.s.UpdateHistory(im.ctx, ids, func(_ slashing.KeyID, tx slashing.HistoryTx) error {
		p := entries[next]
		next++
		res := &im.results[p.result]
		var err error
		if res.Blocks, err = importBlocks(tx, p.entry.Blocks); err != nil {
			return err
		}
		if res.Attestations, err = importAttestations(tx, p.entry.Attestations); err != nil {
			return err
		}
		return tx.SetEnabled(true)
	})
}

// fail marks a failed element's key, when it has one, for disabling.
func (im *importer) fail(result int) {
	if im.results[result].PublicKey != nil {
		im.failed = append(im.failed, result)
	}
}

// disableFailed registers and disables the key of every failed element, after everything else is written, so that
// a key with a failed element stays disabled even when another element for it imported. A failure to disable is
// added to the element's error.
func (im *importer) disableFailed() {
	done := map[slashing.KeyID]bool{}
	for _, i := range im.failed {
		res := &im.results[i]
		id := slashing.KeyIDOf(res.PublicKey)
		if done[id] {
			continue
		}
		done[id] = true
		// The disabling must happen even after ctx has ended.
		ctx := context.WithoutCancel(im.ctx)
		err := im.s.RegisterValidators(ctx, [][]byte{res.PublicKey})
		if err == nil {
			err = im.s.SetValidatorEnabled(ctx, id, false)
		}
		if err != nil {
			res.Err = errors.Join(res.Err, fmt.Errorf("disabling the key also failed: %w", err))
		}
	}
}

// importBlocks inserts the blocks the store does not cover and raises the slot watermark to the lowest inserted
// slot when that is higher.
func importBlocks(tx slashing.HistoryTx, blocks []slashing.SignedBlock) (Counts, error) {
	var (
		c       Counts
		minSlot minTracker
	)
	for _, b := range blocks {
		existing, found, err := tx.BlockAt(b.Slot)
		if err != nil {
			return c, err
		}
		if found {
			c.skip(covers(existing.SigningRoot, b.SigningRoot))
			continue
		}
		if err := tx.InsertBlock(b); err != nil {
			return c, err
		}
		c.Imported++
		minSlot.track(b.Slot)
	}
	if !minSlot.set {
		return c, nil
	}
	low, err := tx.LowWatermark()
	if err != nil {
		return c, err
	}
	if minSlot.above(low.Slot) {
		if err := tx.RaiseSlotLowWatermark(minSlot.v); err != nil {
			return c, err
		}
	}
	return c, nil
}

// importAttestations inserts the attestations the store does not cover and raises each epoch watermark, on its own,
// to the lowest inserted epoch when that is higher. Attestations that surround or are surrounded by recorded ones
// are imported like any other: they only make the history stricter.
func importAttestations(tx slashing.HistoryTx, atts []slashing.SignedAttestation) (Counts, error) {
	var (
		c                    Counts
		minSource, minTarget minTracker
	)
	for _, a := range atts {
		existing, found, err := tx.AttestationAt(a.TargetEpoch)
		if err != nil {
			return c, err
		}
		if found {
			c.skip(covers(existing.SigningRoot, a.SigningRoot))
			continue
		}
		if err := tx.InsertAttestation(a); err != nil {
			return c, err
		}
		c.Imported++
		minSource.track(a.SourceEpoch)
		minTarget.track(a.TargetEpoch)
	}
	if !minSource.set {
		return c, nil
	}
	low, err := tx.LowWatermark()
	if err != nil {
		return c, err
	}
	if !minSource.above(low.SourceEpoch) && !minTarget.above(low.TargetEpoch) {
		return c, nil
	}
	source, target := minSource.v, minTarget.v
	if low.SourceEpoch != nil {
		source, target = max(source, *low.SourceEpoch), max(target, *low.TargetEpoch)
	}
	return c, tx.RaiseEpochLowWatermarks(source, target)
}

// covers reports whether a stored record makes an imported one with the same slot or target redundant: the
// imported record has no root, or the same known root.
func covers(stored, imported *slashing.Root) bool {
	return imported == nil || (stored != nil && *stored == *imported)
}

func (c *Counts) skip(covered bool) {
	if covered {
		c.Duplicates++
	} else {
		c.Conflicts++
	}
}

// minTracker tracks the minimum of the values it has seen.
type minTracker struct {
	v   uint64
	set bool
}

func (m *minTracker) track(v uint64) {
	if !m.set || v < m.v {
		m.v, m.set = v, true
	}
}

// above reports whether the tracked minimum is above the watermark w, or w is unset.
func (m *minTracker) above(w *uint64) bool { return m.set && (w == nil || m.v > *w) }
