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
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"

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
	// Keys, when not nil, limits the import to the elements of these validators: the others are skipped, with no
	// result, and nothing is written or disabled for them. An element whose public key is not valid is skipped too,
	// since it cannot belong to one of them.
	Keys []slashing.KeyID
	// LeaveEnabled leaves the enabled flag of the keys whose element imports as it was, instead of enabling them,
	// so that the caller enables a key once everything else it needs is in place (the keymanager, after the key's
	// files are written). A key new to the store then stays registered disabled until the caller enables it. A key
	// whose element fails is still disabled.
	LeaveEnabled bool
	// Enable names keys disabled on purpose (a keymanager DELETE or disable-validator) that a clean element enables
	// too. Without it a clean element enables only a key that an import disabled (new to the store, or disabled by
	// an earlier import's failure); a key disabled on purpose stays disabled and is reported KeptDisabled.
	Enable []slashing.KeyID
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
	// Slashable are imported records that make the history slashable: attestations whose source epoch is after
	// their target epoch, or that surround or are surrounded by another recorded attestation. They are written like
	// any other, since a record only adds protection, but the key has then signed slashable messages. Blocks have
	// none: a second block at a slot is a conflict and is not written.
	Slashable int
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
	// Disabled reports that the key of a failed element was disabled. It is false when the element has no valid
	// key, or when disabling the key failed too (Err then says so).
	Disabled bool
	// KeptDisabled reports that the element imported but its key stays disabled, because it was disabled on
	// purpose (a keymanager DELETE or disable-validator) and ImportOptions.Enable does not name it.
	KeptDisabled bool
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
// A validator whose element imports is enabled by the transaction that writes its history, unless opts.LeaveEnabled,
// when an import disabled it: a key new to the store is registered disabled before that transaction, and a key whose
// element failed in an earlier import was disabled by it. A key disabled on purpose (a keymanager DELETE or
// disable-validator) stays disabled, and is reported KeptDisabled, unless opts.Enable names it. A validator whose
// element fails is disabled, so that its key cannot sign without the history the file meant to give it, and it is
// reported in the result; a key disabled on purpose stays disabled on purpose. Import returns an error when the
// file stops being readable, when the roots differ, or when ctx ends. The elements read before such an error are
// still written, as far as the store allows: each is whole, and history only adds protection. An element that could
// not be written is reported as failed, like any other.
func Import(ctx context.Context, s slashing.Store, r io.Reader, opts ImportOptions) (ImportResult, error) {
	im := &importer{ctx: ctx, s: s, batch: opts.Batch, leaveEnabled: opts.LeaveEnabled,
		enable: make(map[slashing.KeyID]bool, len(opts.Enable))}
	if im.batch <= 0 {
		im.batch = DefaultBatch
	}
	for _, k := range opts.Enable {
		im.enable[k] = true
	}
	if opts.Keys != nil {
		im.want = make(map[slashing.KeyID]bool, len(opts.Keys))
		for _, k := range opts.Keys {
			im.want[k] = true
		}
	}
	err := Decode(r, im.metadata, im.entry)
	if ferr := im.flush(); err == nil {
		err = ferr
	}
	im.disableFailed()
	return ImportResult{Validators: im.results}, err
}

type importer struct {
	ctx          context.Context
	s            slashing.Store
	batch        int
	want         map[slashing.KeyID]bool // nil: every element
	leaveEnabled bool
	enable       map[slashing.KeyID]bool // keys disabled on purpose to enable
	results      []ValidatorResult
	pending      []pendingEntry
	items        int
	failed       []int // results whose key is disabled at the end
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
	if im.want != nil {
		pk := e.PublicKey
		if eerr != nil {
			pk = eerr.PublicKey
		}
		if pk == nil || !im.want[slashing.KeyIDOf(pk)] {
			return nil
		}
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
	// New keys are registered disabled: only the transaction that writes a key's history enables it, so a key never
	// signs without the history the file gives it, even when the import stops between the two commits.
	if err := im.s.RegisterValidatorsDisabled(im.ctx, pubkeys); err != nil {
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

// write imports entries, whose keys differ, in one transaction and records their counts. The function finds its
// entry by id and sets the counts rather than adding to them, so a backend that retries the transaction gets the
// same result.
func (im *importer) write(entries []pendingEntry) error {
	ids := make([]slashing.KeyID, len(entries))
	byID := make(map[slashing.KeyID]pendingEntry, len(entries))
	for i, p := range entries {
		ids[i] = p.id
		byID[p.id] = p
	}
	return im.s.UpdateHistory(im.ctx, ids, func(id slashing.KeyID, tx slashing.HistoryTx) error {
		p := byID[id]
		res := &im.results[p.result]
		var err error
		if res.Blocks, err = importBlocks(tx, p.entry.Blocks); err != nil {
			return err
		}
		if res.Attestations, err = importAttestations(tx, p.entry.Attestations); err != nil {
			return err
		}
		res.KeptDisabled = false
		if im.leaveEnabled {
			return nil
		}
		return im.enableKey(id, tx, res)
	})
}

// enableKey enables a key whose element imported, unless it is disabled on purpose and not named in Enable, when it
// reports it KeptDisabled.
func (im *importer) enableKey(id slashing.KeyID, tx slashing.HistoryTx, res *ValidatorResult) error {
	enabled, err := tx.Enabled()
	if err != nil || enabled {
		return err
	}
	byImport, err := tx.DisabledByImport()
	if err != nil {
		return err
	}
	if !byImport && !im.enable[id] {
		res.KeptDisabled = true
		return nil
	}
	return tx.SetEnabled(true)
}

// fail marks a failed element's key, when it has one, for disabling.
func (im *importer) fail(result int) {
	if im.results[result].PublicKey != nil {
		im.failed = append(im.failed, result)
	}
}

// disableFailed registers and disables the key of every failed element, after everything else is written, so that
// a key with a failed element stays disabled even when another element for it imported. A key new to the store is
// registered disabled, so it is never enabled on the way. The key is disabled by import, so that a later clean
// import enables it again, unless it was disabled on purpose, which it stays. A failure to disable is added to the
// element's error.
func (im *importer) disableFailed() {
	outcome := map[slashing.KeyID]error{}
	for _, i := range im.failed {
		res := &im.results[i]
		id := slashing.KeyIDOf(res.PublicKey)
		err, done := outcome[id]
		if !done {
			// The disabling must happen even after ctx has ended.
			ctx := context.WithoutCancel(im.ctx)
			err = im.s.RegisterValidatorsDisabled(ctx, [][]byte{res.PublicKey})
			if err == nil {
				err = im.s.UpdateHistory(ctx, []slashing.KeyID{id}, func(_ slashing.KeyID, tx slashing.HistoryTx) error {
					return tx.DisableForImport()
				})
			}
			outcome[id] = err
		}
		if err != nil {
			res.Err = errors.Join(res.Err, fmt.Errorf("disabling the key also failed: %w", err))
		} else {
			res.Disabled = true
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
// to the lowest inserted epoch when that is higher. Attestations that surround or are surrounded by recorded ones,
// or whose source is after their target, are imported like any other, since they only make the history stricter,
// and counted as slashable.
func importAttestations(tx slashing.HistoryTx, atts []slashing.SignedAttestation) (Counts, error) {
	var (
		c                    Counts
		minSource, minTarget minTracker
		inserted             []slashing.SignedAttestation
	)
	_, stored, err := tx.LastAttestation() // whether the validator held attestations before
	if err != nil {
		return c, err
	}
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
		inserted = append(inserted, a)
		minSource.track(a.SourceEpoch)
		minTarget.track(a.TargetEpoch)
	}
	if len(inserted) == 0 {
		return c, nil
	}
	if c.Slashable, err = countSlashable(tx, inserted, stored); err != nil {
		return c, err
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

// countSlashable counts the inserted attestations that are slashable within the validator's whole recorded
// history: their source is after their target, or they surround or are surrounded by another recorded attestation.
// The history is the inserted attestations alone when the validator held none before (stored is false); otherwise it
// is read from the store. In target order, an attestation surrounds an earlier one exactly when its source is below
// that one's, and is surrounded by a later one exactly when its source is above that one's, so one pass each way
// finds them all.
func countSlashable(tx slashing.HistoryTx, inserted []slashing.SignedAttestation, stored bool) (int, error) {
	history, isNew := inserted, func(uint64) bool { return true }
	if stored {
		targets := make(map[uint64]bool, len(inserted))
		for _, a := range inserted {
			targets[a.TargetEpoch] = true
		}
		isNew = func(target uint64) bool { return targets[target] }
		history = nil
		for target := uint64(0); ; target++ {
			a, found, err := tx.NearestAttestation(target)
			if err != nil {
				return 0, err
			}
			if !found {
				break
			}
			history = append(history, a)
			if target = a.TargetEpoch; target == math.MaxUint64 {
				break
			}
		}
	} else {
		slices.SortFunc(history, func(a, b slashing.SignedAttestation) int { return cmp.Compare(a.TargetEpoch, b.TargetEpoch) })
	}
	// surrounded[i]: a later attestation (higher target) has a lower source.
	surrounded := make([]bool, len(history))
	minLater := uint64(math.MaxUint64)
	for i := len(history) - 1; i >= 0; i-- {
		surrounded[i] = history[i].SourceEpoch > minLater
		minLater = min(minLater, history[i].SourceEpoch)
	}
	n, maxEarlier := 0, uint64(0)
	for i, a := range history {
		// An earlier attestation (lower target) has a higher source.
		surrounds := i > 0 && a.SourceEpoch < maxEarlier
		maxEarlier = max(maxEarlier, a.SourceEpoch)
		if isNew(a.TargetEpoch) && (a.SourceEpoch > a.TargetEpoch || surrounds || surrounded[i]) {
			n++
		}
	}
	return n, nil
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
