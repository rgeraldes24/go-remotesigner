// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	fieldparams "github.com/theQRL/qrysm/config/fieldparams"
	"github.com/theQRL/qrysm/consensus-types/primitives"
	qrysmpb "github.com/theQRL/qrysm/proto/qrysm/v1alpha1"
	validatordb "github.com/theQRL/qrysm/validator/db/kv"
	history "github.com/theQRL/qrysm/validator/slashing-protection-history"
	"github.com/theQRL/qrysm/validator/slashing-protection-history/format"
)

// The interchange fixtures: an EIP-3076 export written by qrysm's validator (validator slashing-protection-history
// export) from a validator database with a known history, and the check that a file imports back into qrysm with
// that same history. The signer's tests import the export, and `vectorgen interchange-check` imports the signer's
// re-export into qrysm.

const (
	interchangeExport = "interchange/qrysm-export.json"
	interchangeIndex  = "interchange/index.json"
)

// historyBlock and historyAtt are records saved into qrysm's validator database. A nil root saves an empty
// signing root, which qrysm exports as 32 zero bytes for a block and leaves out for an attestation.
type (
	historyBlock struct {
		slot uint64
		root []byte
	}
	historyAtt struct {
		source, target uint64
		root           []byte
	}
	keyHistory struct {
		key    int
		blocks []historyBlock
		atts   []historyAtt
	}
)

// hroot is the signing root of a history record.
func hroot(label string) []byte { return fill32("interchange:" + label) }

// interchangeHistory covers what a qrysm export can hold: a key with blocks and attestations, keys with only one
// kind, a block without a signing root (exported as zeros), an attestation without one (left out), gaps, and a
// source that jumps. None is slashable, so qrysm imports every key.
var interchangeHistory = []keyHistory{
	{key: 0,
		blocks: []historyBlock{{1000, hroot("b0-1000")}, {1130, hroot("b0-1130")}, {1290, hroot("b0-1290")}},
		atts:   []historyAtt{{7, 8, hroot("a0-8")}, {8, 9, hroot("a0-9")}, {9, 10, hroot("a0-10")}, {10, 12, hroot("a0-12")}}},
	{key: 1,
		atts: []historyAtt{{0, 1, hroot("a1-1")}, {1, 2, nil}, {2, 4, hroot("a1-4")}}},
	{key: 2,
		blocks: []historyBlock{{2000, hroot("b2-2000")}, {2001, nil}}},
	{key: 3,
		blocks: []historyBlock{{64, hroot("b3-64")}},
		atts:   []historyAtt{{20, 30, hroot("a3-30")}, {30, 31, hroot("a3-31")}}},
}

// genInterchange writes interchange/qrysm-export.json, in qrysm's native layout, and interchange/index.json.
func genInterchange(g *generator) error {
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "vectorgen-interchange")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	db, err := validatordb.NewKVStore(ctx, dir, &validatordb.Config{})
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	gvr := g.mainnet.gvr
	if err := db.SaveGenesisValidatorsRoot(ctx, gvr[:]); err != nil {
		return err
	}
	var validators []obj
	for _, h := range interchangeHistory {
		pub := g.keys[h.key].pub
		if err := saveHistory(ctx, db, pub, h); err != nil {
			return fmt.Errorf("key %d: %w", h.key, err)
		}
		validators = append(validators, obj{}.
			set("key_index", h.key).
			set("pubkey", hx(pub)).
			set("signed_blocks", len(h.blocks)).
			set("signed_attestations", len(h.atts)))
	}
	out, err := qrysmExport(ctx, db)
	if err != nil {
		return err
	}
	if err := writeFile(g.vectors, interchangeExport, out); err != nil {
		return err
	}
	return writeJSON(g.vectors, interchangeIndex, obj{}.
		set("description", g.description("EIP-3076 interchange vectors. qrysm-export.json is the file qrysm's "+
			"validator writes (validator slashing-protection-history export, ExportStandardProtectionJSON, "+
			"tab-indented) from a validator database holding the history below, on the end-to-end-mainnet network; "+
			"it keeps qrysm's native layout. A block saved without a signing root is exported with 32 zero bytes, an "+
			"attestation without one has no signing_root. vectorgen interchange-check imports a file into a new "+
			"qrysm database and requires qrysm's export of it to equal qrysm-export.json byte for byte.")).
		set("generator", g.info).
		set("file", filepath.Base(interchangeExport)).
		set("preset", "mainnet").
		set("genesis_validators_root", hx(gvr[:])).
		set("validators", validators))
}

func saveHistory(ctx context.Context, db *validatordb.Store, pub []byte, h keyHistory) error {
	var pk [fieldparams.MLDSA87PubkeyLength]byte
	if copy(pk[:], pub) != len(pk) {
		return fmt.Errorf("public key of %d bytes", len(pub))
	}
	for _, b := range h.blocks {
		if err := db.SaveProposalHistoryForSlot(ctx, pk, primitives.Slot(b.slot), b.root); err != nil {
			return err
		}
	}
	if len(h.atts) == 0 {
		return nil
	}
	roots := make([][]byte, len(h.atts))
	atts := make([]*qrysmpb.IndexedAttestation, len(h.atts))
	for i, a := range h.atts {
		roots[i] = a.root
		atts[i] = &qrysmpb.IndexedAttestation{Data: &qrysmpb.AttestationData{
			Source: &qrysmpb.Checkpoint{Epoch: primitives.Epoch(a.source), Root: make([]byte, 32)},
			Target: &qrysmpb.Checkpoint{Epoch: primitives.Epoch(a.target), Root: make([]byte, 32)},
		}}
	}
	return db.SaveAttestationsForPubKey(ctx, pk, roots, atts)
}

// qrysmExport exports db as qrysm's CLI writes the file: MarshalIndent with a tab, plus a final newline.
func qrysmExport(ctx context.Context, db *validatordb.Store) ([]byte, error) {
	var f *format.EIPSlashingProtectionFormat
	err := withoutProgress(func() (err error) {
		f, err = history.ExportStandardProtectionJSON(ctx, db)
		return err
	})
	if err != nil {
		return nil, err
	}
	out, err := json.MarshalIndent(f, "", "\t")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// interchangeCheck imports file into a new qrysm validator database and checks that qrysm takes every key (it
// marks none slashable) and that its export of the database equals the qrysm-export.json fixture under vectors.
func interchangeCheck(ctx context.Context, file, vectors string, stdout io.Writer) error {
	want, err := os.ReadFile(filepath.Join(vectors, filepath.FromSlash(interchangeExport)))
	if err != nil {
		return err
	}
	in, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "vectorgen-interchange-check")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	db, err := validatordb.NewKVStore(ctx, dir, &validatordb.Config{})
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	if err := withoutProgress(func() error { return history.ImportStandardProtectionJSON(ctx, db, bytes.NewReader(in)) }); err != nil {
		return fmt.Errorf("qrysm refuses %s: %w", file, err)
	}
	blacklisted, err := db.EIPImportBlacklistedPublicKeys(ctx)
	if err != nil {
		return err
	}
	if len(blacklisted) > 0 {
		return fmt.Errorf("qrysm marks %d key(s) of %s slashable", len(blacklisted), file)
	}
	got, err := qrysmExport(ctx, db)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("qrysm's export after importing %s differs from %s: %w", file, interchangeExport,
			describeDiff(got, want))
	}
	var f format.EIPSlashingProtectionFormat
	if err := json.Unmarshal(in, &f); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "interchange-check: qrysm imported %d validator(s) from %s with the history of %s\n",
		len(f.Data), file, interchangeExport)
	return nil
}

// describeDiff names the first validator whose history differs.
func describeDiff(got, want []byte) error {
	var g, w format.EIPSlashingProtectionFormat
	if err := errors.Join(json.Unmarshal(got, &g), json.Unmarshal(want, &w)); err != nil {
		return err
	}
	if g.Metadata != w.Metadata {
		return fmt.Errorf("metadata %+v, want %+v", g.Metadata, w.Metadata)
	}
	if len(g.Data) != len(w.Data) {
		return fmt.Errorf("%d validators, want %d", len(g.Data), len(w.Data))
	}
	for i := range g.Data {
		gb, _ := json.Marshal(g.Data[i])
		wb, _ := json.Marshal(w.Data[i])
		if !bytes.Equal(gb, wb) {
			return fmt.Errorf("data[%d] is %.300s…, want %.300s…", i, gb, wb)
		}
	}
	return errors.New("the layout differs")
}

// withoutProgress runs fn with os.Stdout on the null device: qrysm's interchange code draws progress bars on
// os.Stdout, which would bury the tool's own output.
func withoutProgress(fn func() error) error {
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return fn()
	}
	saved := os.Stdout
	os.Stdout = null
	defer func() {
		os.Stdout = saved
		_ = null.Close()
	}()
	return fn()
}
