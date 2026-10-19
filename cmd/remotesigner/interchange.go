// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/urfave/cli/v2"

	"github.com/rgeraldes24/go-remotesigner/cmd/remotesigner/flags"
	"github.com/rgeraldes24/go-remotesigner/internal/api/consensus"
	"github.com/rgeraldes24/go-remotesigner/internal/network"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/interchange"
)

// The slashing-protection history commands: EIP-3076 import and export, the low-watermark repair and the high
// watermark. With bbolt they run offline, like migrate; with Postgres online, under the signers' advisory locks.

func importCommand(stdout, stderr io.Writer) *cli.Command {
	return &cli.Command{
		Name: flags.ImportCommand,
		Usage: "import an EIP-3076 slashing-protection interchange file (format version 5) into the store, creating " +
			"a bbolt store when it does not exist (offline with bbolt: the signer must be stopped; online with Postgres, " +
			"one validator per transaction)",
		Flags:        flags.Import(),
		OnUsageError: onUsageError,
		Action: func(c *cli.Context) error {
			if err := noArgs(c); err != nil {
				return err
			}
			from := c.String(flags.From)
			if from == "" {
				return usageError(fmt.Errorf("--%s is required", flags.From))
			}
			target, err := targetOf(c, false)
			if err != nil {
				return usageError(err)
			}
			root, err := networkRoot(c)
			if err != nil {
				return usageError(err)
			}
			res, err := importFile(c.Context, target, from, root)
			return finishImport(stdout, stderr, target.String(), res, err)
		},
	}
}

// finishImport reports an import and returns the command's exit. An import that stopped with an error after
// elements were read (a store write that failed, for example) still reports them, so that the operator sees which
// keys were disabled, and which could not be.
func finishImport(stdout, stderr io.Writer, path string, res interchange.ImportResult, importErr error) error {
	if importErr != nil && len(res.Validators) == 0 {
		return cli.Exit(importErr.Error(), exitStartup)
	}
	failed, enabled := reportImport(stdout, stderr, path, res)
	var msgs []string
	if importErr != nil {
		msgs = append(msgs, fmt.Sprintf("%v; the import stopped after %d element(s): run it again once the cause is "+
			"fixed", importErr, len(res.Validators)))
	}
	if failed > 0 {
		msgs = append(msgs, fmt.Sprintf("%d validator(s) failed to import; their keys stay disabled until an import of "+
			"them succeeds", failed))
	}
	if enabled > 0 {
		msgs = append(msgs, fmt.Sprintf("%d of their keys could not be disabled: do not start the signer with them "+
			"before an import of them succeeds", enabled))
	}
	if len(msgs) > 0 {
		return cli.Exit(strings.Join(msgs, "; "), exitStartup)
	}
	return nil
}

// importFile checks the whole file, then imports it into the store. Into Postgres, each validator is its own
// transaction, so that an import holds a validator's locks only while it writes that validator, and signing
// replicas wait for it no longer; a long history is written in one call, under the store command's long bound
// (commandConfig), and a signing request for that key that waits longer than lock_timeout meanwhile fails.
func importFile(ctx context.Context, target storeTarget, from string, root *slashing.Root) (interchange.ImportResult, error) {
	f, err := os.Open(from)
	if err != nil {
		return interchange.ImportResult{}, err
	}
	defer func() { _ = f.Close() }()
	// A file that cannot be read to its end is refused before anything is written.
	noop := func(int, interchange.Entry, *interchange.EntryError) error { return nil }
	if err := interchange.Decode(f, func(interchange.Metadata) error { return nil }, noop); err != nil {
		return interchange.ImportResult{}, fmt.Errorf("%s: %w; nothing was imported", from, err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return interchange.ImportResult{}, err
	}
	s, err := target.open(ctx, root, "")
	if err != nil {
		return interchange.ImportResult{}, err
	}
	defer func() { _ = s.Close() }()
	var opts interchange.ImportOptions
	if target.postgres() {
		opts.Batch = 1
	}
	res, err := interchange.Import(ctx, s, f, opts)
	if err != nil {
		return res, fmt.Errorf("import %s into %s: %w", from, target, err)
	}
	return res, nil
}

// reportImport prints the import's counts, warnings and failures. It returns how many elements failed, and how
// many of those have a key that could not be disabled.
func reportImport(stdout, stderr io.Writer, path string, res interchange.ImportResult) (failed, enabled int) {
	var blocks, atts interchange.Counts
	for _, v := range res.Validators {
		blocks.Imported += v.Blocks.Imported
		blocks.Duplicates += v.Blocks.Duplicates
		blocks.Conflicts += v.Blocks.Conflicts
		atts.Imported += v.Attestations.Imported
		atts.Duplicates += v.Attestations.Duplicates
		atts.Conflicts += v.Attestations.Conflicts
		if v.Err == nil && v.Blocks.Conflicts+v.Attestations.Conflicts > 0 {
			_, _ = fmt.Fprintf(stderr, "warning: data[%d] (key %s): %d block(s) and %d attestation(s) differ from the "+
				"store's record at the same slot or target epoch and were not imported\n",
				v.Index, slashing.KeyIDOf(v.PublicKey), v.Blocks.Conflicts, v.Attestations.Conflicts)
		}
		if v.Err == nil && v.Attestations.Slashable > 0 {
			_, _ = fmt.Fprintf(stderr, "warning: data[%d] (key %s): %d imported attestation(s) have a source after their "+
				"target, or surround or are surrounded by another recorded attestation: the key's history is already "+
				"slashable\n", v.Index, slashing.KeyIDOf(v.PublicKey), v.Attestations.Slashable)
		}
	}
	failures := res.Failed()
	_, _ = fmt.Fprintf(stdout, "imported %d of %d validator(s) into %s: %d block(s) and %d attestation(s) written; "+
		"%d block(s) and %d attestation(s) already covered; %d block(s) and %d attestation(s) conflicting, not written\n",
		len(res.Validators)-len(failures), len(res.Validators), path, blocks.Imported, atts.Imported,
		blocks.Duplicates, atts.Duplicates, blocks.Conflicts, atts.Conflicts)
	for _, v := range failures {
		switch {
		case v.PublicKey == nil:
			_, _ = fmt.Fprintf(stderr, "error: data[%d]: %v (no valid public key)\n", v.Index, v.Err)
		case v.Disabled:
			_, _ = fmt.Fprintf(stderr, "error: data[%d] (key %s): %v; the key is disabled\n", v.Index,
				slashing.KeyIDOf(v.PublicKey), v.Err)
		default:
			enabled++
			_, _ = fmt.Fprintf(stderr, "error: data[%d] (key %s): %v; the key could not be disabled either\n", v.Index,
				slashing.KeyIDOf(v.PublicKey), v.Err)
		}
	}
	return len(failures), enabled
}

func exportCommand(stdout, stderr io.Writer) *cli.Command {
	return &cli.Command{
		Name: flags.ExportCommand,
		Usage: "export the store's slashing-protection history as an EIP-3076 interchange file (format version 5) " +
			"(offline with bbolt: the signer must be stopped; online with Postgres, from one consistent snapshot)",
		Flags:        flags.Export(),
		OnUsageError: onUsageError,
		Action: func(c *cli.Context) error {
			if err := noArgs(c); err != nil {
				return err
			}
			to := c.String(flags.To)
			if to == "" {
				return usageError(fmt.Errorf("--%s is required", flags.To))
			}
			var keys []slashing.KeyID
			if c.IsSet(flags.Keys) {
				keys = []slashing.KeyID{}
				for _, k := range c.StringSlice(flags.Keys) {
					id, e := consensus.ParseIdentifier(k)
					if e != nil {
						return usageError(fmt.Errorf("--%s: want 0x and a public key or its sha256 in hex", flags.Keys))
					}
					keys = append(keys, slashing.KeyID(id))
				}
			}
			target, err := targetOf(c, true)
			if err != nil {
				return usageError(err)
			}
			root, err := networkRoot(c)
			if err != nil {
				return usageError(err)
			}
			res, err := exportFile(c.Context, target, to, interchange.ExportOptions{Keys: keys, GenesisValidatorsRoot: root})
			if errors.Is(err, slashing.ErrNoGenesisValidatorsRoot) {
				return cli.Exit(fmt.Sprintf("%v (--%s, with --%s for a file network)", err, flags.Network,
					flags.NetworkGenesisGVR), exitStartup)
			}
			if err != nil {
				return cli.Exit(err.Error(), exitStartup)
			}
			for _, k := range res.Missing {
				_, _ = fmt.Fprintf(stderr, "note: the store has no history for key %s\n", k)
			}
			if res.Watermarks > 0 {
				_, _ = fmt.Fprintf(stderr, "note: %d of the records stand for a low watermark raised by watermark-repair "+
					"and have no signing root, so that the importing side refuses everything at and below it\n", res.Watermarks)
			}
			_, _ = fmt.Fprintf(stdout, "exported %d validator(s), %d block(s) and %d attestation(s) from %s to %s\n",
				res.Validators, res.Blocks, res.Attestations, target, to)
			return nil
		},
	}
}

// exportFile writes the export to a temporary file next to to, and renames it over to once it is complete.
func exportFile(ctx context.Context, target storeTarget, to string, opts interchange.ExportOptions) (interchange.ExportResult, error) {
	s, err := target.open(ctx, nil, "")
	if err != nil {
		return interchange.ExportResult{}, err
	}
	defer func() { _ = s.Close() }()
	tmp, err := os.CreateTemp(filepath.Dir(to), "."+filepath.Base(to)+".*")
	if err != nil {
		return interchange.ExportResult{}, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	res, err := interchange.Export(ctx, s, tmp, opts)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return interchange.ExportResult{}, fmt.Errorf("export %s: %w", target, err)
	}
	if err := os.Rename(tmp.Name(), to); err != nil {
		return interchange.ExportResult{}, err
	}
	return res, nil
}

func watermarkRepairCommand(stdout io.Writer) *cli.Command {
	return &cli.Command{
		Name: flags.WatermarkRepairCommand,
		Usage: "raise every validator's low watermarks, so that no block at or below the slot and no attestation with a " +
			"source below the epoch or a target at or below it is signed: the fallback when no history can be imported; " +
			"it never lowers a watermark (offline with bbolt: the signer must be stopped; online with Postgres)",
		Flags:        flags.WatermarkRepair(),
		OnUsageError: onUsageError,
		Action: func(c *cli.Context) error {
			if err := noArgs(c); err != nil {
				return err
			}
			if !c.IsSet(flags.Epoch) || !c.IsSet(flags.Slot) {
				return usageError(fmt.Errorf("--%s and --%s are both required", flags.Epoch, flags.Slot))
			}
			epoch, slot := c.Uint64(flags.Epoch), c.Uint64(flags.Slot)
			target, err := targetOf(c, true)
			if err != nil {
				return usageError(err)
			}
			s, err := target.open(c.Context, nil, "")
			if err != nil {
				return cli.Exit(err.Error(), exitStartup)
			}
			defer func() { _ = s.Close() }()
			n, err := slashing.RepairLowWatermarks(c.Context, s, slot, epoch)
			if err != nil {
				return cli.Exit(fmt.Sprintf("watermark-repair refused: %v", err), exitStartup)
			}
			_, _ = fmt.Fprintf(stdout, "raised the low watermarks of %d validator(s) in %s to slot %d and epoch %d\n",
				n, target, slot, epoch)
			return nil
		},
	}
}

func setHighWatermarkCommand(stdout io.Writer) *cli.Command {
	return &cli.Command{
		Name: flags.SetHighWatermarkCommand,
		Usage: "set the global high watermark, a fence at or beyond which nothing is signed, or remove it with " +
			"--remove (offline with bbolt: the signer must be stopped; online with Postgres, where it waits for every " +
			"check-and-record that read the old one)",
		Flags:        flags.SetHighWatermark(),
		OnUsageError: onUsageError,
		Action: func(c *cli.Context) error {
			if err := noArgs(c); err != nil {
				return err
			}
			var h slashing.HighWatermark
			switch remove, epoch, slot := c.Bool(flags.Remove), c.IsSet(flags.Epoch), c.IsSet(flags.Slot); {
			case remove && (epoch || slot):
				return usageError(fmt.Errorf("--%s takes no --%s or --%s", flags.Remove, flags.Epoch, flags.Slot))
			case !remove && (!epoch || !slot):
				return usageError(fmt.Errorf("--%s and --%s are both required (or --%s)", flags.Epoch, flags.Slot, flags.Remove))
			case !remove:
				e, s := c.Uint64(flags.Epoch), c.Uint64(flags.Slot)
				h = slashing.HighWatermark{Epoch: &e, Slot: &s}
			}
			target, err := targetOf(c, true)
			if err != nil {
				return usageError(err)
			}
			// A store not yet bound to a network is bound to the one --network names, as at startup.
			root, err := networkRoot(c)
			if err != nil {
				return usageError(err)
			}
			s, err := target.open(c.Context, root, "")
			if err != nil {
				return cli.Exit(err.Error(), exitStartup)
			}
			defer func() { _ = s.Close() }()
			switch err := s.SetHighWatermark(c.Context, h); {
			case errors.Is(err, slashing.ErrNoGenesisValidatorsRoot):
				return cli.Exit(fmt.Sprintf("set-high-watermark refused: the store is not bound to a network yet (no "+
					"genesis validators root); import its history, start the signer once, or name the network with "+
					"--%s (and --%s for a file network)", flags.Network, flags.NetworkGenesisGVR), exitStartup)
			case errors.Is(err, slashing.ErrWatermarkConflict):
				return cli.Exit("set-high-watermark refused: the high watermark must be above every validator's "+
					"low watermark (slot above every low-watermark slot, epoch above every low-watermark epoch)", exitStartup)
			case err != nil:
				return cli.Exit(err.Error(), exitStartup)
			}
			if h.IsSet() {
				_, _ = fmt.Fprintf(stdout, "high watermark of %s set to epoch %d and slot %d\n", target, *h.Epoch, *h.Slot)
			} else {
				_, _ = fmt.Fprintf(stdout, "high watermark of %s removed\n", target)
			}
			return nil
		},
	}
}

// networkRoot returns the genesis validators root that --network and its sources give, or nil when no network is
// named or it does not give a root.
func networkRoot(c *cli.Context) (*slashing.Root, error) {
	src := network.Sources{Network: c.String(flags.Network), GenesisStateFile: c.String(flags.NetworkGenesisState)}
	if src.Network == "" {
		return nil, nil
	}
	if s := c.String(flags.NetworkGenesisGVR); s != "" {
		r, err := parseRoot(s)
		if err != nil {
			return nil, fmt.Errorf("--%s: %w", flags.NetworkGenesisGVR, err)
		}
		src.GenesisValidatorsRoot = &r
	}
	if c.IsSet(flags.NetworkGenesisTime) {
		t := c.Uint64(flags.NetworkGenesisTime)
		src.GenesisTime = &t
	}
	n, err := network.Load(src)
	if err != nil {
		return nil, err
	}
	if !n.GVRKnown() {
		return nil, nil
	}
	r := slashing.Root(n.GenesisValidatorsRoot)
	return &r, nil
}

func noArgs(c *cli.Context) error {
	if c.NArg() > 0 {
		return usageError(fmt.Errorf("unexpected argument %q", c.Args().First()))
	}
	return nil
}
