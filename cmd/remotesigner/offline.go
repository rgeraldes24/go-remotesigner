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

	"github.com/urfave/cli/v2"

	"github.com/rgeraldes24/go-remotesigner/cmd/remotesigner/flags"
	"github.com/rgeraldes24/go-remotesigner/internal/api/consensus"
	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/boltstore"
)

// The offline store commands (the history commands are in interchange.go).
// bbolt allows one process per file, so they fail while a signer has the
// store open; that refusal says what to do.

// errStoreInUse is the startup-failure message for a locked store.
const errStoreInUse = "the slashing-protection store %s is open in a running remotesigner: stop the signer first"

func migrateCommand(stdout io.Writer) *cli.Command {
	return &cli.Command{
		Name:         flags.MigrateCommand,
		Usage:        "upgrade the bbolt slashing-protection store to this release's schema (offline; the signer must be stopped)",
		Flags:        flags.Migrate(),
		OnUsageError: onUsageError,
		Action: func(c *cli.Context) error {
			if c.NArg() > 0 {
				return usageError(fmt.Errorf("unexpected argument %q", c.Args().First()))
			}
			path, err := storeFile(c)
			if err != nil {
				return usageError(err)
			}
			m, err := boltstore.Migrate(path)
			switch {
			case errors.Is(err, boltstore.ErrLocked):
				return cli.Exit(fmt.Sprintf(errStoreInUse+", then run consensus migrate again", path), exitStartup)
			case err != nil:
				return cli.Exit(err.Error(), exitStartup)
			case m.From == m.To:
				_, _ = fmt.Fprintf(stdout, "%s is already at schema version %d; nothing to do\n", path, m.To)
			default:
				_, _ = fmt.Fprintf(stdout, "%s migrated from schema version %d to %d; backup at %s\n", path, m.From, m.To, m.Backup)
			}
			return nil
		},
	}
}

func randaoStateCommand(stdout io.Writer) *cli.Command {
	return &cli.Command{
		Name:            flags.RandaoStateCommand,
		Usage:           "manage stored RANDAO frontiers",
		HideHelpCommand: true,
		OnUsageError:    onUsageError,
		Subcommands: []*cli.Command{{
			Name: flags.ResetCommand,
			Usage: "clear one key's RANDAO frontier, so that its next reveal is a first use (offline with bbolt; " +
				"while the signer runs use DELETE /api/v1/consensus/randao_state/{identifier} with the admin token)",
			Flags:        flags.RandaoStateReset(),
			OnUsageError: onUsageError,
			Action: func(c *cli.Context) error {
				if c.NArg() > 0 {
					return usageError(fmt.Errorf("unexpected argument %q", c.Args().First()))
				}
				if c.String(flags.Key) == "" {
					return usageError(fmt.Errorf("--%s is required", flags.Key))
				}
				id, e := consensus.ParseIdentifier(c.String(flags.Key))
				if e != nil {
					return usageError(fmt.Errorf("--%s: want 0x and the public key or its sha256 in hex", flags.Key))
				}
				path, err := storeFile(c)
				if err != nil {
					return usageError(err)
				}
				if err := resetRandaoState(c.Context, path, slashing.KeyID(id)); err != nil {
					return cli.Exit(err.Error(), exitStartup)
				}
				_, _ = fmt.Fprintf(stdout, "RANDAO state of key %s cleared in %s; its next reveal is a first use\n",
					slashing.KeyID(id), path)
				return nil
			},
		}},
		Action: func(c *cli.Context) error {
			return usageError(fmt.Errorf("want %s %s --%s <id>", flags.RandaoStateCommand, flags.ResetCommand, flags.Key))
		},
	}
}

// storeFile is the bbolt file the offline commands work on: the path of
// --slashing-protection-db-url, else <data-path>/slashing-protection.db.
// The file must exist; only consensus import creates a store.
func storeFile(c *cli.Context) (string, error) {
	path, err := storePath(c)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("no slashing-protection store at %s", path)
	}
	return path, nil
}

// storePath is the bbolt file of storeFile, which need not exist yet.
func storePath(c *cli.Context) (string, error) {
	path, err := dbPath(c)
	if err != nil || path != "" {
		return path, err
	}
	dataPath := c.String(flags.DataPath)
	if dataPath == "" {
		return "", fmt.Errorf("name the store with --%s or --%s", flags.SlashingProtectionDBURL, flags.DataPath)
	}
	return filepath.Join(dataPath, config.SlashingProtectionFile), nil
}

func resetRandaoState(ctx context.Context, path string, id slashing.KeyID) error {
	s, err := boltstore.Open(path, boltstore.Options{})
	if errors.Is(err, boltstore.ErrLocked) {
		return fmt.Errorf(errStoreInUse+", or reset the key online with DELETE /api/v1/consensus/randao_state/{identifier} and the admin token", path)
	}
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	st, err := s.ValidatorStatus(ctx, id)
	if err != nil {
		return err
	}
	if !st.Registered {
		return fmt.Errorf("key %s is not registered in %s", id, path)
	}
	return s.DeleteRandaoState(ctx, id)
}
