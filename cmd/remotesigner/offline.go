// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/urfave/cli/v2"

	"github.com/rgeraldes24/go-remotesigner/cmd/remotesigner/flags"
	"github.com/rgeraldes24/go-remotesigner/internal/api/consensus"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/boltstore"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/pgstore"
)

// The store commands (the history commands are in interchange.go). bbolt
// allows one process per file, so with bbolt they fail while a signer has
// the store open, and that refusal says what to do; a Postgres database they
// use online, under the advisory locks the signers take.

// errStoreInUse is the startup-failure message for a locked store.
const errStoreInUse = "the slashing-protection store %s is open in a running remotesigner: stop the signer first"

func migrateCommand(stdout io.Writer) *cli.Command {
	return &cli.Command{
		Name: flags.MigrateCommand,
		Usage: "upgrade the slashing-protection store to this release's schema: a bbolt file offline (the signer must " +
			"be stopped), after a backup; a Postgres database online, creating the schema in an empty one (needs a role " +
			"that may create tables)",
		Flags:        flags.Migrate(),
		OnUsageError: onUsageError,
		Action: func(c *cli.Context) error {
			if c.NArg() > 0 {
				return usageError(fmt.Errorf("unexpected argument %q", c.Args().First()))
			}
			target, err := targetOf(c, true)
			if err != nil {
				return usageError(err)
			}
			if target.postgres() {
				return migratePostgres(c.Context, stdout, target)
			}
			path := target.path
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

// migratePostgres creates or upgrades the schema of a Postgres database, under the migration lock.
func migratePostgres(ctx context.Context, stdout io.Writer, target storeTarget) error {
	cfg, err := target.postgresConfig()
	if err != nil {
		return cli.Exit(err.Error(), exitStartup)
	}
	m, err := pgstore.Migrate(ctx, cfg)
	switch {
	case err != nil:
		return cli.Exit(err.Error(), exitStartup)
	case m.From == m.To:
		_, _ = fmt.Fprintf(stdout, "%s is already at schema version %d; nothing to do\n", target, m.To)
	case m.From == 0:
		_, _ = fmt.Fprintf(stdout, "%s: slashing-protection schema version %d created\n", target, m.To)
	default:
		_, _ = fmt.Fprintf(stdout, "%s migrated from schema version %d to %d\n", target, m.From, m.To)
	}
	return nil
}

func randaoStateCommand(stdout io.Writer) *cli.Command {
	return &cli.Command{
		Name:            flags.RandaoStateCommand,
		Usage:           "manage stored RANDAO frontiers",
		HideHelpCommand: true,
		OnUsageError:    onUsageError,
		Subcommands: []*cli.Command{{
			Name: flags.ResetCommand,
			Usage: "clear one key's RANDAO frontier, so that its next reveal is a first use (offline with bbolt, where " +
				"a running signer takes DELETE /api/v1/consensus/randao_state/{identifier} with the admin token instead; " +
				"online with Postgres)",
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
				target, err := targetOf(c, true)
				if err != nil {
					return usageError(err)
				}
				if err := resetRandaoState(c.Context, target, slashing.KeyID(id)); err != nil {
					return cli.Exit(err.Error(), exitStartup)
				}
				_, _ = fmt.Fprintf(stdout, "RANDAO state of key %s cleared in %s; its next reveal is a first use\n",
					slashing.KeyID(id), target)
				return nil
			},
		}},
		Action: func(c *cli.Context) error {
			return usageError(fmt.Errorf("want %s %s --%s <id>", flags.RandaoStateCommand, flags.ResetCommand, flags.Key))
		},
	}
}

func disableValidatorCommand(stdout io.Writer) *cli.Command {
	return &cli.Command{
		Name: flags.DisableValidator,
		Usage: "disable a key in slashing protection: the signer then refuses its blocks, attestations and new RANDAO " +
			"layers with 412 VALIDATOR_DISABLED (offline with bbolt: the signer must be stopped; online with Postgres, " +
			"where every replica refuses them from the next request). Reloads never disable a key; removing its files " +
			"only unloads it.",
		Flags:        flags.DisableValidatorFlags(),
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
			target, err := targetOf(c, true)
			if err != nil {
				return usageError(err)
			}
			already, err := disableValidator(c.Context, target, slashing.KeyID(id))
			if err != nil {
				return cli.Exit(err.Error(), exitStartup)
			}
			if already {
				_, _ = fmt.Fprintf(stdout, "key %s is already disabled in %s\n", slashing.KeyID(id), target)
				return nil
			}
			_, _ = fmt.Fprintf(stdout, "key %s disabled in %s: the signer refuses its blocks, attestations and new RANDAO "+
				"layers (412 VALIDATOR_DISABLED)\n", slashing.KeyID(id), target)
			return nil
		},
	}
}

// disableValidator persists enabled=false for a registered key. It reports whether the key was already disabled.
// With Postgres the write waits for the key's open block and attestation transactions in every replica.
func disableValidator(ctx context.Context, target storeTarget, id slashing.KeyID) (bool, error) {
	s, err := target.open(ctx, nil, ", then run consensus disable-validator again")
	if err != nil {
		return false, err
	}
	defer func() { _ = s.Close() }()
	st, err := s.ValidatorStatus(ctx, id)
	if err != nil {
		return false, err
	}
	if !st.Registered {
		return false, fmt.Errorf("key %s is not registered in %s", id, target)
	}
	if !st.Enabled {
		return true, nil
	}
	return false, s.SetValidatorEnabled(ctx, id, false)
}

func resetRandaoState(ctx context.Context, target storeTarget, id slashing.KeyID) error {
	s, err := target.open(ctx, nil, ", or reset the key online with DELETE /api/v1/consensus/randao_state/{identifier} "+
		"and the admin token")
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	st, err := s.ValidatorStatus(ctx, id)
	if err != nil {
		return err
	}
	if !st.Registered {
		return fmt.Errorf("key %s is not registered in %s", id, target)
	}
	return s.DeleteRandaoState(ctx, id)
}
