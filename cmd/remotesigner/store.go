// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/urfave/cli/v2"

	"github.com/rgeraldes24/go-remotesigner/cmd/remotesigner/flags"
	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secretfile"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/boltstore"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/pgstore"
)

// storeTarget is the store a store subcommand works on: the bbolt file, which only one process may open, so the
// commands run while the signer is stopped; or the Postgres database, which they use online, under the same
// advisory locks as the signers.
type storeTarget struct {
	// path is the bbolt file; empty for Postgres.
	path string
	// pg is the Postgres store's configuration, without its password, which open reads; nil for bbolt.
	pg           *pgstore.Config
	passwordFile string
	policy       secretfile.Policy
}

// String names the store in messages.
func (s storeTarget) String() string {
	if s.pg != nil {
		return s.pg.String()
	}
	return s.path
}

// postgres reports whether the target is a Postgres database.
func (s storeTarget) postgres() bool { return s.pg != nil }

// targetOf resolves the store flags: --slashing-protection-db-url, on the command or a parent, else the bbolt file
// <data-path>/slashing-protection.db. With bbolt and mustExist, a missing file is refused: only consensus import
// creates a store. Its errors are usage errors.
func targetOf(c *cli.Context, mustExist bool) (storeTarget, error) {
	u, err := dbURL(c)
	if err != nil {
		return storeTarget{}, err
	}
	if u.Postgres != "" {
		policy := secretfile.Policy{Strict: c.Bool(flags.StrictFilePermissions), Warn: func(path string, mode fs.FileMode) {
			_, _ = fmt.Fprintf(c.App.ErrWriter, "warning: %s: mode %04o: readable by group or other users\n", path, mode)
		}}
		return storeTarget{
			pg:           commandConfig(u.Postgres, lineageString(c, flags.SlashingProtectionDBUser)),
			passwordFile: lineageString(c, flags.SlashingProtectionDBPass),
			policy:       policy,
		}, nil
	}
	path := u.Path
	if path == "" {
		dataPath := c.String(flags.DataPath)
		if dataPath == "" {
			return storeTarget{}, fmt.Errorf("name the store with --%s or --%s", flags.SlashingProtectionDBURL, flags.DataPath)
		}
		path = filepath.Join(dataPath, config.SlashingProtectionFile)
	}
	if mustExist {
		if _, err := os.Stat(path); err != nil {
			return storeTarget{}, fmt.Errorf("no slashing-protection store at %s", path)
		}
	}
	return storeTarget{path: path}, nil
}

// commandConfig is a store command's Postgres configuration: a pool of one connection, since a command makes one
// call at a time, and pgstore.CommandTimeout per call, since an online import writes each validator's whole history
// in one call. lock_timeout and statement_timeout bound its waits as they bound the signers'.
func commandConfig(url, user string) *pgstore.Config {
	return &pgstore.Config{URL: url, User: user, MaxConns: 1, MinConns: 0, Timeout: pgstore.CommandTimeout}
}

// lineageString returns a flag's value from the command or the nearest parent that sets it.
func lineageString(c *cli.Context, name string) string {
	for _, x := range c.Lineage() {
		if x.IsSet(name) {
			return x.String(name)
		}
	}
	return ""
}

// postgresConfig is the Postgres configuration with the password read from its file.
func (s storeTarget) postgresConfig() (pgstore.Config, error) {
	cfg := *s.pg
	if s.passwordFile != "" {
		pw, err := pgstore.ReadPasswordFile(s.passwordFile, s.policy)
		if err != nil {
			return cfg, fmt.Errorf("--%s: %w", flags.SlashingProtectionDBPass, err)
		}
		cfg.Password = pw
	}
	return cfg, nil
}

// open opens the store, pinning or checking root when it is given. A bbolt file that a running signer holds is
// refused with retry, the message's ending ("" for none).
func (s storeTarget) open(ctx context.Context, root *slashing.Root, retry string) (slashing.Store, error) {
	if s.pg != nil {
		cfg, err := s.postgresConfig()
		if err != nil {
			return nil, err
		}
		cfg.GenesisValidatorsRoot = root
		return pgstore.Open(ctx, cfg)
	}
	st, err := boltstore.Open(s.path, boltstore.Options{GenesisValidatorsRoot: root})
	if errors.Is(err, boltstore.ErrLocked) {
		return nil, fmt.Errorf(errStoreInUse+"%s", s.path, retry)
	}
	return st, err
}

// dbURL returns --slashing-protection-db-url, set on the command or on any parent, parsed; its zero value when it
// is not set.
func dbURL(c *cli.Context) (config.DBURL, error) {
	for _, x := range c.Lineage() {
		if !x.IsSet(flags.SlashingProtectionDBURL) {
			continue
		}
		u, err := config.ParseDBURL(x.String(flags.SlashingProtectionDBURL))
		if err != nil {
			return config.DBURL{}, fmt.Errorf("--%s: %w", flags.SlashingProtectionDBURL, err)
		}
		return u, nil
	}
	return config.DBURL{}, nil
}
