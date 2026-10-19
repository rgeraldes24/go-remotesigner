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
// Modified by The go-remotesigner Authors, 2026: translated from Java to Go; the database health check runs for the
// Postgres store, while the bbolt store is checked on each request.
// Derived from Web3Signer
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/DbHealthCheck.java and
// core/src/main/java/tech/pegasys/web3signer/core/Eth2Runner.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package runner

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/api/consensus"
	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/policy"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secretfile"
	"github.com/rgeraldes24/go-remotesigner/internal/network"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/boltstore"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/memstore"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/pgstore"
)

// storeSet is the slashing-protection store of a run and what goes with it.
type storeSet struct {
	store slashing.Store
	// kind is the capabilities slashing_protection value.
	kind string
	// pruner is the store the pruner uses: the store itself, or for Postgres a one-connection pool of its own.
	pruner slashing.Store
	// shared is set for a database that replicas share (Postgres): pruning waits one interval before its first
	// run and paces itself (startPruner).
	shared bool
	// health is the slashing-protection-db-health-check; nil without a store.
	health func(context.Context) bool
	stop   func()
}

// close stops the health check and closes the stores.
func (s *storeSet) close() error {
	if s.stop != nil {
		s.stop()
	}
	var errs []error
	if s.pruner != nil && s.pruner != s.store {
		errs = append(errs, s.pruner.Close())
	}
	return errors.Join(append(errs, s.store.Close())...)
}

// openStore opens the bbolt or Postgres store, or a memory store when protection is disabled (CheckFailSafes has
// allowed that only on loopback). A store pinned to a GVR binds the policy to it.
func openStore(ctx context.Context, cfg *config.Config, n *network.Network, pol *policy.Policy,
	log *logrus.Logger) (*storeSet, error) {
	if !cfg.Consensus.SlashingProtectionEnabled {
		log.Error("SLASHING PROTECTION IS DISABLED: blocks and attestations are signed without any slashing check. " +
			"This is allowed only because every listener is loopback.")
		log.Warn("RANDAO frontiers are kept in memory only: after a restart every key's next reveal is a first use " +
			"(set --randao-protection-required to refuse this)")
		return &storeSet{store: memstore.New(), kind: consensus.ProtectionDisabled}, nil
	}
	onPin := func(gvr slashing.Root) {
		if err := pol.PinGenesisValidatorsRoot(gvr); err != nil {
			log.WithError(err).Error("The store pinned a genesis validators root the policy refused")
		}
	}
	var gvr *slashing.Root
	if n.GVRKnown() {
		r := slashing.Root(n.GenesisValidatorsRoot)
		gvr = &r
	}
	var (
		set *storeSet
		err error
	)
	if cfg.Consensus.Postgres.URL != "" {
		set, err = openPostgres(ctx, cfg, gvr, onPin, log)
	} else {
		set, err = openBolt(cfg, gvr, onPin, log)
	}
	if err != nil {
		return nil, err
	}
	pinned, ok, err := set.store.GenesisValidatorsRoot(ctx)
	if err == nil && ok && !n.GVRKnown() {
		err = pol.PinGenesisValidatorsRoot(pinned)
		log.WithField("genesis-validators-root", hexRoot(pinned)).Info("Genesis validators root pinned by the store")
	}
	if err != nil {
		_ = set.close()
		return nil, err
	}
	return set, nil
}

func openBolt(cfg *config.Config, gvr *slashing.Root, onPin func(slashing.Root), log *logrus.Logger) (*storeSet, error) {
	path := cfg.SlashingProtectionDB()
	if cfg.Consensus.SlashingProtectionDBMigrate {
		if err := migrateBolt(path, log); err != nil {
			return nil, err
		}
	}
	store, err := boltstore.Open(path, boltstore.Options{GenesisValidatorsRoot: gvr, OnPin: onPin})
	if err != nil {
		return nil, err
	}
	return &storeSet{
		store: store, kind: consensus.ProtectionBolt, pruner: store,
		// The bbolt store is local: it is read on each request.
		health: func(ctx context.Context) bool {
			_, err := store.SchemaVersion(ctx)
			return err == nil
		},
	}, nil
}

// migrateBolt upgrades an existing store file before it is opened (--slashing-protection-db-migrate); a missing
// file is created current by Open.
func migrateBolt(path string, log *logrus.Logger) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	m, err := boltstore.Migrate(path)
	if err != nil {
		return fmt.Errorf("refusing to start: --slashing-protection-db-migrate: %w", err)
	}
	if m.From != m.To {
		log.WithFields(logrus.Fields{"from": m.From, "to": m.To, "backup": m.Backup}).
			Warn("Slashing-protection store migrated")
	}
	return nil
}

// postgresConfig resolves the Postgres store's connection settings, reading the password file under the secret-file
// policy.
func postgresConfig(cfg *config.Config, log logrus.FieldLogger) (pgstore.Config, error) {
	pg := cfg.Consensus.Postgres
	c := pgstore.Config{URL: pg.URL, User: pg.Username}
	if pg.PasswordFile != "" {
		policy := secretfile.Policy{Strict: cfg.StrictFilePermissions, Warn: func(path string, mode fs.FileMode) {
			log.WithFields(logrus.Fields{"file": path, "mode": fmt.Sprintf("%04o", mode)}).
				Warn("The Postgres password file is readable by group or other users")
		}}
		pw, err := pgstore.ReadPasswordFile(pg.PasswordFile, policy)
		if err != nil {
			return c, fmt.Errorf("refusing to start: --slashing-protection-db-password-file: %w", err)
		}
		c.Password = pw
	}
	return c, nil
}

func openPostgres(ctx context.Context, cfg *config.Config, gvr *slashing.Root, onPin func(slashing.Root),
	log *logrus.Logger) (*storeSet, error) {
	pc, err := postgresConfig(cfg, log)
	if err != nil {
		return nil, err
	}
	if cfg.Consensus.SlashingProtectionDBMigrate {
		m, err := pgstore.Migrate(ctx, pc)
		if err != nil {
			return nil, fmt.Errorf("refusing to start: --slashing-protection-db-migrate: %w", err)
		}
		if m.From != m.To {
			log.WithFields(logrus.Fields{"database": pc.String(), "from": m.From, "to": m.To}).
				Warn("Slashing-protection database migrated")
		}
	}
	pc.GenesisValidatorsRoot, pc.OnPin = gvr, onPin
	store, err := pgstore.Open(ctx, pc)
	if err != nil {
		return nil, fmt.Errorf("refusing to start: %w", err)
	}
	pruner, err := pgstore.Open(ctx, pruningConfig(pc))
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("refusing to start: %w", err)
	}
	h := startDBHealth(store.Ping, cfg.Consensus.Postgres.HealthCheckTimeout, cfg.Consensus.Postgres.HealthCheckInterval, log)
	log.WithFields(logrus.Fields{
		"database": store.Name(), "max-connections": pgstore.DefaultMaxConns, "call-timeout": pgstore.DefaultTimeout,
		"health-check-interval": cfg.Consensus.Postgres.HealthCheckInterval,
	}).Info("Slashing protection uses the Postgres store")
	return &storeSet{store: store, kind: consensus.ProtectionPostgres, pruner: pruner, shared: true, health: h.up,
		stop: h.close}, nil
}

// pruningConfig is the configuration of the pruner's store: a pool of one connection, so that pruning never takes a
// connection signing needs, and no root to pin, which the signing store has pinned or checked.
func pruningConfig(pc pgstore.Config) pgstore.Config {
	pc.GenesisValidatorsRoot, pc.OnPin, pc.MaxConns, pc.MinConns = nil, nil, 1, 0
	return pc
}

// dbHealth is Web3Signer's database health check: a query bounded by the timeout alone, run at startup and then
// every interval in the background; the health check reports the last result.
type dbHealth struct {
	ok   atomic.Bool
	quit chan struct{}
	done sync.WaitGroup
}

// startDBHealth starts the health check, which runs ping bounded by timeout.
func startDBHealth(ping func(context.Context) error, timeout, interval time.Duration, log logrus.FieldLogger) *dbHealth {
	h := &dbHealth{quit: make(chan struct{})}
	h.ok.Store(true)
	check := func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		err := ping(ctx)
		if up := err == nil; h.ok.Swap(up) != up {
			if up {
				log.Info("The slashing-protection database is reachable again")
			} else {
				log.WithError(err).Error("The slashing-protection database health check failed")
			}
		}
	}
	h.done.Go(func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			check()
			select {
			case <-h.quit:
				return
			case <-ticker.C:
			}
		}
	})
	return h
}

func (h *dbHealth) up(context.Context) bool { return h.ok.Load() }

func (h *dbHealth) close() {
	close(h.quit)
	h.done.Wait()
}
