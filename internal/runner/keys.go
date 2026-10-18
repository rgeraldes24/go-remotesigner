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
// core/src/main/java/tech/pegasys/web3signer/core/Eth2Runner.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package runner

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/api/ops"
	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/argon"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keyconfig"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystores"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secretfile"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/source"
	"github.com/rgeraldes24/go-remotesigner/internal/randao"
	"github.com/rgeraldes24/go-remotesigner/internal/signer"
	"github.com/rgeraldes24/go-remotesigner/internal/signer/provider"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// loadState is what the keys-check health checks read besides each
// source kind's error count: whether a load has finished, and whether the
// last one changed nothing.
type loadState struct {
	done   atomic.Bool
	failed atomic.Bool // the last load changed nothing (slashing-protection registration failed)
}

// loadFunc loads one source kind: one batch per source, or an error when
// the kind failed as a whole.
type loadFunc func(ctx context.Context, workers int, unchanged source.Unchanged, report func(done, total int)) (
	[]provider.Batch, error)

// keySource is one kind of key source and its keys-check health check.
type keySource struct {
	what   string // for logs, e.g. "key-config files"
	prefix string // of its sources' names
	check  string // the health check id
	load   loadFunc
	// wholeMsg and oneMsg are logged when the kind fails as a whole and
	// when one of its sources fails.
	wholeMsg, oneMsg string
	// io: its sources are fetched over the network, not decrypted, so it
	// runs secretFetchWorkers at once.
	io   bool
	errs atomic.Int64 // sources that failed in the last load
}

// secretFetchWorkers is how many secrets a bulk loader fetches at once:
// the work is network round trips, not Argon2id.
const secretFetchWorkers = 8

// KeyLoader loads keys from the configured sources into the provider, in
// Web3Signer's order: the key-config files, Azure Key Vault, the
// keystores, AWS Secrets Manager, then GCP Secret Manager. The first load
// is the startup load; every later one is a POST /reload. Both modes use
// it; LoadHooks holds what a mode adds.
type KeyLoader struct {
	// sources are the configured source kinds in load order. The
	// key-config kind is always there, as its health check is; its load is
	// nil without --key-config-path.
	sources []*keySource
	stores  *stores
	sem     *argon.Semaphore
	timeout time.Duration // of a reload; the startup load is unbounded

	keys  *provider.Provider
	hooks LoadHooks
	state *loadState
	log   logrus.FieldLogger

	loaded atomic.Bool // the startup load has finished

	refreshMu sync.Mutex // serialises refresh
}

// LoadHooks are a mode's additions to a key load. Every hook may be nil.
type LoadHooks struct {
	// Register is called with the public keys new to the set before they
	// enter it; when it fails, the load changes nothing.
	Register func(ctx context.Context, pubkeys [][]byte) error
	// Renew reports the loaded keys whose copy just derived replaces them.
	Renew func(provider.ID) bool
	// Applied runs once the new set is in force, after a load or a
	// keymanager change, and returns the number of keys still quarantined.
	// Its calls are serialised.
	Applied func(ctx context.Context) int
}

// KeySources are the key sources of a mode: the global --key-config-path
// and the mode's keystore directory. In execution mode both hold account
// keys, and the secret stores, which hold consensus seeds, are not read.
type KeySources struct {
	Keystores config.Keystores
	Execution bool
}

// NewKeyLoader builds the loader of a mode's key sources.
func NewKeyLoader(cfg *config.Config, src KeySources, sem *argon.Semaphore, keys *provider.Provider, hooks LoadHooks,
	log logrus.FieldLogger) *KeyLoader {
	policy := SecretPolicy(cfg, log)
	l := &KeyLoader{stores: &stores{close: func() {}}, sem: sem, timeout: cfg.ReloadTimeout, keys: keys, hooks: hooks,
		state: &loadState{}, log: log}
	if !src.Execution {
		l.stores = newStores(cfg)
	}
	kc := &keySource{what: "key-config files", prefix: keyconfig.SourcePrefix, check: ops.CheckConfigFilesLoading,
		wholeMsg: "The key-config directory could not be read; every key-config file keeps its previous keys",
		oneMsg:   "A key-config file failed to load; its previous keys stay loaded"}
	if cfg.KeyConfigPath != "" {
		c := &keyconfig.Config{Dir: cfg.KeyConfigPath, Policy: policy, Decrypt: sem.Decrypt,
			MaxFileSize: cfg.KeyConfigFileMaxSize, Execution: src.Execution}
		if !src.Execution {
			c.Secrets = l.stores.fetch
		}
		kc.load = c.Load
	}
	l.sources = append(l.sources, kc)
	l.addBulk(secrets.KindAzure, ops.CheckAzureBulkLoading, "Azure Key Vault secrets")
	if ks := src.Keystores; ks.Path != "" {
		c := &keystores.Config{Dir: ks.Path, PasswordFile: ks.PasswordFile, PasswordsDir: ks.PasswordsPath,
			Policy: policy, Decrypt: sem.Decrypt, Execution: src.Execution}
		l.sources = append(l.sources, &keySource{what: "keystores", prefix: keystores.SourcePrefix,
			check: ops.CheckKeystoresBulkLoading, load: c.Load,
			wholeMsg: "The keystores could not be loaded; every keystore keeps its previous key",
			oneMsg:   "A keystore failed to load; its previous key stays loaded"})
	}
	l.addBulk(secrets.KindAWS, ops.CheckAWSBulkLoading, "AWS Secrets Manager secrets")
	l.addBulk(secrets.KindGCP, ops.CheckGCPBulkLoading, "GCP Secret Manager secrets")
	return l
}

// SecretPolicy is the --strict-file-permissions policy for secret files,
// warning through log when it is off.
func SecretPolicy(cfg *config.Config, log logrus.FieldLogger) secretfile.Policy {
	return secretfile.Policy{Strict: cfg.StrictFilePermissions, Warn: func(path string, mode fs.FileMode) {
		log.WithFields(logrus.Fields{"file": path, "mode": fmt.Sprintf("%04o", mode)}).
			Warn("A secret file is readable by its group or other users; restrict it to its owner (chmod 0600)")
	}}
}

// consensusHooks are the consensus mode's load hooks: new keys are
// registered in slashing protection and quarantined keys are renewed. Once
// the key set has changed, the RANDAO service tracks the loaded keys (and
// forgets the precomputed layers of evicted ones), and the signer drops the
// cached responses of evicted keys and lifts the quarantine of replaced
// ones.
func consensusHooks(keys *provider.Provider, engine *slashing.Engine, sig *signer.Signer, reveals *randao.Service,
	log logrus.FieldLogger) LoadHooks {
	return LoadHooks{
		Register: func(ctx context.Context, pks [][]byte) error {
			if err := engine.RegisterValidators(ctx, pks); err != nil {
				return fmt.Errorf("register keys in slashing protection: %w", err)
			}
			return nil
		},
		Renew: sig.Quarantined,
		Applied: func(ctx context.Context) int {
			var ids []slashing.KeyID
			for pk := range keys.PublicKeys() {
				ids = append(ids, slashing.KeyID(pk.ID()))
			}
			if err := reveals.Track(ctx, ids); err != nil {
				log.WithError(err).Error("Reading the RANDAO frontiers of the loaded keys failed")
			}
			return sig.Release()
		},
	}
}

// addBulk adds the bulk loader of kind when it is enabled.
func (l *KeyLoader) addBulk(kind, check, what string) {
	open, ok := l.stores.bulk[kind]
	if !ok {
		return
	}
	prefix := secrets.Bulk{Kind: kind}.Prefix()
	l.sources = append(l.sources, &keySource{what: what, prefix: prefix, check: check, io: true,
		wholeMsg: "The " + what + " could not be listed; every secret keeps its previous keys",
		oneMsg:   "A secret failed to load; its previous keys stay loaded",
		load: func(ctx context.Context, workers int, _ source.Unchanged, report func(done, total int)) (
			[]provider.Batch, error) {
			store, closeStore, err := open(ctx)
			if err != nil {
				return nil, fmt.Errorf("%s bulk loading: %w", kind, err)
			}
			defer closeStore()
			return secrets.Bulk{Kind: kind, Store: store}.Load(ctx, workers, report)
		}})
}

// Close releases the secret-store clients.
func (l *KeyLoader) Close() { l.stores.close() }

// workers is the number of sources loaded at once. A reload runs while the
// signer serves, so it leaves one CPU to signing.
func (l *KeyLoader) workers() int {
	if !l.loaded.Load() {
		return l.sem.Procs()
	}
	return max(1, min(l.sem.Procs(), runtime.GOMAXPROCS(0)-1))
}

// Load is the reloader's load function. It returns the number of sources
// that failed to load, or an error when nothing changed because the new
// keys could not be registered in slashing protection.
func (l *KeyLoader) Load(ctx context.Context) (int, error) {
	defer l.loaded.Store(true)
	loadCtx := ctx
	if l.loaded.Load() && l.timeout > 0 {
		var cancel context.CancelFunc
		loadCtx, cancel = context.WithTimeout(ctx, l.timeout)
		defer cancel()
	}
	errs, err := l.load(ctx, loadCtx)
	l.state.failed.Store(err != nil)
	l.state.done.Store(true)
	return errs, err
}

func (l *KeyLoader) load(ctx, loadCtx context.Context) (int, error) {
	if !slices.ContainsFunc(l.sources, func(s *keySource) bool { return s.load != nil }) {
		l.log.Warn("No --key-config-path, --keystores-path or secret-store bulk loader: no keys are loaded")
	}
	// Sources the keymanager changes from here on keep what it made of
	// them, whatever this load reads (provider.ApplySince).
	since := l.keys.Generation()
	unchanged := func(src, version string) bool { return l.keys.Unchanged(src, version, l.hooks.Renew) }
	workers := l.workers()
	decrypts, busy := l.sem.Stats()
	var batches []provider.Batch
	counts := make([]int, len(l.sources))
	for i, s := range l.sources {
		if s.load == nil {
			continue
		}
		w := workers
		if s.io {
			w = secretFetchWorkers
		}
		b, err := s.load(loadCtx, w, unchanged, l.progress(s.what))
		batches, counts[i] = l.collect(batches, b, err, s.prefix, s.wholeMsg, s.oneMsg)
	}
	if errors.Is(loadCtx.Err(), context.DeadlineExceeded) {
		l.log.WithField("reload-timeout", l.timeout).
			Warn("The reload ran past --reload-timeout; the sources not loaded by then keep their previous keys")
	}
	// New keys are registered under ctx, not loadCtx: what was loaded before
	// the reload timeout is still applied.
	var register func([][]byte) error
	if l.hooks.Register != nil {
		register = func(pks [][]byte) error { return l.hooks.Register(ctx, pks) }
	}
	d, err := l.keys.ApplySince(since, batches, register, l.hooks.Renew)
	if err != nil {
		return sum(counts), err
	}
	// A source the keymanager changed meanwhile was read half-way through
	// its change; what the load made of it does not count.
	for _, b := range batches {
		if b.Err == nil || !l.keys.ChangedSince(since, b.Source) {
			continue
		}
		for i, s := range l.sources {
			if strings.HasPrefix(b.Source, s.prefix) {
				counts[i]--
				break
			}
		}
	}
	for i, s := range l.sources {
		s.errs.Store(int64(counts[i]))
	}
	total := sum(counts)
	quarantined := l.refresh(ctx)
	n, totalTime := l.sem.Stats()
	l.log.WithFields(logrus.Fields{
		"loaded": l.keys.Len(), "added": d.Added, "removed": d.Removed, "renewed": d.Renewed, "unchanged": d.Unchanged,
		"errors": total, "quarantined": quarantined,
		"decrypts": n - decrypts, "decrypt-time": (totalTime - busy).Round(time.Millisecond),
	}).Info("Keys loaded")
	return total, nil
}

// refresh brings what follows the key set up to date after it changed, by a
// load or through the keymanager, by running the mode's Applied hook. It
// returns the number of keys still quarantined. Calls are serialised, and
// each reads the key set it runs with, so the last one leaves the state of
// the latest key set.
func (l *KeyLoader) refresh(ctx context.Context) int {
	if l.hooks.Applied == nil {
		return 0
	}
	l.refreshMu.Lock()
	defer l.refreshMu.Unlock()
	return l.hooks.Applied(ctx)
}

// collect appends a loader's batches and counts its errors, logging each.
// A loader that failed as a whole counts one error, and every source it
// had keeps its keys: a load error is never a removal.
func (l *KeyLoader) collect(batches, b []provider.Batch, err error, prefix, wholeMsg, oneMsg string) (
	[]provider.Batch, int) {
	if err != nil {
		l.log.WithError(err).Error(wholeMsg)
		for _, src := range l.keys.Sources(prefix) {
			batches = append(batches, provider.Batch{Source: src, Err: err})
		}
		return batches, 1
	}
	errs := 0
	for _, x := range b {
		if x.Err != nil {
			errs++
			l.log.WithError(x.Err).Error(oneMsg)
		}
	}
	return append(batches, b...), errs
}

// progress logs the progress of a long load of what.
func (l *KeyLoader) progress(what string) func(done, total int) {
	start := time.Now()
	return func(done, total int) {
		f := logrus.Fields{"done": done, "total": total}
		if done > 0 {
			elapsed := time.Since(start)
			f["remaining"] = (time.Duration(total-done) * elapsed / time.Duration(done)).Round(time.Second)
		}
		l.log.WithFields(f).Info("Loading " + what)
	}
}

// Checks returns the keys-check health checks of the loader's source
// kinds, as Web3Signer has them: the key-config check always, and each
// other kind's only when it is configured.
func (l *KeyLoader) Checks() []ops.Check {
	checks := make([]ops.Check, 0, len(l.sources))
	for _, s := range l.sources {
		checks = append(checks, ops.Check{ID: s.check, Run: keysCheck(l.state, s, l.keys)})
	}
	return checks
}

// sum adds up a load's error counts.
func sum(counts []int) int {
	n := 0
	for _, c := range counts {
		n += c
	}
	return n
}

// keysCheck is the keys-check health check of a source kind: DOWN until
// the first load, after a load whose registration failed, and while its
// sources fail to load.
func keysCheck(st *loadState, s *keySource, keys *provider.Provider) func(context.Context) (bool, map[string]any) {
	return func(context.Context) (bool, map[string]any) {
		n := s.errs.Load()
		up := st.done.Load() && !st.failed.Load() && n == 0
		return up, map[string]any{"keys-loaded": keys.Count(s.prefix), "error-count": n}
	}
}

// LogKeySources records the Argon2id sizing and the file-permission policy
// at startup.
func LogKeySources(log logrus.FieldLogger, cfg *config.Config, sz argon.Sizing) {
	log.WithFields(logrus.Fields{"procs": sz.Procs, "budget-mib": sz.Budget >> 20, "budget-source": sz.Source}).
		Info("Keystore decryption: " + sz.String())
	if !cfg.StrictFilePermissions {
		log.Warn("--strict-file-permissions=false: secret files that their group or other users can read are loaded " +
			"with a warning")
	}
}
