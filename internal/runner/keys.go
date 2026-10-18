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
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/api/ops"
	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/argon"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keyconfig"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystores"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secretfile"
	"github.com/rgeraldes24/go-remotesigner/internal/randao"
	"github.com/rgeraldes24/go-remotesigner/internal/signer"
	"github.com/rgeraldes24/go-remotesigner/internal/signer/provider"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// The health checks of the key sources, as Web3Signer names them.
const (
	checkConfigFiles = ops.CheckConfigFilesLoading
	checkKeystores   = ops.CheckKeystoresBulkLoading
)

// loadState is what the keys-check health checks read: the outcome of the
// last load, per source kind.
type loadState struct {
	done      atomic.Bool
	failed    atomic.Bool // the last load changed nothing (slashing-protection registration failed)
	keyConfig atomic.Int64
	keystores atomic.Int64
}

// keyLoader loads keys from the configured sources into the provider: the
// key-config files first, then the keystores, as Web3Signer orders its
// sources. The first load is the startup load; every later one is a
// POST /reload.
type keyLoader struct {
	keyConfig *keyconfig.Config // nil without --key-config-path
	keystores *keystores.Config // nil without --keystores-path
	sem       *argon.Semaphore
	timeout   time.Duration // of a reload; the startup load is unbounded

	keys    *provider.Provider
	engine  *slashing.Engine
	sig     *signer.Signer
	reveals *randao.Service
	state   *loadState
	log     logrus.FieldLogger

	loaded atomic.Bool // the startup load has finished
}

func newKeyLoader(cfg *config.Config, sem *argon.Semaphore, keys *provider.Provider, engine *slashing.Engine,
	sig *signer.Signer, reveals *randao.Service, state *loadState, log logrus.FieldLogger) *keyLoader {
	policy := secretfile.Policy{Strict: cfg.StrictFilePermissions, Warn: func(path string, mode fs.FileMode) {
		log.WithFields(logrus.Fields{"file": path, "mode": fmt.Sprintf("%04o", mode)}).
			Warn("A secret file is readable by its group or other users; restrict it to its owner (chmod 0600)")
	}}
	l := &keyLoader{sem: sem, timeout: cfg.ReloadTimeout, keys: keys, engine: engine, sig: sig, reveals: reveals,
		state: state, log: log}
	if cfg.KeyConfigPath != "" {
		l.keyConfig = &keyconfig.Config{Dir: cfg.KeyConfigPath, Policy: policy, Decrypt: sem.Decrypt,
			MaxFileSize: cfg.KeyConfigFileMaxSize}
	}
	if ks := cfg.Consensus.Keystores; ks.Path != "" {
		l.keystores = &keystores.Config{Dir: ks.Path, PasswordFile: ks.PasswordFile, PasswordsDir: ks.PasswordsPath,
			Policy: policy, Decrypt: sem.Decrypt}
	}
	return l
}

// workers is the number of sources loaded at once. A reload runs while the
// signer serves, so it leaves one CPU to signing.
func (l *keyLoader) workers() int {
	if !l.loaded.Load() {
		return l.sem.Procs()
	}
	return max(1, min(l.sem.Procs(), runtime.GOMAXPROCS(0)-1))
}

// Load is the reloader's load function. It returns the number of sources
// that failed to load, or an error when nothing changed because the new
// keys could not be registered in slashing protection.
func (l *keyLoader) Load(ctx context.Context) (int, error) {
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

func (l *keyLoader) load(ctx, loadCtx context.Context) (int, error) {
	if l.keyConfig == nil && l.keystores == nil {
		l.log.Warn("No --key-config-path or --keystores-path: no keys are loaded")
	}
	unchanged := func(src, version string) bool { return l.keys.Unchanged(src, version, l.sig.Quarantined) }
	workers := l.workers()
	decrypts, busy := l.sem.Stats()
	var batches []provider.Batch
	kcErrs, ksErrs := 0, 0
	if l.keyConfig != nil {
		b, err := l.keyConfig.Load(loadCtx, workers, unchanged, l.progress("key-config files"))
		batches, kcErrs = l.collect(batches, b, err, keyconfig.SourcePrefix,
			"The key-config directory could not be read; every key-config file keeps its previous keys",
			"A key-config file failed to load; its previous keys stay loaded")
	}
	if l.keystores != nil {
		b, err := l.keystores.Load(loadCtx, workers, unchanged, l.progress("keystores"))
		batches, ksErrs = l.collect(batches, b, err, keystores.SourcePrefix,
			"The keystores could not be loaded; every keystore keeps its previous key",
			"A keystore failed to load; its previous key stays loaded")
	}
	if errors.Is(loadCtx.Err(), context.DeadlineExceeded) {
		l.log.WithField("reload-timeout", l.timeout).
			Warn("The reload ran past --reload-timeout; the sources not loaded by then keep their previous keys")
	}
	// New keys are registered under ctx, not loadCtx: what was loaded before
	// the reload timeout is still applied.
	d, err := l.keys.Apply(batches, func(pks [][]byte) error { return l.engine.RegisterValidators(ctx, pks) },
		l.sig.Quarantined)
	if err != nil {
		return kcErrs + ksErrs, fmt.Errorf("register keys in slashing protection: %w", err)
	}
	l.state.keyConfig.Store(int64(kcErrs))
	l.state.keystores.Store(int64(ksErrs))
	var ids []slashing.KeyID
	for pk := range l.keys.PublicKeys() {
		ids = append(ids, slashing.KeyID(pk.ID()))
	}
	if err := l.reveals.Track(ctx, ids); err != nil {
		l.log.WithError(err).Error("Reading the RANDAO frontiers of the loaded keys failed")
	}
	quarantined := l.sig.Release()
	n, total := l.sem.Stats()
	l.log.WithFields(logrus.Fields{
		"loaded": l.keys.Len(), "added": d.Added, "removed": d.Removed, "renewed": d.Renewed, "unchanged": d.Unchanged,
		"errors": kcErrs + ksErrs, "quarantined": quarantined,
		"decrypts": n - decrypts, "decrypt-time": (total - busy).Round(time.Millisecond),
	}).Info("Keys loaded")
	return kcErrs + ksErrs, nil
}

// collect appends a loader's batches and counts its errors, logging each.
// A loader that failed as a whole counts one error, and every source it
// had keeps its keys: a load error is never a removal.
func (l *keyLoader) collect(batches, b []provider.Batch, err error, prefix, wholeMsg, oneMsg string) (
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
func (l *keyLoader) progress(what string) func(done, total int) {
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

// keysCheck is a keys-check health check: DOWN until the first load, after
// a load whose registration failed, and while sources fail to load.
func keysCheck(st *loadState, errs *atomic.Int64, loaded func() int) func(context.Context) (bool, map[string]any) {
	return func(context.Context) (bool, map[string]any) {
		n := errs.Load()
		up := st.done.Load() && !st.failed.Load() && n == 0
		return up, map[string]any{"keys-loaded": loaded(), "error-count": n}
	}
}

// logKeySources records the Argon2id sizing and the file-permission policy
// at startup.
func logKeySources(log logrus.FieldLogger, cfg *config.Config, sz argon.Sizing) {
	log.WithFields(logrus.Fields{"procs": sz.Procs, "budget-mib": sz.Budget >> 20, "budget-source": sz.Source}).
		Info("Keystore decryption: " + sz.String())
	if !cfg.StrictFilePermissions {
		log.Warn("--strict-file-permissions=false: secret files that their group or other users can read are loaded " +
			"with a warning")
	}
}
