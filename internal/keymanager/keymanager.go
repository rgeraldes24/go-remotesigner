// Copyright 2021 ConsenSys AG.
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
// Modified by The go-remotesigner Authors, 2026: translated from Java to Go and adapted for QRL.
// Derived from Web3Signer
// core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/keymanager/imports/ImportKeystoresHandler.java,
// core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/keymanager/delete/DeleteKeystoresProcessor.java,
// core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/keymanager/list/ListKeystoresHandler.java,
// signing/src/main/java/tech/pegasys/web3signer/signing/DefaultValidatorManager.java and
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/DbValidatorManager.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

// Package keymanager lists, imports and deletes validator keys while the
// signer runs: the operations behind the keymanager API
// (/qrl/v1/keystores, docs/operations/keymanager.md).
//
// An import opens each keystore through the Argon2id semaphore, compares
// the public key its seed derives with the one it declares, imports the
// slashing-protection history the request carries for the keys it is about
// to add, writes the key's files into the key-config directory (0600, named
// by the SHA-256 of the key) and only then loads and enables the key. A key
// that fails any step is reported as an error and nothing of it is left in
// the directory, unless its files were there before the import (an earlier
// import wrote them): they stay, and the loads load the key from them.
//
// A delete disables the key in slashing protection first, so that nothing
// signs with it after the history is read, then removes its files and
// evicts it, and returns the history of every key it disabled as one
// EIP-3076 interchange. A key that is not loaded is disabled too, so that a
// load that brings it in later (the startup load still running, or a
// source that failed to load) cannot make it sign.
//
// Both run beside the loads of the key-config directory: the provider's
// change generations (provider.ApplySince) keep a running load from undoing
// either. Imports and deletes are serialised with each other.
package keymanager

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystore/qrlv1"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystores"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/source"
	"github.com/rgeraldes24/go-remotesigner/internal/signer/provider"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/interchange"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/memstore"
)

// MaxKeystores is the largest number of keystores one import takes.
const MaxKeystores = 64

// Status is the outcome of one key in an import or a delete.
type Status string

// Import and delete outcomes, as the keymanager API reports them.
const (
	Imported  Status = "imported"
	Duplicate Status = "duplicate"
	Error     Status = "error"
	Deleted   Status = "deleted"
	NotActive Status = "not_active"
	NotFound  Status = "not_found"
)

// Result is the outcome of one key. Message says why for an error; it never
// holds key material, passwords or file paths.
type Result struct {
	Status  Status
	Message string
	// log replaces Message in the log when Message repeats request data
	// (an error of the request's interchange): bodies are never logged.
	log string
}

// Key is one loaded key, as the list reports it.
type Key struct {
	PublicKey *mldsa87.PublicKey
	// DerivationPath is the path the key's keystore records; empty for
	// none.
	DerivationPath string
	// ReadOnly: the key was not imported through the keymanager, so it
	// cannot be deleted through it.
	ReadOnly bool
}

// Errors of a request as a whole.
var (
	// ErrRequest: the request is malformed (more than MaxKeystores, or as
	// many passwords as keystores missing).
	ErrRequest = errors.New("keymanager: malformed request")
	// ErrInterchange: the request's slashing-protection history cannot be
	// read, or is for another network. Nothing was imported. The error's
	// message names the kind of refusal only, never a value of the file.
	ErrInterchange = errors.New("keymanager: slashing_protection refused")
	// ErrStore: the slashing-protection store could not be read to check
	// the request's history. Nothing was imported.
	ErrStore = errors.New("keymanager: the slashing-protection store could not be read")
)

// refusal is an ErrInterchange that keeps its cause for errors.Is, but
// whose message names only the kind of refusal: the interchange decoder's
// errors quote the file's field names and values, which are request data
// and never reach the log.
type refusal struct{ cause error }

func (r refusal) Error() string {
	kind := "the file is not an EIP-3076 interchange this signer reads"
	switch {
	case errors.Is(r.cause, slashing.ErrGenesisValidatorsRootMismatch):
		kind = "the file is for another genesis validators root"
	case errors.Is(r.cause, interchange.ErrVersion):
		kind = "unsupported interchange_format_version"
	}
	return ErrInterchange.Error() + ": " + kind
}

func (r refusal) Unwrap() []error { return []error{ErrInterchange, r.cause} }

// loggable returns err for the log: an error that describes the request's
// interchange becomes its kind alone.
func loggable(err error) error {
	if errors.Is(err, interchange.ErrFormat) || errors.Is(err, interchange.ErrVersion) ||
		errors.Is(err, slashing.ErrGenesisValidatorsRootMismatch) {
		return refusal{cause: err}
	}
	return err
}

// maxDetail bounds the part of a result's message that repeats an error of
// the request's interchange.
const maxDetail = 160

// detail renders an error of the request's interchange for a result's
// message, which goes back to the caller and never to the log: printable
// ASCII, at most maxDetail bytes, since the error may quote field names of
// any length from the file.
func detail(err error) string {
	s := err.Error()
	b := make([]byte, 0, min(len(s), maxDetail)+len("…"))
	for i := 0; i < len(s) && i < maxDetail; i++ {
		c := s[i]
		if c < 0x20 || c >= 0x7f {
			c = '?'
		}
		b = append(b, c)
	}
	if len(s) > maxDetail {
		b = append(b, "…"...)
	}
	return string(b)
}

// Config configures a Manager.
type Config struct {
	// Dir is the key-config directory (--key-config-path), which the
	// startup load and every reload read; imported keys are written there.
	Dir string
	// Keys is the loaded key set.
	Keys *provider.Provider
	// Engine registers loaded keys in slashing protection.
	Engine *slashing.Engine
	// Store is the slashing-protection store.
	Store slashing.Store
	// History imports and exports slashing-protection history; without it
	// (slashing protection disabled) a request's history is ignored and a
	// delete exports none.
	History bool
	// GenesisValidatorsRoot is the network's root, when known; it is
	// written into an export from a store that has none pinned yet.
	GenesisValidatorsRoot func() (slashing.Root, bool)
	// Decrypt opens a keystore; the signer's runs through the Argon2id
	// semaphore.
	Decrypt keystores.DecryptFunc
	// Workers is the number of keystores opened at once.
	Workers int
	// Changed is called after an import or a delete changed the key set.
	Changed func()
	Log     logrus.FieldLogger
}

// Manager runs the keymanager's operations. It is safe for concurrent use.
type Manager struct {
	cfg Config
	mu  sync.Mutex // serialises imports and deletes after their keystores are open

	// afterWrite, in tests, runs between writing the imported keys' files
	// and loading the keys, where a reload may load them from the files.
	afterWrite func()
}

// New returns a Manager.
func New(cfg Config) *Manager {
	if cfg.Log == nil {
		cfg.Log = logrus.New()
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 1
	}
	return &Manager{cfg: cfg}
}

// List returns the loaded keys, sorted by public key.
func (m *Manager) List() []Key {
	var out []Key
	for e := range m.cfg.Keys.Entries() {
		out = append(out, Key{PublicKey: &e.PK, DerivationPath: e.Meta.DerivationPath, ReadOnly: !m.removable(e)})
	}
	return out
}

// removable reports whether a loaded key can be deleted: it was loaded from
// the key-config file the keymanager names it by, as that file's only key,
// out of a keystore.
func (m *Manager) removable(e *provider.Entry) bool {
	src := filesOf(m.cfg.Dir, &e.PK).source()
	return e.Meta.Keystore && e.Source == src && m.cfg.Keys.SourceLen(src) == 1
}

// ImportRequest is one import: keystores and their passwords, index by
// index, and an optional EIP-3076 interchange.
type ImportRequest struct {
	Keystores [][]byte
	Passwords [][]byte
	// SlashingProtection is the interchange, empty for none.
	SlashingProtection []byte
}

// opened is one keystore of an import, opened.
type opened struct {
	key  *mldsa87.Key // nil when err is set or ownership passed on
	meta provider.Meta
	err  error
}

// Import imports the keystores of req and returns one result per keystore,
// in order: imported (the key was added, or it was loaded but disabled and
// is now enabled), duplicate (the key is loaded and enabled already, or an
// earlier keystore of the request has it and was imported) or error. It
// fails as a whole, before any keystore is opened, with ErrRequest,
// ErrInterchange or ErrStore.
//
// Only the history of the keys about to be added or enabled is imported,
// and their enabled flag is left alone until they are loaded; a key whose
// history fails is disabled and reported as an error. A key is enabled, as
// a key re-imported after a delete or `consensus disable-validator` must
// be, once it is loaded: the import proved that the caller holds it.
func (m *Manager) Import(ctx context.Context, req ImportRequest) ([]Result, error) {
	n := len(req.Keystores)
	if n > MaxKeystores || len(req.Passwords) != n {
		return nil, ErrRequest
	}
	results := make([]Result, n)
	if n == 0 {
		return results, nil
	}
	history := m.cfg.History && len(req.SlashingProtection) > 0
	if history {
		if err := m.checkInterchange(ctx, req.SlashingProtection); err != nil {
			return nil, err
		}
	} else if len(req.SlashingProtection) > 0 {
		m.cfg.Log.Warn("Keymanager import: slashing protection is disabled, so the request's slashing_protection " +
			"is ignored")
	}

	open := make([]opened, n)
	source.Each(ctx, n, m.cfg.Workers, func(i int) {
		open[i] = m.open(ctx, req.Keystores[i], req.Passwords[i])
	}, nil)
	defer func() {
		for _, o := range open {
			if o.key != nil {
				o.key.Zeroize()
			}
		}
	}()

	m.mu.Lock()
	defer m.mu.Unlock()
	// What follows commits; it runs to its end even when the client goes.
	ctx = context.WithoutCancel(ctx)
	first := map[provider.ID]int{} // the keystore each key the import adds or enables comes from
	copyOf := map[int]int{}        // a later keystore of such a key, and its first
	var candidates, reenable []int // keys to add, and loaded keys to enable
	for i := range open {
		o := &open[i]
		if o.err != nil {
			results[i] = Result{Status: Error, Message: o.err.Error()}
			continue
		}
		id := o.key.ID()
		if j, ok := first[id]; ok {
			copyOf[i] = j
			continue
		}
		if _, loaded := m.cfg.Keys.Entry(id); loaded {
			pk := o.key.PublicKey()
			var disabled bool
			if results[i], disabled = m.loadedKey(ctx, &pk); disabled {
				first[id] = i
				reenable = append(reenable, i)
			}
			continue
		}
		first[id] = i
		candidates = append(candidates, i)
	}

	if history && len(candidates)+len(reenable) > 0 {
		failed, err := m.importHistory(ctx, req.SlashingProtection, open, slices.Concat(candidates, reenable))
		if err != nil {
			m.cfg.Log.WithError(loggable(err)).
				Error("Keymanager import: the slashing-protection history could not be imported")
		}
		keep := func(idxs []int, notDone, disabled string) []int {
			kept := idxs[:0]
			for _, i := range idxs {
				pk := open[i].key.PublicKey()
				switch herr, bad := failed[slashing.KeyID(pk.ID())]; {
				case err != nil:
					results[i] = Result{Status: Error, Message: "slashing_protection could not be imported; " + notDone}
				case bad:
					results[i] = Result{Status: Error, Message: "its slashing-protection history could not be imported " +
						"(" + detail(herr) + "); " + disabled,
						log: "its slashing-protection history could not be imported; " + disabled}
				default:
					kept = append(kept, i)
				}
			}
			return kept
		}
		candidates = keep(candidates, "not imported", "the key is disabled and not imported")
		reenable = keep(reenable, "the key stays disabled", "the key stays disabled")
	}
	raced := m.commit(ctx, open, req, candidates, results)
	enable := make([]pending, 0, len(reenable)+len(raced))
	for _, i := range reenable {
		enable = append(enable, pending{i: i, pk: open[i].key.PublicKey()})
	}
	m.enable(ctx, append(enable, raced...), results)
	for i, j := range copyOf {
		if results[j].Status == Imported {
			results[i] = Result{Status: Duplicate}
		} else {
			results[i] = Result{Status: Error, Message: "the same key as keystore " + strconv.Itoa(j) +
				", which was not imported"}
		}
	}
	m.logImport(open, results)
	if m.cfg.Changed != nil {
		m.cfg.Changed()
	}
	return results, nil
}

// open parses one keystore, applies the keystore policy, and decrypts it
// with its password through the semaphore, comparing the derived public key
// with the declared one. The password is used as the password file
// written for it will be read back: without trailing line breaks.
func (m *Manager) open(ctx context.Context, data, password []byte) opened {
	if len(password) > keystores.MaxPasswordFile {
		return opened{err: fmt.Errorf("the password is longer than %d bytes, the largest password file the signer "+
			"reads", keystores.MaxPasswordFile)}
	}
	ks, err := qrlv1.Parse(data)
	if err != nil {
		return opened{err: err}
	}
	if _, ok := ks.PublicKey(); !ok {
		return opened{err: errors.New("the keystore declares no pubkey; the keymanager imports only keystores " +
			"that name their key, so that every file it writes holds the full key")}
	}
	if err := ctx.Err(); err != nil {
		return opened{err: errors.New("not opened: the request ended")}
	}
	pw := qrlv1.NewPassword(qrlv1.TrimPassword(password))
	defer pw.Wipe()
	k, err := m.cfg.Decrypt(ctx, ks, pw)
	if err != nil {
		if ctx.Err() != nil {
			return opened{err: errors.New("not opened: the request ended")}
		}
		return opened{err: err}
	}
	return opened{key: k, meta: provider.Meta{DerivationPath: ks.Path, Keystore: true}}
}

// loadedKey is the result of a keystore whose key is loaded already: a
// duplicate, unless slashing protection holds the key disabled (a delete
// while it was not loaded yet, or `consensus disable-validator`), which
// the import then enables, as it does a key it adds. It reports whether
// the key is disabled.
func (m *Manager) loadedKey(ctx context.Context, pk *mldsa87.PublicKey) (Result, bool) {
	st, err := m.cfg.Store.ValidatorStatus(ctx, slashing.KeyID(pk.ID()))
	if err != nil {
		m.cfg.Log.WithField("key", pk.LogID()).WithError(err).
			Error("Keymanager import: the slashing-protection status of a loaded key could not be read")
		return Result{Status: Error, Message: "the key is loaded, but its slashing-protection status could not be " +
			"read"}, false
	}
	if !st.Registered || st.Enabled {
		return Result{Status: Duplicate}, false
	}
	return Result{}, true
}

// enable enables loaded keys that are disabled, in one transaction, once
// the history the request carries for them is imported, and sets their
// results.
func (m *Manager) enable(ctx context.Context, keys []pending, results []Result) {
	if len(keys) == 0 {
		return
	}
	ids := make([]slashing.KeyID, len(keys))
	for n, p := range keys {
		ids[n] = slashing.KeyID(p.pk.ID())
	}
	err := m.cfg.Store.UpdateHistory(ctx, ids, func(_ slashing.KeyID, tx slashing.HistoryTx) error {
		return tx.SetEnabled(true)
	})
	for _, p := range keys {
		if err != nil {
			m.cfg.Log.WithField("key", p.pk.LogID()).WithError(err).
				Error("Keymanager import: a loaded key could not be enabled in slashing protection")
			results[p.i] = Result{Status: Error, Message: "the key is loaded, but it could not be enabled in slashing " +
				"protection; it stays disabled"}
			continue
		}
		results[p.i] = Result{Status: Imported}
	}
}

// boundRoot returns the root the store is pinned to, else the network's.
func (m *Manager) boundRoot(ctx context.Context) (slashing.Root, bool, error) {
	gvr, ok, err := m.cfg.Store.GenesisValidatorsRoot(ctx)
	if err != nil || ok {
		return gvr, ok, err
	}
	if m.cfg.GenesisValidatorsRoot != nil {
		gvr, ok = m.cfg.GenesisValidatorsRoot()
	}
	return gvr, ok, nil
}

// checkInterchange reads the whole interchange before anything is opened or
// written: it must be EIP-3076 version 5 to its end, for this signer's
// network when that is known. Elements that are not valid entries are left
// to the import, which fails only their keys.
func (m *Manager) checkInterchange(ctx context.Context, data []byte) error {
	gvr, known, err := m.boundRoot(ctx)
	if err != nil {
		return fmt.Errorf("%w: the genesis validators root: %w", ErrStore, err)
	}
	err = interchange.Decode(bytes.NewReader(data), func(md interchange.Metadata) error {
		if known && md.GenesisValidatorsRoot != gvr {
			return fmt.Errorf("%w: the file is for genesis validators root %#x, this signer's network is %#x",
				slashing.ErrGenesisValidatorsRootMismatch, md.GenesisValidatorsRoot[:], gvr[:])
		}
		return nil
	}, func(int, interchange.Entry, *interchange.EntryError) error { return nil })
	if err != nil {
		return refusal{cause: err}
	}
	return nil
}

// importHistory imports the history of the candidate keys only, leaving
// their enabled flag alone, and returns the keys whose history failed (the
// import disabled them). A store that has no genesis validators root yet is
// pinned to the file's.
func (m *Manager) importHistory(ctx context.Context, data []byte, open []opened, candidates []int) (
	map[slashing.KeyID]error, error) {
	ids := make([]slashing.KeyID, len(candidates))
	for n, i := range candidates {
		pk := open[i].key.PublicKey()
		ids[n] = slashing.KeyID(pk.ID())
	}
	res, err := interchange.Import(ctx, m.cfg.Store, bytes.NewReader(data),
		interchange.ImportOptions{Keys: ids, LeaveEnabled: true})
	failed := map[slashing.KeyID]error{}
	for _, v := range res.Failed() {
		if v.PublicKey != nil {
			failed[slashing.KeyIDOf(v.PublicKey)] = v.Err
		}
	}
	return failed, err
}

// commitWorkers bounds the keys whose files are written at once: each
// file is synced before it is renamed, and the syncs of several keys
// overlap.
const commitWorkers = 8

// pending is a key on its way in.
type pending struct {
	i     int // its keystore
	pk    mldsa87.PublicKey
	files keyFiles
	// keep: the key's files were in the directory before the import (an
	// earlier import, not loaded yet: the startup load still running, or
	// its load failed). A failure leaves them, as they were or as the
	// import rewrote them for the same key, and leaves the loads to them.
	keep bool
}

// commit adds the candidate keys: it writes their files, registers them in
// slashing protection in one transaction, loads each from its files and
// enables them all in one transaction, and sets their results. A key that
// fails a step is an error and leaves nothing: its files are removed, it is
// evicted, and its enabled flag is as it was (a key the store did not know
// is registered, enabled, which is how any load would register it, unless
// the history step registered it disabled). A key whose files were in the
// directory before keeps them instead, and stays as the loads make it. It returns the keys that a
// load brought in from another source meanwhile and that are disabled, for
// the caller to enable.
func (m *Manager) commit(ctx context.Context, open []opened, req ImportRequest, candidates []int,
	results []Result) (raced []pending) {
	keys := make([]pending, len(candidates))
	for n, i := range candidates {
		pk := open[i].key.PublicKey()
		files := filesOf(m.cfg.Dir, &pk)
		keys[n] = pending{i: i, pk: pk, files: files, keep: files.exists()}
	}
	fail := func(p pending, msg string, err error) {
		log := m.cfg.Log.WithField("key", p.pk.LogID())
		log.WithError(err).Error("Keymanager import: " + msg)
		if !p.keep {
			if _, rerr := p.files.remove(); rerr != nil {
				log.WithError(rerr).Error("Keymanager import: the files of a key that was not imported could not be removed")
			}
			// Mark the source changed, so that a load that read the files
			// meanwhile drops what it read.
			_, _ = m.cfg.Keys.Remove(p.files.source())
		}
		if k := open[p.i].key; k != nil {
			k.Zeroize()
			open[p.i].key = nil
		}
		results[p.i] = Result{Status: Error, Message: msg}
	}

	written := make([]error, len(keys))
	changed := make([]bool, len(keys))
	source.Each(ctx, len(keys), commitWorkers, func(n int) {
		p := keys[n]
		changed[n], written[n] = p.files.write(req.Keystores[p.i], req.Passwords[p.i])
	}, nil)
	var ok []pending
	for n, p := range keys {
		if written[n] != nil {
			// A write that failed after changing a name removed the files.
			p.keep = p.keep && !changed[n]
			fail(p, "the key's files could not be written", written[n])
			continue
		}
		ok = append(ok, p)
	}
	if len(ok) == 0 {
		return nil
	}
	if err := syncDir(m.cfg.Dir); err != nil {
		for _, p := range ok {
			fail(p, "the key's files could not be written", err)
		}
		return nil
	}
	if m.afterWrite != nil {
		m.afterWrite()
	}

	pubkeys := make([][]byte, len(ok))
	for n := range ok {
		pubkeys[n] = ok[n].pk[:]
	}
	if err := m.cfg.Engine.RegisterValidators(ctx, pubkeys); err != nil {
		for _, p := range ok {
			fail(p, "the key could not be registered in slashing protection", err)
		}
		return nil
	}
	var loaded []pending
	for _, p := range ok {
		key := open[p.i].key
		open[p.i].key = nil // Add owns it now
		err := m.cfg.Keys.Add(provider.Batch{Source: p.files.source(), Keys: []*mldsa87.Key{key},
			Meta: []provider.Meta{open[p.i].meta}}, nil)
		if errors.Is(err, provider.ErrDuplicate) {
			if e, has := m.cfg.Keys.Entry(p.pk.ID()); !has || e.Source != p.files.source() {
				// Loaded from another source meanwhile.
				if !p.keep {
					if _, rerr := p.files.remove(); rerr != nil {
						m.cfg.Log.WithField("key", p.pk.LogID()).WithError(rerr).
							Error("Keymanager import: the files of a duplicate key could not be removed")
					}
					_, _ = m.cfg.Keys.Remove(p.files.source())
				}
				var disabled bool
				if results[p.i], disabled = m.loadedKey(ctx, &p.pk); disabled {
					raced = append(raced, p)
				}
				continue
			}
			// A load read the files just written and loaded the key from
			// them: it is the key this import added.
			err = nil
		}
		if err != nil {
			fail(p, "the key could not be loaded", err)
			continue
		}
		loaded = append(loaded, p)
	}
	if len(loaded) == 0 {
		return raced
	}
	ids := make([]slashing.KeyID, len(loaded))
	for n, p := range loaded {
		ids[n] = slashing.KeyID(p.pk.ID())
	}
	err := m.cfg.Store.UpdateHistory(ctx, ids, func(_ slashing.KeyID, tx slashing.HistoryTx) error {
		return tx.SetEnabled(true)
	})
	for _, p := range loaded {
		if err != nil {
			fail(p, "the key could not be enabled in slashing protection", err)
			continue
		}
		results[p.i] = Result{Status: Imported}
	}
	return raced
}

func (m *Manager) logImport(open []opened, results []Result) {
	counts := map[Status]int{}
	for i, r := range results {
		counts[r.Status]++
		if r.Status != Error {
			continue
		}
		reason := r.Message
		if r.log != "" {
			reason = r.log
		}
		f := logrus.Fields{"keystore": i, "reason": reason}
		if k := open[i].key; k != nil {
			pk := k.PublicKey()
			f["key"] = pk.LogID()
		}
		m.cfg.Log.WithFields(f).Warn("Keymanager import: a keystore was not imported")
	}
	m.cfg.Log.WithFields(logrus.Fields{
		"imported": counts[Imported], "duplicate": counts[Duplicate], "error": counts[Error], "keys": m.cfg.Keys.Len(),
	}).Info("Keymanager import")
}

// Delete deletes the keys pubkeys names and returns one result per key, in
// order, and the EIP-3076 interchange of every key it disabled (empty when
// the signer is not bound to a network yet, and so has no history):
//
//   - deleted: the key was loaded from its keymanager files, or was not
//     loaded but had such files; it is disabled, its files are removed and
//     it is evicted;
//   - not_active: the key was not loaded and has history; it is disabled;
//   - not_found: the key was not loaded and has no history; it is
//     disabled, so that it cannot sign if it is loaded later;
//   - error: the key is read-only (loaded from another source) and nothing
//     changed for it, or a step failed, as Message says.
//
// The keys are disabled together, in two store transactions whatever their
// number, before any is evicted.
func (m *Manager) Delete(ctx context.Context, pubkeys []mldsa87.PublicKey) ([]Result, []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ctx = context.WithoutCancel(ctx)
	results := make([]Result, len(pubkeys))
	var todo []int // the keys to disable, in request order
	for i := range pubkeys {
		if r, refused := m.refuseDelete(&pubkeys[i]); refused {
			results[i] = r
			continue
		}
		todo = append(todo, i)
	}
	// Disable first: from here on nothing signs a block or an attestation
	// with the keys, so the history exported below is complete.
	if err := m.disable(ctx, pubkeys, todo); err != nil {
		m.cfg.Log.WithError(err).WithField("keys", len(todo)).Error("Keymanager delete: the keys could not be disabled")
		for _, i := range todo {
			results[i] = Result{Status: Error, Message: "the key could not be disabled in slashing protection; nothing " +
				"was changed"}
		}
		todo = nil
	}
	exported := []slashing.KeyID{}
	inactive := map[int]slashing.KeyID{}
	for _, i := range todo {
		r := m.evict(&pubkeys[i])
		results[i] = r
		id := slashing.KeyID(pubkeys[i].ID())
		exported = append(exported, id)
		if r.Status == NotActive {
			inactive[i] = id
		}
	}
	if m.cfg.Changed != nil {
		m.cfg.Changed()
	}
	export, missing, err := m.export(ctx, exported)
	switch {
	case errors.Is(err, slashing.ErrNoGenesisValidatorsRoot):
		// Not bound to a network: nothing was ever recorded.
		for i := range inactive {
			results[i].Status = NotFound
		}
	case err != nil:
		m.cfg.Log.WithError(err).Error("Keymanager delete: the slashing-protection history could not be exported")
		for i := range results {
			if results[i].Status != Error {
				results[i] = Result{Status: Error, Message: "the key is disabled, but its slashing-protection history " +
					"could not be exported; export it with the export command once the signer is stopped"}
			}
		}
	default:
		for i, id := range inactive {
			if missing[id] {
				results[i].Status = NotFound
			}
		}
	}
	m.logDelete(pubkeys, results)
	return results, export
}

// refuseDelete returns the error result of a key that a delete must leave
// alone: a read-only key, or one whose keystore file at the keymanager's
// name declares another key.
func (m *Manager) refuseDelete(pk *mldsa87.PublicKey) (Result, bool) {
	if e, loaded := m.cfg.Keys.Entry(pk.ID()); loaded && !m.removable(e) {
		return Result{Status: Error, Message: "the key is read-only: it was not imported through the keymanager"}, true
	}
	if err := filesOf(m.cfg.Dir, pk).check(pk); err != nil {
		m.cfg.Log.WithField("key", pk.LogID()).WithError(err).Error("Keymanager delete: the key's files were left in place")
		return Result{Status: Error, Message: "the keystore file named by this key holds another key; nothing was changed"}, true
	}
	return Result{}, false
}

// disable disables the keys of pubkeys at idxs in slashing protection: it
// registers the keys the store does not know, disabled, in one transaction,
// and disables them all in another.
func (m *Manager) disable(ctx context.Context, pubkeys []mldsa87.PublicKey, idxs []int) error {
	if len(idxs) == 0 {
		return nil
	}
	raw := make([][]byte, len(idxs))
	ids := make([]slashing.KeyID, len(idxs))
	for n, i := range idxs {
		raw[n] = pubkeys[i][:]
		ids[n] = slashing.KeyID(pubkeys[i].ID())
	}
	if err := m.cfg.Store.RegisterValidatorsDisabled(ctx, raw); err != nil {
		return err
	}
	return m.cfg.Store.UpdateHistory(ctx, ids, func(_ slashing.KeyID, tx slashing.HistoryTx) error {
		return tx.SetEnabled(false)
	})
}

// evict removes a disabled key's files and evicts it. A key that was
// neither loaded nor had files comes back as NotActive, which the export
// turns into NotFound when the key has no history.
func (m *Manager) evict(pk *mldsa87.PublicKey) Result {
	f := filesOf(m.cfg.Dir, pk)
	log := m.cfg.Log.WithField("key", pk.LogID())
	// The files go before the key is evicted: a load that reads the
	// directory after the eviction marks the source no longer finds them,
	// and one that read it before is ignored for the source.
	removed, ferr := f.remove()
	evicted, err := m.cfg.Keys.Remove(f.source())
	if err != nil {
		log.WithError(err).Error("Keymanager delete: the key could not be evicted")
		return Result{Status: Error, Message: "the key is disabled, but it could not be evicted"}
	}
	if ferr != nil {
		log.WithError(ferr).Error("Keymanager delete: the key's files could not be removed")
		return Result{Status: Error, Message: "the key is disabled and evicted, but its files could not be removed; " +
			"remove them by hand before a reload loads the key again (it stays disabled)"}
	}
	if evicted > 0 || removed {
		return Result{Status: Deleted}
	}
	return Result{Status: NotActive}
}

// export writes the interchange of ids, and reports the keys that have no
// history.
func (m *Manager) export(ctx context.Context, ids []slashing.KeyID) ([]byte, map[slashing.KeyID]bool, error) {
	missing := map[slashing.KeyID]bool{}
	store := m.cfg.Store
	if !m.cfg.History {
		// Slashing protection is disabled, so no history is kept: the
		// export is an empty store's, which names the network when it is
		// known, as Web3Signer's empty-data export does.
		store = memstore.New()
	}
	opts := interchange.ExportOptions{Keys: ids}
	if gvr, ok, err := m.boundRoot(ctx); err == nil && ok {
		opts.GenesisValidatorsRoot = &gvr
	}
	var buf bytes.Buffer
	res, err := interchange.Export(ctx, store, &buf, opts)
	if err != nil {
		return nil, nil, err
	}
	for _, id := range res.Missing {
		missing[id] = true
	}
	return buf.Bytes(), missing, nil
}

func (m *Manager) logDelete(pubkeys []mldsa87.PublicKey, results []Result) {
	counts := map[Status]int{}
	for i, r := range results {
		counts[r.Status]++
		f := logrus.Fields{"key": pubkeys[i].LogID(), "status": r.Status}
		if r.Status == Error {
			m.cfg.Log.WithFields(f).WithField("reason", r.Message).Warn("Keymanager delete: a key was not deleted")
		} else {
			m.cfg.Log.WithFields(f).Info("Keymanager delete: key disabled")
		}
	}
	m.cfg.Log.WithFields(logrus.Fields{
		"deleted": counts[Deleted], "not_active": counts[NotActive], "not_found": counts[NotFound],
		"error": counts[Error], "keys": m.cfg.Keys.Len(),
	}).Info("Keymanager delete")
}
