// Copyright 2022 ConsenSys AG.
// Copyright 2023 ConsenSys AG.
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
// signing/src/main/java/tech/pegasys/web3signer/signing/bulkloading/BlsKeystoreBulkLoader.java and
// signing/src/main/java/tech/pegasys/web3signer/signing/secp256k1/util/JsonFilesUtil.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

// Package keystores bulk-loads the keystores of --keystores-path: every
// non-hidden *.json file directly in the directory, opened with one shared
// password file (--keystores-password-file) or with a password file per
// keystore (--keystores-passwords-path: <stem>.txt for <stem>.json). This
// is the layout the deposit CLI writes and qrysm's validator client uses: a
// directory of keystore-*.json files and one password file.
//
// Each keystore is one source, so a keystore that fails to load keeps the
// key it had while the others load. A keystore whose files are unchanged
// since its key was loaded is not decrypted again. Decryption goes through
// the caller's Decrypt, which bounds the Argon2id runs.
package keystores

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystore/qrlv1"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secretfile"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/source"
	"github.com/rgeraldes24/go-remotesigner/internal/signer/provider"
)

// SourcePrefix starts the source name of every keystore this package loads.
const SourcePrefix = "keystores:"

// MaxPasswordFile bounds a password file.
const MaxPasswordFile = 64 << 10

// ErrNoPasswordFile: a keystore has no <stem>.txt in --keystores-passwords-path.
var ErrNoPasswordFile = errors.New("no password file")

// FileError is the error of one keystore that failed to load.
type FileError struct {
	Path string
	Err  error
}

func (e *FileError) Error() string { return e.Path + ": " + e.Err.Error() }

func (e *FileError) Unwrap() error { return e.Err }

// DecryptFunc decrypts a parsed keystore; the signer's runs through the
// Argon2id semaphore.
type DecryptFunc func(ctx context.Context, ks *qrlv1.Keystore, pw *qrlv1.Password) (*mldsa87.Key, error)

// Config is a keystore source. Exactly one of PasswordFile and PasswordsDir
// is set.
type Config struct {
	Dir          string // --keystores-path
	PasswordFile string // --keystores-password-file
	PasswordsDir string // --keystores-passwords-path
	// Policy is applied to every password file.
	Policy  secretfile.Policy
	Decrypt DecryptFunc
}

// Source is the source name of the keystore at path.
func Source(path string) string { return SourcePrefix + path }

// Path is the keystore path of a source name.
func Path(source string) string { return strings.TrimPrefix(source, SourcePrefix) }

// Files lists the keystore files: the non-hidden entries of dir whose
// extension is .json in any case, sorted. An entry that cannot be stat'ed
// (a dangling symlink, a file being replaced) is listed too, so that it
// fails to load and keeps its previous key; entries that stat as something
// other than a regular file are skipped.
func Files(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("keystores: read --keystores-path: %w", err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") || !strings.EqualFold(filepath.Ext(name), ".json") {
			continue
		}
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && !fi.Mode().IsRegular() {
			continue
		}
		out = append(out, p)
	}
	slices.Sort(out)
	return out, nil
}

// PasswordFileFor is the password file of the keystore at path in a
// passwords directory: the keystore's file name with its extension
// replaced by .txt.
func PasswordFileFor(passwordsDir, path string) string {
	name := filepath.Base(path)
	return filepath.Join(passwordsDir, strings.TrimSuffix(name, filepath.Ext(name))+".txt")
}

// Load loads every keystore, on up to workers goroutines, and returns one
// batch per keystore, in file-name order: Keep when unchanged reports its
// version (a nil unchanged keeps nothing), else its key or the error that
// made it fail. Keystores not reached before ctx ends fail with ctx's
// error.
//
// Load fails as a whole, returning no batches, when the directory cannot be
// listed or the shared password file cannot be read or is refused by the
// policy: the caller then keeps every keystore's previous key. report, when
// not nil, receives the progress of a long load.
func (c Config) Load(ctx context.Context, workers int, unchanged source.Unchanged,
	report func(done, total int)) ([]provider.Batch, error) {
	start := time.Now()
	files, err := Files(c.Dir)
	if err != nil {
		return nil, err
	}
	var (
		shared     *qrlv1.Password
		sharedInfo os.FileInfo
	)
	if c.PasswordFile != "" {
		if sharedInfo, err = os.Stat(c.PasswordFile); err == nil {
			err = c.Policy.Check(c.PasswordFile, sharedInfo)
		}
		if err != nil {
			return nil, fmt.Errorf("keystores: --keystores-password-file: %w", err)
		}
		if len(files) > 0 {
			if shared, err = readPassword(c.PasswordFile, c.Policy); err != nil {
				return nil, fmt.Errorf("keystores: --keystores-password-file: %w", err)
			}
			defer shared.Wipe()
		}
	}
	out := make([]provider.Batch, len(files))
	source.Each(ctx, len(files), workers, func(i int) {
		out[i] = c.load(ctx, start, files[i], shared, sharedInfo, unchanged)
	}, report)
	return out, nil
}

// load loads one keystore.
func (c Config) load(ctx context.Context, start time.Time, path string, shared *qrlv1.Password, sharedInfo os.FileInfo,
	unchanged source.Unchanged) provider.Batch {
	b := provider.Batch{Source: Source(path)}
	fail := func(err error) provider.Batch {
		b.Err = &FileError{Path: path, Err: err}
		return b
	}
	ksInfo, err := os.Stat(path)
	if err != nil {
		return fail(err)
	}
	pwFile, pwInfo := c.PasswordFile, sharedInfo
	if c.PasswordsDir != "" {
		pwFile = PasswordFileFor(c.PasswordsDir, path)
		if pwInfo, err = os.Stat(pwFile); errors.Is(err, os.ErrNotExist) {
			return fail(fmt.Errorf("%w %s in --keystores-passwords-path", ErrNoPasswordFile, filepath.Base(pwFile)))
		}
		if err == nil {
			err = c.Policy.Check(pwFile, pwInfo)
		}
		if err != nil {
			return fail(err)
		}
	}
	b.Version = source.Version(start, []os.FileInfo{ksInfo}, pwInfo)
	if unchanged != nil && unchanged(b.Source, b.Version) {
		b.Keep = true
		return b
	}
	if err := ctx.Err(); err != nil {
		return fail(fmt.Errorf("not loaded: %w", err))
	}
	data, err := secretfile.ReadCapped(path, qrlv1.MaxSize)
	if err != nil {
		return fail(err)
	}
	ks, err := qrlv1.Parse(data)
	if err != nil {
		return fail(err)
	}
	pw := shared
	if pw == nil {
		if pw, err = readPassword(pwFile, c.Policy); err != nil {
			return fail(err)
		}
		defer pw.Wipe()
	}
	key, err := c.Decrypt(ctx, ks, pw)
	if err != nil {
		return fail(err)
	}
	b.Keys = []*mldsa87.Key{key}
	b.Meta = []provider.Meta{{DerivationPath: ks.Path, Keystore: true}}
	return b
}

// readPassword reads a password file: its content without trailing line
// breaks.
func readPassword(path string, p secretfile.Policy) (*qrlv1.Password, error) {
	data, err := secretfile.Read(path, MaxPasswordFile, p)
	if err != nil {
		return nil, err
	}
	defer mldsa87.Wipe(data)
	return qrlv1.NewPassword(qrlv1.TrimPassword(data)), nil
}
