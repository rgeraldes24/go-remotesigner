// Copyright 2022 ConsenSys AG.
// Copyright 2026 ConsenSys AG.
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
// signing/src/main/java/tech/pegasys/web3signer/signing/KeystoreFileManager.java and
// signing/src/main/java/tech/pegasys/web3signer/signing/KeystoreFileRecord.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package keymanager

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keyconfig"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystore/qrlv1"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secretfile"
)

// File and directory modes of what the keymanager writes.
const (
	FileMode fs.FileMode = 0o600
	DirMode  fs.FileMode = 0o700
)

// Errors of the key-config directory and of a key's files.
var (
	// ErrDirInsecure: the key-config directory is open to its group or to
	// other users.
	ErrDirInsecure = errors.New("accessible to its group or other users; restrict it to its owner (chmod 0700) " +
		"or set --strict-file-permissions=false")
	// ErrOtherKey: a keystore file at a key's name declares another key.
	ErrOtherKey = errors.New("the keystore file at this key's name declares another key")
)

// posixModes reports whether file modes carry POSIX permission bits; on
// Windows they do not, and the directory's ACL governs access.
var posixModes = runtime.GOOS != "windows"

// PrepareDir readies the key-config directory for the files the keymanager
// writes. A missing directory is created with mode 0700. An existing one
// that its group or other users can access is refused with ErrDirInsecure
// when strict (--strict-file-permissions), and reported to warn otherwise.
func PrepareDir(dir string, strict bool, warn func(mode fs.FileMode)) error {
	fi, err := os.Stat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(dir, DirMode); err != nil {
			return fmt.Errorf("create the key-config directory %s: %w", dir, err)
		}
		// MkdirAll applies the umask; the mode is set as such.
		if err := os.Chmod(dir, DirMode); err != nil {
			return fmt.Errorf("key-config directory %s: %w", dir, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("key-config directory %s: %w", dir, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("key-config directory %s: not a directory", dir)
	}
	if perm := fi.Mode().Perm(); posixModes && perm&^DirMode != 0 {
		if strict {
			return fmt.Errorf("key-config directory %s: mode %04o: %w", dir, perm, ErrDirInsecure)
		}
		if warn != nil {
			warn(perm)
		}
	}
	return nil
}

// keyFiles are the files the keymanager writes for one key in the
// key-config directory, named by the hex SHA-256 of its public key (a
// public key in hex is longer than any file name may be): <stem>.yaml, the
// key-config file the loader reads; <stem>.json, the keystore as it was
// imported; and <stem>.password, its password.
type keyFiles struct {
	dir, stem string
}

func filesOf(dir string, pk *mldsa87.PublicKey) keyFiles {
	id := pk.ID()
	return keyFiles{dir: dir, stem: hex.EncodeToString(id[:])}
}

func (f keyFiles) config() string   { return filepath.Join(f.dir, f.stem+".yaml") }
func (f keyFiles) keystore() string { return filepath.Join(f.dir, f.stem+".json") }
func (f keyFiles) password() string { return filepath.Join(f.dir, f.stem+".password") }

// source is the provider source of the key-config file.
func (f keyFiles) source() string { return keyconfig.Source(f.config()) }

// configYAML is the key-config file: a file-keystore document naming the
// keystore and password files next to it.
func (f keyFiles) configYAML() []byte {
	return []byte("type: " + keyconfig.TypeFileKeystore + "\nkeyType: " + keyconfig.KeyTypeMLDSA87 +
		"\nkeystoreFile: " + f.stem + ".json\nkeystorePasswordFile: " + f.stem + ".password\n")
}

// write writes the password file, the keystore and the key-config file.
// Each is written to a new temporary file (O_EXCL, mode 0600, synced) and,
// once all three are, renamed over its name, in that order: the key-config
// file, which the loader lists, comes last, so that a load never finds it
// without the files it names. A file or a symlink planted at a name is
// replaced, never written through, and a reader sees the old file or the
// whole new one. A failure before the renames (a full disk fails there)
// leaves every name as it was; one between them removes the key's files.
// It reports whether it changed any name. The caller syncs the directory
// (syncDir) once it has written the files of every key it adds.
func (f keyFiles) write(keystore, password []byte) (changed bool, err error) {
	files := [...]struct {
		path string
		data []byte
	}{{f.password(), password}, {f.keystore(), keystore}, {f.config(), f.configYAML()}}
	var tmps []string
	defer func() {
		for _, tmp := range tmps {
			_ = os.Remove(tmp) // a no-op once renamed
		}
	}()
	for _, w := range files {
		tmp, err := writeTemp(w.path, w.data)
		if err != nil {
			return false, err
		}
		tmps = append(tmps, tmp)
	}
	for i, w := range files {
		if err := os.Rename(tmps[i], w.path); err != nil {
			if i == 0 {
				return false, err
			}
			_, _ = f.remove()
			return true, err
		}
	}
	return true, nil
}

// exists reports whether the key's key-config file is in the directory: an
// earlier import wrote the key's files.
func (f keyFiles) exists() bool {
	_, err := os.Lstat(f.config())
	return err == nil
}

// remove removes the key-config file first, so that a load never finds it
// without its keystore, then the keystore and the password file. It
// reports whether any of them existed.
func (f keyFiles) remove() (bool, error) {
	existed := false
	var errs []error
	for _, p := range []string{f.config(), f.keystore(), f.password()} {
		err := os.Remove(p)
		switch {
		case err == nil:
			existed = true
		case !errors.Is(err, fs.ErrNotExist):
			errs = append(errs, err)
		}
	}
	if existed {
		errs = append(errs, syncDir(f.dir))
	}
	return existed, errors.Join(errs...)
}

// check fails with ErrOtherKey when the keystore file at the key's name
// declares a key other than pk. A missing or unreadable keystore file, or
// one that declares no key, passes: its name is the key's.
func (f keyFiles) check(pk *mldsa87.PublicKey) error {
	data, err := secretfile.ReadCapped(f.keystore(), qrlv1.MaxSize)
	if err != nil {
		return nil
	}
	ks, err := qrlv1.Parse(data)
	if err != nil {
		return nil
	}
	if declared, ok := ks.PublicKey(); ok && declared != *pk {
		return ErrOtherKey
	}
	return nil
}

// writeTemp writes data to a temporary file next to path, created with
// O_EXCL and mode 0600, and synced, and returns its name, for the caller
// to rename over path. Temporary names start with a dot, so the loaders
// never list them. On failure nothing is left.
func writeTemp(path string, data []byte) (string, error) {
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", err
	}
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+"."+hex.EncodeToString(suffix[:])+".tmp")
	t, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, FileMode)
	if err != nil {
		return "", err
	}
	// The umask may have narrowed the mode; it never widens it.
	err = t.Chmod(FileMode)
	if err == nil {
		_, err = t.Write(data)
	}
	if err == nil {
		err = t.Sync()
	}
	if cerr := t.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return tmp, nil
}

// syncDir makes the directory's entries durable, where the platform can.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}
