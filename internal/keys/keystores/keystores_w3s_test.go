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
// signing/src/test/java/tech/pegasys/web3signer/signing/bulkloading/BlsKeystoreBulkLoaderTest.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package keystores

import (
	"os"
	"path/filepath"
	"testing"
)

// The bulk loader cases of Web3Signer's BlsKeystoreBulkLoaderTest, with
// ML-DSA-87 keystores. Each keystore is its own batch here, so "the error
// count" is the number of failed batches, and a loader that fails as a
// whole returns an error instead of one error result.

func TestLoadingEmptyKeystoreDirReturnsNoSigners(t *testing.T) {
	ksDir, pwDir := t.TempDir(), t.TempDir()
	res := mustLoad(t, Config{Dir: ksDir, PasswordsDir: pwDir})
	if len(res) != 0 {
		t.Fatalf("%d batches", len(res))
	}
}

func TestLoadsMultipleKeystores(t *testing.T) {
	ksDir, pwDir := t.TempDir(), t.TempDir()
	f := newFixture(t)
	a := f.keystore(t, ksDir, pwDir, 1, "password1")
	b := f.keystore(t, ksDir, pwDir, 2, "password2")
	res := mustLoad(t, Config{Dir: ksDir, PasswordsDir: pwDir})
	assertKeys(t, res, a, b)
	assertErrors(t, res, 0)
}

func TestLoadsMultipleKeystoresUsingSinglePasswordFile(t *testing.T) {
	dir := t.TempDir()
	ksDir := filepath.Join(dir, "keystores")
	if err := os.Mkdir(ksDir, 0o700); err != nil {
		t.Fatal(err)
	}
	f := newFixture(t)
	a := f.keystore(t, ksDir, "", 1, "password1")
	b := f.keystore(t, ksDir, "", 2, "password1")
	pw := writeSecret(t, dir, "password.txt", "password1")
	res := mustLoad(t, Config{Dir: ksDir, PasswordFile: pw})
	assertKeys(t, res, a, b)
	assertErrors(t, res, 0)
}

func TestIgnoresNonJsonFiles(t *testing.T) {
	ksDir, pwDir := t.TempDir(), t.TempDir()
	f := newFixture(t)
	a := f.keystore(t, ksDir, pwDir, 1, "password1")
	b := f.keystore(t, ksDir, pwDir, 2, "password2")
	if err := os.Rename(filepath.Join(ksDir, a.name), filepath.Join(ksDir, a.name[:len(a.name)-len(".json")]+".ignored")); err != nil {
		t.Fatal(err)
	}
	res := mustLoad(t, Config{Dir: ksDir, PasswordsDir: pwDir})
	assertKeys(t, res, b)
	assertErrors(t, res, 0)
}

func TestKeystoreWithoutPasswordCausesErrorCountAndRemainingKeystoresAreLoaded(t *testing.T) {
	ksDir, pwDir := t.TempDir(), t.TempDir()
	f := newFixture(t)
	f.keystore(t, ksDir, "", 1, "password1") // no password file
	b := f.keystore(t, ksDir, pwDir, 2, "password2")
	res := mustLoad(t, Config{Dir: ksDir, PasswordsDir: pwDir})
	assertKeys(t, res, b)
	assertErrors(t, res, 1)
}

func TestInvalidKeystoreIsIgnoredAndRemainingKeystoresAreLoaded(t *testing.T) {
	ksDir, pwDir := t.TempDir(), t.TempDir()
	f := newFixture(t)
	writeSecret(t, ksDir, "bad.json", "{}")
	writeSecret(t, pwDir, "bad.txt", "password1")
	b := f.keystore(t, ksDir, pwDir, 2, "password2")
	res := mustLoad(t, Config{Dir: ksDir, PasswordsDir: pwDir})
	assertKeys(t, res, b)
	assertErrors(t, res, 1)
}

func TestInvalidKeystoreDirectoryReturnsError(t *testing.T) {
	_, err := Config{Dir: filepath.Join(t.TempDir(), "invalidKeystorePath"), PasswordsDir: t.TempDir()}.
		Load(t.Context(), 1, nil, nil)
	if err == nil {
		t.Fatal("a missing keystore directory loaded")
	}
}

func TestInvalidKeystorePasswordFileReturnsError(t *testing.T) {
	dir := t.TempDir()
	ksDir := filepath.Join(dir, "keystores")
	if err := os.Mkdir(ksDir, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := Config{Dir: ksDir, PasswordFile: filepath.Join(dir, "invalidPasswordFilePath")}.Load(t.Context(), 1, nil, nil)
	if err == nil {
		t.Fatal("a missing password file loaded")
	}
}
