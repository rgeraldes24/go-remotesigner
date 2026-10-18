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
// acceptance-tests/src/test/java/tech/pegasys/web3signer/tests/bulkloading/KeystoreAcceptanceTest.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package acceptance

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystoretest"
)

// The cases of Web3Signer's KeystoreAcceptanceTest: keystores of
// --keystores-path, opened with a password directory or with one password
// file, are served by publicKeys.

// sealedKeystore writes key i of tag, sealed under password with the
// cheapest KDF, into dir and returns its file name and 0x public key.
func sealedKeystore(t *testing.T, dir, tag string, i int, password string) (string, string) {
	t.Helper()
	s, err := keystoretest.NewSealer(password, keystoretest.Cheapest)
	if err != nil {
		t.Fatal(err)
	}
	seed := keystoretest.Seed(tag, i)
	data, err := s.DepositCLI(seed, i, true)
	if err != nil {
		t.Fatal(err)
	}
	name := keystoretest.DepositFileName(i, 1760000000)
	if _, err := keystoretest.WriteFile(dir, name, data); err != nil {
		t.Fatal(err)
	}
	pk, err := keystoretest.PublicKeyHex(seed)
	if err != nil {
		t.Fatal(err)
	}
	return name, "0x" + pk
}

func TestSecretsFromKeystoresAreLoadedUsingPasswordDirAndReportedViaPublicKeysAPI(t *testing.T) {
	keystoreDir, passwordDir := t.TempDir(), t.TempDir()
	var want []string
	for i, password := range []string{"password1", "password2"} {
		name, pk := sealedKeystore(t, keystoreDir, t.Name(), i, password)
		if _, err := keystoretest.WriteFile(passwordDir, strings.TrimSuffix(name, ".json")+".txt", []byte(password)); err != nil {
			t.Fatal(err)
		}
		want = append(want, pk)
	}
	s := start(t, options{consensus: []string{"--keystores-path=" + keystoreDir, "--keystores-passwords-path=" + passwordDir}})
	s.waitReadyWithin(time.Minute)
	slices.Sort(want)
	if got := s.publicKeys(); !slices.Equal(got, want) {
		t.Fatalf("publicKeys: %d keys, want the 2 keystores' keys", len(got))
	}
}

func TestSecretsFromKeystoresAreLoadedUsingPasswordFileAndReportedViaPublicKeysAPI(t *testing.T) {
	dir := t.TempDir()
	keystoreDir := filepath.Join(dir, "keystores")
	if err := os.Mkdir(keystoreDir, 0o700); err != nil {
		t.Fatal(err)
	}
	var want []string
	for i := range 2 {
		_, pk := sealedKeystore(t, keystoreDir, t.Name(), i, "password1")
		want = append(want, pk)
	}
	passwordFile, err := keystoretest.WriteFile(dir, "password.txt", []byte("password1"))
	if err != nil {
		t.Fatal(err)
	}
	s := start(t, options{consensus: []string{"--keystores-path=" + keystoreDir, "--keystores-password-file=" + passwordFile}})
	s.waitReadyWithin(time.Minute)
	slices.Sort(want)
	if got := s.publicKeys(); !slices.Equal(got, want) {
		t.Fatalf("publicKeys: %d keys, want the 2 keystores' keys", len(got))
	}
}
