// Copyright 2025 ConsenSys AG.
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
// acceptance-tests/src/test/java/tech/pegasys/web3signer/tests/reload/ReloadAcceptanceTest.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package acceptance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystoretest"
)

// The cases of Web3Signer's ReloadAcceptanceTest, against the built binary
// with ML-DSA-87 keys in the key-config directory. They assert the
// deviation register where it differs from Web3Signer: the fixed messages
// of X44, and X52, the startup load reported by GET /reload.

// rawKey writes key i of tag as a file-raw key-config file named name and
// returns its 0x public key.
func rawKey(t *testing.T, dir, name, tag string, i int) string {
	t.Helper()
	seed := keystoretest.Seed(tag, i)
	pk, err := keystoretest.PublicKeyHex(seed)
	if err != nil {
		t.Fatal(err)
	}
	content := fmt.Sprintf("type: file-raw\nkeyType: ML_DSA_87\nprivateKey: \"0x%x\"\n", seed[:])
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return "0x" + pk
}

// invalidKey writes a file-raw key-config file whose privateKey is not a
// seed, as Web3Signer's test writes invalid hex.
func invalidKey(t *testing.T, dir, name, value string) {
	t.Helper()
	content := fmt.Sprintf("type: file-raw\nkeyType: ML_DSA_87\nprivateKey: %q\n", value)
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

var (
	standardOnce   sync.Once
	standardSealer *keystoretest.Sealer
	standardErr    error
)

// slowKeys writes n file-keystore key-config files whose keystores use the
// standard KDF (Argon2id with 256 MiB), so that a reload that loads them
// takes at least a second, as Web3Signer's test slows its reload down with
// encrypted keystores. The keystores and their password file live outside
// the key-config directory.
func slowKeys(t *testing.T, dir, tag string, n int) {
	t.Helper()
	standardOnce.Do(func() { standardSealer, standardErr = keystoretest.NewSealer("password", keystoretest.Standard) })
	if standardErr != nil {
		t.Fatal(standardErr)
	}
	ksDir := t.TempDir()
	pw, err := keystoretest.WriteFile(ksDir, "password.txt", []byte("password\n"))
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		data, err := standardSealer.DepositCLI(keystoretest.Seed(tag, i), i, false)
		if err != nil {
			t.Fatal(err)
		}
		ks, err := keystoretest.WriteFile(ksDir, keystoretest.DepositFileName(i, 1760000000), data)
		if err != nil {
			t.Fatal(err)
		}
		content := fmt.Sprintf("type: file-keystore\nkeyType: ML_DSA_87\nkeystoreFile: %q\nkeystorePasswordFile: %q\n", ks, pw)
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("slow-%d.yaml", i)), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// slowLoading is a signer that decrypts one standard keystore at a time.
var slowLoading = options{global: []string{"--signer-load-parallelism=1"}}

// reloadStatus returns GET /reload's body.
func (s *signer) reloadStatus() map[string]any {
	s.t.Helper()
	code, body, _ := s.do(request{path: "/reload", token: s.signToken()})
	var st map[string]any
	if err := json.Unmarshal([]byte(body), &st); code != 200 || err != nil {
		s.t.Fatalf("GET /reload: %d %s", code, body)
	}
	return st
}

// postReload posts /reload with the admin token and returns the status
// code and body.
func (s *signer) postReload() (int, string) {
	s.t.Helper()
	code, body, _ := s.do(request{method: "POST", path: "/reload", token: s.adminToken(), contentType: "application/json"})
	return code, body
}

func TestReloadAcceptsRequestAndReturns202WithAcceptedMessage(t *testing.T) {
	s := start(t, options{})
	s.waitReady()
	code, body := s.postReload()
	if code != 202 || body != `{"code":202,"message":"reload started"}` {
		t.Fatalf("POST /reload: %d %s", code, body)
	}
}

func TestReloadRejectsSecondRequestWithConflictWhenReloadInProgress(t *testing.T) {
	s := start(t, slowLoading)
	s.waitReady()
	slowKeys(t, s.keys, t.Name(), 2)
	if code, body := s.postReload(); code != 202 {
		t.Fatalf("first POST /reload: %d %s", code, body)
	}
	code, body := s.postReload()
	if code != 409 || reasonOf(t, body) != "RELOAD_IN_PROGRESS" {
		t.Fatalf("second POST /reload: %d %s", code, body)
	}
	s.waitReloadStatus("completed", time.Minute)
}

func TestReloadAllowsNewRequestAfterPreviousCompletes(t *testing.T) {
	s := start(t, options{})
	s.waitReady()
	for i := range 3 {
		rawKey(t, s.keys, fmt.Sprintf("key-%d.yaml", i), t.Name(), i)
	}
	s.reload("completed", 10*time.Second)
	if n := len(s.publicKeys()); n != 3 {
		t.Fatalf("%d keys after the reload, want 3", n)
	}
	if code, body := s.postReload(); code != 202 {
		t.Fatalf("second POST /reload: %d %s", code, body)
	}
	s.waitReloadStatus("completed", 10*time.Second)
}

// Adding, deleting and rewriting key-config files: the reload serves the
// added key and the rewritten file's new key, and neither the deleted key
// nor the rewritten file's old one.
func TestReloadPicksUpFileSystemChanges(t *testing.T) {
	keys := t.TempDir()
	k1 := rawKey(t, keys, "key-1.yaml", t.Name(), 1)
	k2 := rawKey(t, keys, "key-2.yaml", t.Name(), 2)
	s := start(t, options{keys: keys})
	s.waitReady()
	if got := s.publicKeys(); len(got) != 2 {
		t.Fatalf("%d keys at startup, want 2", len(got))
	}

	// Add one, delete one, modify one.
	k3 := rawKey(t, keys, "key-3.yaml", t.Name(), 3)
	if err := os.Remove(filepath.Join(keys, "key-2.yaml")); err != nil {
		t.Fatal(err)
	}
	k1Updated := rawKey(t, keys, "key-1.yaml", t.Name(), 10)
	s.reload("completed", 30*time.Second)

	got := s.publicKeys()
	want := []string{k1Updated, k3}
	slices.Sort(want)
	if !slices.Equal(got, want) || slices.Contains(got, k1) || slices.Contains(got, k2) {
		t.Fatalf("publicKeys after the changes: %d keys, want the updated and the added key", len(got))
	}
}

// Web3Signer loads its keys before it listens, so GET /reload is idle until
// the first POST. This signer listens at once (X36) and reports the startup
// load as the last operation (X52): completed, with its time, once the
// keys are loaded.
func TestReloadStatusReportsTheStartupLoad(t *testing.T) {
	s := start(t, options{})
	s.waitReady()
	st := s.reloadStatus()
	if st["status"] != "completed" || st["lastOperationTime"] == nil || st["lastError"] != nil {
		t.Fatalf("GET /reload after startup: %v", st)
	}
}

func TestReloadStatusTransitionsFromRunningToCompleted(t *testing.T) {
	s := start(t, slowLoading)
	s.waitReady()
	slowKeys(t, s.keys, t.Name(), 2)
	if code, body := s.postReload(); code != 202 {
		t.Fatalf("POST /reload: %d %s", code, body)
	}
	if st := s.reloadStatus(); st["status"] != "running" || st["lastOperationTime"] == nil || st["lastError"] != nil {
		t.Fatalf("GET /reload right after POST: %v", st)
	}
	s.waitReloadStatus("completed", time.Minute)
	if st := s.reloadStatus(); st["lastOperationTime"] == nil || st["lastError"] != nil {
		t.Fatalf("GET /reload after the reload: %v", st)
	}
}

func TestReloadStatusCanBeCalledMultipleTimesDuringReload(t *testing.T) {
	s := start(t, slowLoading)
	s.waitReady()
	slowKeys(t, s.keys, t.Name(), 2)
	if code, body := s.postReload(); code != 202 {
		t.Fatalf("POST /reload: %d %s", code, body)
	}
	for i := range 5 {
		if st := s.reloadStatus(); st["status"] != "running" {
			t.Fatalf("GET /reload %d during the reload: %v", i, st)
		}
	}
	s.waitReloadStatus("completed", time.Minute)
}

func TestReloadLastOperationTimeIsUpdatedOnEachReload(t *testing.T) {
	s := start(t, options{})
	s.waitReady()
	s.reload("completed", 10*time.Second)
	first := s.reloadStatus()["lastOperationTime"]
	time.Sleep(1100 * time.Millisecond) // lastOperationTime has a resolution of one second
	s.reload("completed", 10*time.Second)
	if second := s.reloadStatus()["lastOperationTime"]; second == first {
		t.Fatalf("lastOperationTime %v did not change", second)
	}
}

func TestReloadStatusIsCompletedWithErrorsWhenSomeKeyFilesFail(t *testing.T) {
	s := start(t, options{})
	s.waitReady()
	k1 := rawKey(t, s.keys, "valid-1.yaml", t.Name(), 1)
	invalidKey(t, s.keys, "invalid1.yaml", "not-a-valid-hex-string")
	invalidKey(t, s.keys, "invalid2.yaml", "GGGGGGGGGGGGGGGG")
	k2 := rawKey(t, s.keys, "valid-2.yaml", t.Name(), 2)
	s.reload("completed_with_errors", 10*time.Second)
	if st := s.reloadStatus(); st["lastOperationTime"] == nil || st["lastError"] != "reload completed with 2 key loading error(s)" {
		t.Fatalf("GET /reload: %v", st)
	}
	want := []string{k1, k2}
	slices.Sort(want)
	if got := s.publicKeys(); !slices.Equal(got, want) {
		t.Fatalf("publicKeys: %d keys, want the 2 valid ones", len(got))
	}
}

func TestReloadStatusIsCompletedWhenAllKeyFilesLoad(t *testing.T) {
	s := start(t, options{})
	s.waitReady()
	rawKey(t, s.keys, "valid-1.yaml", t.Name(), 1)
	rawKey(t, s.keys, "valid-2.yaml", t.Name(), 2)
	s.reload("completed", 10*time.Second)
	if st := s.reloadStatus(); st["lastOperationTime"] == nil || st["lastError"] != nil {
		t.Fatalf("GET /reload: %v", st)
	}
	if n := len(s.publicKeys()); n != 2 {
		t.Fatalf("%d keys, want 2", n)
	}
}

func TestReloadPreviousErrorIsClearedAfterSuccessfulReload(t *testing.T) {
	s := start(t, options{})
	s.waitReady()
	invalidKey(t, s.keys, "invalid1.yaml", "invalid-hex-content")
	invalidKey(t, s.keys, "invalid2.yaml", "also-invalid")
	s.reload("completed_with_errors", 10*time.Second)
	if st := s.reloadStatus(); st["lastError"] == nil {
		t.Fatalf("GET /reload: %v", st)
	}

	for _, name := range []string{"invalid1.yaml", "invalid2.yaml"} {
		if err := os.Remove(filepath.Join(s.keys, name)); err != nil {
			t.Fatal(err)
		}
	}
	k := rawKey(t, s.keys, "valid.yaml", t.Name(), 1)
	s.reload("completed", 10*time.Second)
	if st := s.reloadStatus(); st["lastError"] != nil {
		t.Fatalf("GET /reload after the fix: %v", st)
	}
	if got := s.publicKeys(); !slices.Equal(got, []string{k}) {
		t.Fatalf("publicKeys: %d keys, want the valid one", len(got))
	}
}

func TestReloadStatusShowsErrorCountForMultipleFailures(t *testing.T) {
	s := start(t, options{})
	s.waitReady()
	for i := range 5 {
		invalidKey(t, s.keys, fmt.Sprintf("invalid%d.yaml", i), fmt.Sprintf("invalid-content-%d", i))
	}
	k := rawKey(t, s.keys, "valid.yaml", t.Name(), 1)
	s.reload("completed_with_errors", 10*time.Second)
	if st := s.reloadStatus(); st["lastError"] != "reload completed with 5 key loading error(s)" {
		t.Fatalf("GET /reload: %v", st)
	}
	if got := s.publicKeys(); !slices.Equal(got, []string{k}) {
		t.Fatalf("publicKeys: %d keys, want the valid one", len(got))
	}
}

func TestReloadWithAllInvalidKeyFilesShowsCompletedWithErrors(t *testing.T) {
	s := start(t, options{})
	s.waitReady()
	for i := range 3 {
		invalidKey(t, s.keys, fmt.Sprintf("invalid%d.yaml", i), "completely-invalid")
	}
	s.reload("completed_with_errors", 10*time.Second)
	if st := s.reloadStatus(); st["lastError"] != "reload completed with 3 key loading error(s)" {
		t.Fatalf("GET /reload: %v", st)
	}
	if n := len(s.publicKeys()); n != 0 {
		t.Fatalf("%d keys, want none", n)
	}
}
