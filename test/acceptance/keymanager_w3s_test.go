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
// acceptance-tests/src/test/java/tech/pegasys/web3signer/tests/keymanager/ListKeysAcceptanceTest.java,
// acceptance-tests/src/test/java/tech/pegasys/web3signer/tests/keymanager/ImportKeystoresAcceptanceTest.java,
// acceptance-tests/src/test/java/tech/pegasys/web3signer/tests/keymanager/DeleteKeystoresAcceptanceTest.java,
// acceptance-tests/src/test/java/tech/pegasys/web3signer/tests/keymanager/KeyManagerTestBase.java and
// acceptance-tests/src/test/java/tech/pegasys/web3signer/tests/keymanager/SlashingProtectionDataChoice.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package acceptance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// The cases of Web3Signer's keymanager acceptance tests (list, import and
// delete), against the built binary with ML-DSA-87 keys. Where the signer
// differs they assert the deviation register:
//
//   - X15: the keymanager's files are <sha256(pubkey)>.yaml, .json and
//     .password, mode 0600, and only a key loaded from such a file can be
//     deleted;
//   - X16: per-key history failures surface as an error for that key, which
//     stays inactive; only the history of the imported keys is written; the
//     export always names the genesis validators root;
//   - X29: DELETE persists enabled=false, which no reload undoes and a later
//     import reverses;
//   - X11: bodies are decoded strictly (Web3Signer answers 500 to a null
//     list, this signer 400).
//
// The Jackson DTO cases (testRequestBodyParsing) have no counterpart: the
// strict decoders are tested on their own in internal/api/keymanager.

// keystoreFiles writes the key-config file, keystore and password file of
// k as the keymanager names them, as Web3Signer's createKeystoreYamlFile
// writes <pubkey>.yaml; the keystore is the deposit CLI's, key i of its
// phrase, so it records a derivation path.
func keystoreFiles(t *testing.T, dir string, k kmKey, i int) {
	t.Helper()
	for name, content := range map[string]string{
		k.stem + ".json":     k.depositKeystore(t, i),
		k.stem + ".password": kmPassword,
		k.stem + ".yaml": "type: file-keystore\nkeyType: ML_DSA_87\nkeystoreFile: " + k.stem + ".json\n" +
			"keystorePasswordFile: " + k.stem + ".password\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// rawKeyFile writes k as a file-raw key-config file at the keymanager's
// name, as Web3Signer's createRawPrivateKeyFile does at <pubkey>.yaml.
func rawKeyFile(t *testing.T, dir, name string, k kmKey) {
	t.Helper()
	content := fmt.Sprintf("type: file-raw\nkeyType: ML_DSA_87\nprivateKey: \"0x%x\"\n", k.seed[:])
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// historyChoice is SlashingProtectionDataChoice: whether the store holds
// history for the two keys before the signer starts.
type historyChoice bool

const (
	withHistory    historyChoice = true
	withoutHistory historyChoice = false
)

// w3sKeys are the key of Web3Signer's bls_keystore.json, which the history
// covers, and that of bls_keystore_2.json, which it does not; the history
// also covers a third key that no keystore holds.
func w3sKeys(t *testing.T) (main, second, unrelated kmKey) {
	return newKMKey(t, "km-w3s", 0), newKMKey(t, "km-w3s", 1), newKMKey(t, "km-w3s", 2)
}

// singleEntry is the export of main's history: SINGLE_ENTRY_SLASHING_DATA
// with the signer's network.
func singleEntry(t *testing.T, main kmKey) string {
	t.Helper()
	return interchangeDoc(goldenGVR(t), historyEntry(main.pubkey, []uint64{19999}, 6, 7))
}

// emptyExport is EMPTY_SLASHING_DATA: the network and no data.
func emptyExport(t *testing.T) string { return interchangeDoc(goldenGVR(t)) }

// setupKeymanager is setupSignerWithKeyManagerApi: it imports the history
// of main and unrelated when asked (Web3Signer runs a second signer in
// import mode; here it is the offline import) and starts the signer.
func setupKeymanager(t *testing.T, dir, data string, history historyChoice, o options) *signer {
	t.Helper()
	main, _, unrelated := w3sKeys(t)
	if history {
		file := filepath.Join(t.TempDir(), "slashing.json")
		doc := interchangeDoc(goldenGVR(t), historyEntry(main.pubkey, []uint64{19999}, 6, 7),
			historyEntry(unrelated.pubkey, []uint64{12345}, 2, 3))
		if err := os.WriteFile(file, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		if code, out := runOffline(t, "--data-path="+data, "consensus", "import", "--from="+file); code != 0 {
			t.Fatalf("import: %d %s", code, out)
		}
	}
	o.keys, o.data = dir, data
	s := startKM(t, o)
	s.waitReady()
	return s
}

// sameJSON reports whether two JSON documents are equal as values.
func sameJSON(t *testing.T, a, b string) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal([]byte(a), &x); err != nil {
		t.Fatalf("%q: %v", a, err)
	}
	if err := json.Unmarshal([]byte(b), &y); err != nil {
		t.Fatalf("%q: %v", b, err)
	}
	xs, _ := json.Marshal(x)
	ys, _ := json.Marshal(y)
	return string(xs) == string(ys)
}

func TestW3SListKeys(t *testing.T) {
	t.Run("noLoadedKeysReturnsEmptyPublicKeyResponse", func(t *testing.T) {
		s := setupKeymanager(t, kmDir(t), t.TempDir(), withoutHistory, options{})
		if code, r, out := s.km("GET", ""); code != 200 || len(r.Data) != 0 || out != `{"data":[]}` {
			t.Fatalf("%d %s", code, out)
		}
	})
	t.Run("loadedKeysAreReturnedInPublicKeyResponse", func(t *testing.T) {
		dir := kmDir(t)
		main, _, _ := w3sKeys(t)
		keystoreFiles(t, dir, main, 0)
		s := setupKeymanager(t, dir, t.TempDir(), withoutHistory, options{})
		if _, r, out := s.km("GET", ""); !slices.Contains(r.pubkeys(), main.pubkey) {
			t.Fatalf("%s", out)
		}
	})
	t.Run("pathIsReturnedForKeystoreFiles", func(t *testing.T) {
		dir := kmDir(t)
		main, _, _ := w3sKeys(t)
		keystoreFiles(t, dir, main, 3)
		s := setupKeymanager(t, dir, t.TempDir(), withoutHistory, options{})
		if _, r, out := s.km("GET", ""); len(r.Data) != 1 || r.Data[0].DerivationPath != "m/12381/238/3/0" {
			t.Fatalf("%s", out)
		}
	})
	t.Run("additionalPublicKeyAreReportedAfterReload", func(t *testing.T) {
		dir := kmDir(t)
		main, second, _ := w3sKeys(t)
		keystoreFiles(t, dir, main, 0)
		s := setupKeymanager(t, dir, t.TempDir(), withoutHistory, options{})
		keystoreFiles(t, dir, second, 1)
		s.reload("completed", 10*time.Second)
		if _, r, out := s.km("GET", ""); !slices.Contains(r.pubkeys(), main.pubkey) || !slices.Contains(r.pubkeys(), second.pubkey) {
			t.Fatalf("%s", out)
		}
	})
	t.Run("nonKeystoreKeysAreReadOnly", func(t *testing.T) {
		dir := kmDir(t)
		main, _, _ := w3sKeys(t)
		rawKeyFile(t, dir, main.stem+".yaml", main)
		s := setupKeymanager(t, dir, t.TempDir(), withoutHistory, options{})
		if _, r, out := s.km("GET", ""); len(r.Data) != 1 || !r.Data[0].ReadOnly || r.Data[0].DerivationPath != "" {
			t.Fatalf("%s", out)
		}
	})
	// X15: a file-keystore key-config file under another name is read-only
	// too, where Web3Signer lists every file-keystore key as editable.
	t.Run("canReturnBothReadOnlyAndEditableKeystores", func(t *testing.T) {
		dir := kmDir(t)
		main, second, unrelated := w3sKeys(t)
		keystoreFiles(t, dir, main, 0)
		rawKeyFile(t, dir, second.stem+".yaml", second)
		other := filepath.Join(t.TempDir(), "other")
		if err := os.Mkdir(other, 0o700); err != nil {
			t.Fatal(err)
		}
		keystoreFiles(t, other, unrelated, 2)
		content := "type: file-keystore\nkeyType: ML_DSA_87\nkeystoreFile: " + filepath.Join(other, unrelated.stem+".json") +
			"\nkeystorePasswordFile: " + filepath.Join(other, unrelated.stem+".password") + "\n"
		if err := os.WriteFile(filepath.Join(dir, "validator.yaml"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		s := setupKeymanager(t, dir, t.TempDir(), withoutHistory, options{})
		_, r, out := s.km("GET", "")
		want := map[string]bool{main.pubkey: false, second.pubkey: true, unrelated.pubkey: true}
		if len(r.Data) != 3 || !slices.IsSorted(r.pubkeys()) {
			t.Fatalf("%s", out)
		}
		for _, d := range r.Data {
			if ro, ok := want[d.Pubkey]; !ok || d.ReadOnly != ro {
				t.Fatalf("%s: readonly %v", d.Pubkey[:12], d.ReadOnly)
			}
		}
	})
}

func TestW3SImportKeystores(t *testing.T) {
	main, second, unrelated := w3sKeys(t)
	// composeRequestBody: main's keystore and the history of main and
	// unrelated.
	composed := func(t *testing.T, password string, history bool) string {
		h := ""
		if history {
			h = interchangeDoc(goldenGVR(t), historyEntry(main.pubkey, []uint64{19999}, 6, 7),
				historyEntry(unrelated.pubkey, []uint64{12345}, 2, 3))
		}
		return importBody(t, []string{main.keystore(t)}, []string{password}, h)
	}

	t.Run("invalidRequestBodyReturnsError", func(t *testing.T) {
		s := setupKeymanager(t, kmDir(t), t.TempDir(), withoutHistory, options{})
		if code, _, out := s.km("POST", `{"invalid": "json body"}`); code != 400 || reasonOf(t, out) != "UNKNOWN_FIELD" {
			t.Fatalf("%d %s", code, out)
		}
	})
	t.Run("mismatchKeysAndPasswordsReturnsError", func(t *testing.T) {
		s := setupKeymanager(t, kmDir(t), t.TempDir(), withoutHistory, options{})
		body := importBody(t, []string{main.keystore(t)}, []string{kmPassword, "someOtherPassword"}, "")
		if code, _, out := s.km("POST", body); code != 400 || reasonOf(t, out) != "INVARIANT_VIOLATION" {
			t.Fatalf("%d %s", code, out)
		}
	})
	t.Run("emptyKeystoresReturnSuccess", func(t *testing.T) {
		s := setupKeymanager(t, kmDir(t), t.TempDir(), withoutHistory, options{})
		if code, r, out := s.km("POST", `{"keystores": [], "passwords": [] }`); code != 200 || len(r.Data) != 0 {
			t.Fatalf("%d %s", code, out)
		}
	})
	t.Run("validRequestBodyWithSlashingdataReturnsSuccess", func(t *testing.T) {
		s := setupKeymanager(t, kmDir(t), t.TempDir(), withoutHistory, options{})
		if code, r, out := s.km("POST", composed(t, kmPassword, true)); code != 200 || !slices.Contains(r.statuses(), "imported") {
			t.Fatalf("%d %s", code, out)
		}
	})
	t.Run("validRequestBodyWithWrongPasswordReturnsErrorResult", func(t *testing.T) {
		s := setupKeymanager(t, kmDir(t), t.TempDir(), withoutHistory, options{})
		if code, r, out := s.km("POST", composed(t, "wrongpassword", true)); code != 200 || !slices.Contains(r.statuses(), "error") {
			t.Fatalf("%d %s", code, out)
		}
	})
	t.Run("validRequestBodyNoSlashingdataReturnsImported", func(t *testing.T) {
		s := setupKeymanager(t, kmDir(t), t.TempDir(), withoutHistory, options{})
		if code, r, out := s.km("POST", composed(t, kmPassword, false)); code != 200 || !slices.Contains(r.statuses(), "imported") {
			t.Fatalf("%d %s", code, out)
		}
	})
	t.Run("oneValidKeyOneInvalidKeyReturnsImportedAndError", func(t *testing.T) {
		s := setupKeymanager(t, kmDir(t), t.TempDir(), withoutHistory, options{})
		body := importBody(t, []string{main.keystore(t), second.keystore(t)}, []string{kmPassword, "wrongpassord"}, "")
		if code, r, out := s.km("POST", body); code != 200 || !slices.Equal(r.statuses(), []string{"imported", "error"}) {
			t.Fatalf("%d %s", code, out)
		}
	})
	t.Run("existingKeyReturnsDuplicate", func(t *testing.T) {
		dir := kmDir(t)
		keystoreFiles(t, dir, main, 0)
		s := setupKeymanager(t, dir, t.TempDir(), withoutHistory, options{})
		if n := len(s.publicKeys()); n != 1 {
			t.Fatalf("%d keys", n)
		}
		if code, r, out := s.km("POST", composed(t, kmPassword, true)); code != 200 || !slices.Contains(r.statuses(), "duplicate") {
			t.Fatalf("%d %s", code, out)
		}
		if n := len(s.publicKeys()); n != 1 {
			t.Fatalf("%d keys", n)
		}
	})
	t.Run("importLoadsNewKeys", func(t *testing.T) {
		dir := kmDir(t)
		s := setupKeymanager(t, dir, t.TempDir(), withoutHistory, options{})
		if n := len(s.publicKeys()); n != 0 {
			t.Fatalf("%d keys", n)
		}
		if code, r, out := s.km("POST", composed(t, kmPassword, true)); code != 200 || !slices.Contains(r.statuses(), "imported") {
			t.Fatalf("%d %s", code, out)
		}
		if _, r, out := s.km("GET", ""); !slices.Contains(r.pubkeys(), main.pubkey) {
			t.Fatalf("%s", out)
		}
		if keys := s.publicKeys(); len(keys) != 1 || keys[0] != main.pubkey {
			t.Fatalf("publicKeys %d", len(keys))
		}
		// X15: the files are named by the SHA-256 of the key, mode 0600.
		want := []string{main.stem + ".json", main.stem + ".password", main.stem + ".yaml"}
		if got := dirNames(t, dir); !slices.Equal(got, want) {
			t.Fatalf("files %v", got)
		}
		for _, n := range want {
			if fi, err := os.Stat(filepath.Join(dir, n)); err != nil || fi.Mode().Perm() != 0o600 {
				t.Fatalf("%s: %v %v", n, fi, err)
			}
		}
	})
	t.Run("canSignAfterImportingNewKey", func(t *testing.T) {
		s := setupKeymanager(t, kmDir(t), t.TempDir(), withoutHistory, options{})
		if code, r, out := s.km("POST", composed(t, kmPassword, true)); code != 200 || !slices.Contains(r.statuses(), "imported") {
			t.Fatalf("%d %s", code, out)
		}
		if code, reason := s.sign(t, main.pubkey, goldenAttestation(t)); code != 200 {
			t.Fatalf("sign: %d %s", code, reason)
		}
	})
	// X29: the delete persisted enabled=false; importing the key again is
	// what enables it.
	t.Run("canSignPreviouslyDeletedKeyAfterImporting", func(t *testing.T) {
		data := t.TempDir()
		s := setupKeymanager(t, kmDir(t), data, withoutHistory, options{})
		if code, r, out := s.km("POST", composed(t, kmPassword, true)); code != 200 || !slices.Contains(r.statuses(), "imported") {
			t.Fatalf("%d %s", code, out)
		}
		if code, r, out := s.km("DELETE", deleteBody(main.pubkey)); code != 200 || r.Data[0].Status != "deleted" {
			t.Fatalf("%d %s", code, out)
		}
		if _, r, _ := s.km("GET", ""); len(r.Data) != 0 {
			t.Fatal("still listed")
		}
		if code, r, out := s.km("POST", composed(t, kmPassword, true)); code != 200 || !slices.Contains(r.statuses(), "imported") {
			t.Fatalf("%d %s", code, out)
		}
		if _, r, _ := s.km("GET", ""); !slices.Contains(r.pubkeys(), main.pubkey) {
			t.Fatal("not listed again")
		}
		if code, reason := s.sign(t, main.pubkey, goldenAttestation(t)); code != 200 {
			t.Fatalf("sign: %d %s", code, reason)
		}
		s.stop()
		if st := storeStatus(t, data, main.pubkey); !st.Enabled {
			t.Fatalf("%+v", st)
		}
	})
	// X16: only the history of the imported key is written.
	t.Run("importLoadsSlashingData", func(t *testing.T) {
		data := t.TempDir()
		s := setupKeymanager(t, kmDir(t), data, withoutHistory, options{})
		if code, _, out := s.km("POST", composed(t, kmPassword, true)); code != 200 {
			t.Fatalf("%d %s", code, out)
		}
		code, r, out := s.km("DELETE", deleteBody(main.pubkey, unrelated.pubkey))
		if code != 200 || !slices.Equal(r.statuses(), []string{"deleted", "not_found"}) ||
			!sameJSON(t, r.SlashingProtection, singleEntry(t, main)) {
			t.Fatalf("%d %s", code, out)
		}
		s.stop()
		if st := storeStatus(t, data, main.pubkey); !st.Registered {
			t.Fatalf("main %+v", st)
		}
	})
	// X16: a history element of the imported key that fails makes that key
	// an error; it is not loaded and stays disabled. Web3Signer refuses the
	// whole request instead.
	t.Run("historyFailureLeavesTheKeyInactive", func(t *testing.T) {
		data, dir := t.TempDir(), kmDir(t)
		s := setupKeymanager(t, dir, data, withoutHistory, options{})
		bad := `{"pubkey":"` + main.pubkey + `","signed_blocks":[{"slot":"1","signing_root":"0x00"}],"signed_attestations":[]}`
		body := importBody(t, []string{main.keystore(t), second.keystore(t)}, []string{kmPassword, kmPassword},
			interchangeDoc(goldenGVR(t), bad))
		code, r, out := s.km("POST", body)
		if code != 200 || !slices.Equal(r.statuses(), []string{"error", "imported"}) {
			t.Fatalf("%d %s", code, out)
		}
		if _, l, _ := s.km("GET", ""); slices.Contains(l.pubkeys(), main.pubkey) || len(dirNames(t, dir)) != 3 {
			t.Fatalf("the key with a failed history is active: %s", out)
		}
		s.stop()
		if st := storeStatus(t, data, main.pubkey); !st.Registered || st.Enabled {
			t.Fatalf("main %+v", st)
		}
	})
}

func TestW3SDeleteKeystores(t *testing.T) {
	main, second, _ := w3sKeys(t)

	// X11: strict decoding.
	t.Run("invalidRequestBodyReturnsError", func(t *testing.T) {
		s := setupKeymanager(t, kmDir(t), t.TempDir(), withHistory, options{})
		if code, _, out := s.km("DELETE", `{"invalid": "json body"}`); code != 400 || reasonOf(t, out) != "UNKNOWN_FIELD" ||
			!strings.Contains(out, `"code":400`) {
			t.Fatalf("%d %s", code, out)
		}
	})
	t.Run("internalServerErrorReturnsJsonErrorBody", func(t *testing.T) {
		s := setupKeymanager(t, kmDir(t), t.TempDir(), withHistory, options{})
		if code, _, out := s.km("DELETE", `{"pubkeys": null}`); code != 400 || reasonOf(t, out) != "BAD_FIELD" {
			t.Fatalf("%d %s", code, out)
		}
	})
	t.Run("deletingExistingKeyWithNoSlashingProtectionDataTwiceReturnsNotFound", func(t *testing.T) {
		dir := kmDir(t)
		keystoreFiles(t, dir, second, 1)
		s := setupKeymanager(t, dir, t.TempDir(), withHistory, options{})
		for _, want := range []string{"deleted", "not_found"} {
			code, r, out := s.km("DELETE", deleteBody(second.pubkey))
			if code != 200 || r.Data[0].Status != want || !sameJSON(t, r.SlashingProtection, emptyExport(t)) {
				t.Fatalf("%d %s, want %s", code, out, want)
			}
		}
	})
	t.Run("deletingExistingKeyReturnDeleted", func(t *testing.T) {
		dir := kmDir(t)
		keystoreFiles(t, dir, main, 0)
		s := setupKeymanager(t, dir, t.TempDir(), withHistory, options{})
		code, r, out := s.km("DELETE", deleteBody(main.pubkey))
		if code != 200 || r.Data[0].Status != "deleted" || !sameJSON(t, r.SlashingProtection, singleEntry(t, main)) {
			t.Fatalf("%d %s", code, out)
		}
		// X15: its three files are gone.
		if got := dirNames(t, dir); len(got) != 0 {
			t.Fatalf("files %v", got)
		}
	})
	t.Run("deletingExistingTwiceReturnsNotActive", func(t *testing.T) {
		dir := kmDir(t)
		keystoreFiles(t, dir, main, 0)
		s := setupKeymanager(t, dir, t.TempDir(), withHistory, options{})
		for _, want := range []string{"deleted", "not_active"} {
			code, r, out := s.km("DELETE", deleteBody(main.pubkey))
			if code != 200 || r.Data[0].Status != want || !sameJSON(t, r.SlashingProtection, singleEntry(t, main)) {
				t.Fatalf("%d %s, want %s", code, out, want)
			}
		}
	})
	t.Run("deletingRemovesSignerFromActiveSigners", func(t *testing.T) {
		dir := kmDir(t)
		keystoreFiles(t, dir, main, 0)
		keystoreFiles(t, dir, second, 1)
		s := setupKeymanager(t, dir, t.TempDir(), withHistory, options{})
		if _, r, out := s.km("GET", ""); len(r.Data) != 2 {
			t.Fatalf("%s", out)
		}
		code, r, out := s.km("DELETE", deleteBody(main.pubkey))
		if code != 200 || r.Data[0].Status != "deleted" || !sameJSON(t, r.SlashingProtection, singleEntry(t, main)) {
			t.Fatalf("%d %s", code, out)
		}
		if _, r, out := s.km("GET", ""); len(r.Data) != 1 || r.Data[0].Pubkey != second.pubkey {
			t.Fatalf("%s", out)
		}
	})
	t.Run("deletingReadOnlyKeyReturnError", func(t *testing.T) {
		dir := kmDir(t)
		rawKeyFile(t, dir, main.stem+".yaml", main)
		s := setupKeymanager(t, dir, t.TempDir(), withHistory, options{})
		code, r, out := s.km("DELETE", deleteBody(main.pubkey))
		if code != 200 || r.Data[0].Status != "error" || !sameJSON(t, r.SlashingProtection, emptyExport(t)) {
			t.Fatalf("%d %s", code, out)
		}
		if code, reason := s.sign(t, main.pubkey, selectionProof(t)); code != 200 {
			t.Fatalf("the read-only key stopped signing: %d %s", code, reason)
		}
	})
	// X29: Web3Signer runs two signers on one Postgres database. bbolt has
	// one process per store, so the second signer here is the same store
	// after a restart, with the key back in a read-only key-config file:
	// the delete's enabled=false holds, for blocks and attestations, and no
	// load undoes it.
	t.Run("deletingDisablesSigningForAllWeb3Signers", func(t *testing.T) {
		data, dir := t.TempDir(), kmDir(t)
		keystoreFiles(t, dir, main, 0)
		keystoreFiles(t, dir, second, 1)
		s := setupKeymanager(t, dir, data, withHistory, options{})
		code, r, out := s.km("DELETE", deleteBody(main.pubkey))
		if code != 200 || r.Data[0].Status != "deleted" || !sameJSON(t, r.SlashingProtection, singleEntry(t, main)) {
			t.Fatalf("%d %s", code, out)
		}
		if _, l, _ := s.km("GET", ""); len(l.Data) != 1 || l.Data[0].Pubkey != second.pubkey {
			t.Fatal("list after the delete")
		}
		for _, typ := range []string{"ATTESTATION", "BLOCK_V2"} {
			if code, _ := s.sign(t, main.pubkey, goldenRequest(t, typ)); code != 404 {
				t.Fatalf("%s on the first signer: %d", typ, code)
			}
		}
		s.stop()

		rawKeyFile(t, dir, "validator-1.yaml", main)
		s2 := startKM(t, options{keys: dir, data: data})
		s2.waitReady()
		if _, l, _ := s2.km("GET", ""); len(l.Data) != 2 {
			t.Fatal("the second signer did not load both keys")
		}
		for _, typ := range []string{"ATTESTATION", "BLOCK_V2"} {
			if code, reason := s2.sign(t, main.pubkey, goldenRequest(t, typ)); code != 412 || reason != "VALIDATOR_DISABLED" {
				t.Fatalf("%s on the second signer: %d %s", typ, code, reason)
			}
		}
		if code, reason := s2.sign(t, second.pubkey, goldenAttestation(t)); code != 200 {
			t.Fatalf("the other key: %d %s", code, reason)
		}
		s2.reload("completed", 10*time.Second)
		if code, reason := s2.sign(t, main.pubkey, goldenAttestation(t)); code != 412 || reason != "VALIDATOR_DISABLED" {
			t.Fatalf("after a reload: %d %s", code, reason)
		}
	})
	// X16: the export names the network even when the store holds no
	// history; Web3Signer's export then has no genesis_validators_root.
	t.Run("deletingExistingKeyWithNoSlashingProtectionReturnDeleted", func(t *testing.T) {
		dir := kmDir(t)
		keystoreFiles(t, dir, main, 0)
		s := setupKeymanager(t, dir, t.TempDir(), withoutHistory, options{})
		code, r, out := s.km("DELETE", deleteBody(main.pubkey))
		if code != 200 || r.Data[0].Status != "deleted" || !sameJSON(t, r.SlashingProtection, emptyExport(t)) ||
			!strings.Contains(r.SlashingProtection, goldenGVR(t)) {
			t.Fatalf("%d %s", code, out)
		}
	})
}
