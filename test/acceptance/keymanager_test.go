// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package acceptance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystoretest"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/boltstore"
	"github.com/rgeraldes24/go-remotesigner/internal/vectors"
)

// The keymanager API against the built binary (docs/operations/keymanager.md):
// keystore refusals, logging, file modes, and changes during the startup
// load.

const kmPath = "/qrl/v1/keystores"

// kmPassword is the password of every keystore kmSealer seals.
const kmPassword = "keymanager-acceptance-password"

var (
	kmSealerOnce sync.Once
	kmSealerVal  *keystoretest.Sealer
	kmSealerErr  error
)

func kmSealer(t *testing.T) *keystoretest.Sealer {
	t.Helper()
	kmSealerOnce.Do(func() { kmSealerVal, kmSealerErr = keystoretest.NewSealer(kmPassword, keystoretest.Cheapest) })
	if kmSealerErr != nil {
		t.Fatal(kmSealerErr)
	}
	return kmSealerVal
}

// kmKey is a test key: its seed, its 0x public key and the stem of its
// keymanager files.
type kmKey struct {
	seed   *[mldsa87.SeedSize]byte
	pubkey string
	stem   string
}

func newKMKey(t *testing.T, tag string, i int) kmKey {
	t.Helper()
	seed := keystoretest.Seed(tag, i)
	h, err := keystoretest.PublicKeyHex(seed)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := hex.DecodeString(h)
	sum := sha256.Sum256(raw)
	return kmKey{seed: seed, pubkey: "0x" + h, stem: hex.EncodeToString(sum[:])}
}

// keystore is the key's qrysm keystore v1 under kmPassword.
func (k kmKey) keystore(t *testing.T) string {
	t.Helper()
	ks, err := kmSealer(t).QRLV1(k.seed, true)
	if err != nil {
		t.Fatal(err)
	}
	return string(ks)
}

// depositKeystore is the key's deposit CLI keystore, key i of its phrase.
func (k kmKey) depositKeystore(t *testing.T, i int) string {
	t.Helper()
	ks, err := kmSealer(t).DepositCLI(k.seed, i, true)
	if err != nil {
		t.Fatal(err)
	}
	return string(ks)
}

// editKeystore changes a keystore's JSON.
func editKeystore(t *testing.T, ks string, fn func(m map[string]any)) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(ks), &m); err != nil {
		t.Fatal(err)
	}
	fn(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func kdfOf(m map[string]any) map[string]any {
	return m["crypto"].(map[string]any)["kdf"].(map[string]any)["params"].(map[string]any)
}

// goldenGVR is the genesis validators root of the minimal-preset golden
// requests, which goldenRequest returns.
func goldenGVR(t *testing.T) string {
	t.Helper()
	for _, c := range vectors.Signing(t) {
		if c.Preset == "minimal" && c.Name == "typical" {
			return c.Network.GVR
		}
	}
	t.Fatal("no minimal golden case")
	return ""
}

// kmDir creates a key-config directory only its owner can access.
func kmDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "keys")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// startKM starts a signer with the keymanager API and the golden network's
// genesis validators root. A key-config directory is created when o has
// none.
func startKM(t *testing.T, o options) *signer {
	t.Helper()
	if o.keys == "" {
		o.keys = kmDir(t)
	}
	o.consensus = append([]string{"--key-manager-api-enabled", "--network-genesis-validators-root=" + goldenGVR(t)},
		o.consensus...)
	return start(t, o)
}

// kmResponse is a keymanager response body.
type kmResponse struct {
	Data []struct {
		Status         string `json:"status"`
		Message        string `json:"message"`
		Pubkey         string `json:"validating_pubkey"`
		DerivationPath string `json:"derivation_path"`
		ReadOnly       bool   `json:"readonly"`
	} `json:"data"`
	SlashingProtection string `json:"slashing_protection"`
}

func (r kmResponse) statuses() []string {
	out := make([]string, len(r.Data))
	for i, d := range r.Data {
		out[i] = d.Status
	}
	return out
}

func (r kmResponse) pubkeys() []string {
	out := make([]string, len(r.Data))
	for i, d := range r.Data {
		out[i] = d.Pubkey
	}
	return out
}

// km calls a keymanager route with the admin token. A 200 body is decoded.
func (s *signer) km(method, body string) (int, kmResponse, string) {
	s.t.Helper()
	r := request{method: method, path: kmPath, token: s.adminToken()}
	if body != "" {
		r.contentType = "application/json"
		r.body = strings.NewReader(body)
	}
	code, out, _ := s.do(r)
	var resp kmResponse
	if code == 200 {
		if err := json.Unmarshal([]byte(out), &resp); err != nil {
			s.t.Fatalf("%s %s: %v: %s", method, kmPath, err, out)
		}
	}
	return code, resp, out
}

// importBody is a POST body; history is the interchange, or "" for none.
func importBody(t *testing.T, keystores, passwords []string, history string) string {
	t.Helper()
	m := map[string]any{"keystores": keystores, "passwords": passwords}
	if history != "" {
		m["slashing_protection"] = history
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func deleteBody(pubkeys ...string) string {
	b, _ := json.Marshal(map[string]any{"pubkeys": pubkeys})
	return string(b)
}

// interchangeDoc is an EIP-3076 document for gvr with one element per
// entry.
func interchangeDoc(gvr string, entries ...string) string {
	return `{"metadata":{"interchange_format_version":"5","genesis_validators_root":"` + gvr + `"},"data":[` +
		strings.Join(entries, ",") + `]}`
}

// historyEntry is an element with blocks at slots and one attestation
// (source, target) when target is not 0.
func historyEntry(pubkey string, slots []uint64, source, target uint64) string {
	var bs []string
	for _, s := range slots {
		bs = append(bs, fmt.Sprintf(`{"slot":"%d","signing_root":"0x%064x"}`, s, s))
	}
	atts := ""
	if target != 0 {
		atts = fmt.Sprintf(`{"source_epoch":"%d","target_epoch":"%d","signing_root":"0x%064x"}`, source, target, target)
	}
	return fmt.Sprintf(`{"pubkey":"%s","signed_blocks":[%s],"signed_attestations":[%s]}`, pubkey,
		strings.Join(bs, ","), atts)
}

// dirNames lists a directory.
func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// storeStatus opens a stopped signer's store and returns a key's status.
func storeStatus(t *testing.T, data, pubkey string) slashing.ValidatorStatus {
	t.Helper()
	st, err := boltstore.Open(filepath.Join(data, "slashing-protection.db"), boltstore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	pk, err := hex.DecodeString(strings.TrimPrefix(pubkey, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	vs, err := st.ValidatorStatus(context.Background(), slashing.KeyIDOf(pk))
	if err != nil {
		t.Fatal(err)
	}
	return vs
}

// A keystore whose pubkey is another key's (the victim's), a KDF beyond
// the policy (m of 2^31 KiB), a missing KDF, a 16-byte dklen and a pubkey
// that names a path are each refused with status error: no file is
// written, the victim's history is unchanged although the request carries
// history for it, and the refusals cost no Argon2id run, so the signer's
// memory stays where it was.
func TestKeymanagerRefusesSpoofedAndOversizedKeystores(t *testing.T) {
	s := startKM(t, options{})
	s.waitReady()
	gvr := goldenGVR(t)
	victim, attacker := newKMKey(t, "km-victim", 0), newKMKey(t, "km-attacker", 0)
	body := importBody(t, []string{victim.keystore(t)}, []string{kmPassword},
		interchangeDoc(gvr, historyEntry(victim.pubkey, []uint64{5}, 1, 2)))
	if code, r, out := s.km("POST", body); code != 200 || !slices.Equal(r.statuses(), []string{"imported"}) {
		t.Fatalf("import the victim: %d %s", code, out)
	}
	// The victim moves away: deleted here, its history exported.
	code, r, out := s.km("DELETE", deleteBody(victim.pubkey))
	if code != 200 || !slices.Equal(r.statuses(), []string{"deleted"}) {
		t.Fatalf("delete the victim: %d %s", code, out)
	}
	before := r.SlashingProtection

	spoofed := editKeystore(t, attacker.keystore(t), func(m map[string]any) { m["pubkey"] = victim.pubkey[2:] })
	ks := attacker.keystore(t)
	refused := []string{
		spoofed,
		editKeystore(t, ks, func(m map[string]any) { kdfOf(m)["m"] = math.MaxInt32 + 1 }),
		editKeystore(t, ks, func(m map[string]any) { delete(m["crypto"].(map[string]any), "kdf") }),
		editKeystore(t, ks, func(m map[string]any) { kdfOf(m)["dklen"] = 16 }),
		editKeystore(t, ks, func(m map[string]any) { m["pubkey"] = "../../" + victim.stem }),
	}
	pws := slices.Repeat([]string{kmPassword}, len(refused))
	history := interchangeDoc(gvr, historyEntry(victim.pubkey, []uint64{50, 60}, 7, 8),
		historyEntry(attacker.pubkey, []uint64{70}, 0, 0))
	rssBefore := rssKiB(t, s.cmd.Process.Pid)
	start := time.Now()
	code, r, out = s.km("POST", importBody(t, refused, pws, history))
	elapsed := time.Since(start)
	if code != 200 || !slices.Equal(r.statuses(), slices.Repeat([]string{"error"}, len(refused))) {
		t.Fatalf("refused import: %d %s", code, out)
	}
	for i, want := range []string{"does not match", "policy", "policy", "policy", "malformed"} {
		if !strings.Contains(r.Data[i].Message, want) {
			t.Errorf("keystore %d: %q, want %q", i, r.Data[i].Message, want)
		}
	}
	if rssAfter := rssKiB(t, s.cmd.Process.Pid); rssAfter-rssBefore > 64<<10 || elapsed > 5*time.Second {
		t.Fatalf("RSS %d KiB to %d KiB, %v", rssBefore, rssAfter, elapsed)
	}
	if got := dirNames(t, s.keys); len(got) != 0 {
		t.Fatalf("files written: %v", got)
	}
	_, list, _ := s.km("GET", "")
	if len(list.Data) != 0 {
		t.Fatalf("listed %v", list.pubkeys())
	}
	// The victim's history is what it was: the same export, byte for byte.
	code, r, out = s.km("DELETE", deleteBody(victim.pubkey, attacker.pubkey))
	if code != 200 || !slices.Equal(r.statuses(), []string{"not_active", "not_found"}) || r.SlashingProtection != before {
		t.Fatalf("history after the refusals: %d %s\nbefore: %s", code, out, before)
	}
	s.stop()
	if st := storeStatus(t, s.data, victim.pubkey); !st.Registered || st.Enabled {
		t.Fatalf("victim %+v", st)
	}
}

// At TRACE, neither a body that does not parse nor imports, deletes and
// lists put a password, a keystore's ciphertext, a token or a full public
// key into the log.
func TestKeymanagerLogsNoSecretsAtTrace(t *testing.T) {
	s := startKM(t, options{global: []string{"--logging=TRACE"}})
	s.waitReady()
	k, other := newKMKey(t, "km-trace", 0), newKMKey(t, "km-trace", 1)
	ks := k.keystore(t)
	var parsed map[string]any
	if err := json.Unmarshal([]byte(ks), &parsed); err != nil {
		t.Fatal(err)
	}
	ciphertext := parsed["crypto"].(map[string]any)["cipher"].(map[string]any)["message"].(string)
	const wrong = "keymanager-wrong-password-42"

	quoted, _ := json.Marshal(ks)
	for _, broken := range []string{
		`{"keystores":[` + string(quoted) + `],"passwords":["` + kmPassword + `"],`, // syntax error
		`{"keystores":[` + string(quoted) + `],"passwords":["` + kmPassword + `"],"extra":"` + wrong + `"}`,
	} {
		if code, _, out := s.km("POST", broken); code != 400 {
			t.Fatalf("broken body: %d %s", code, out)
		}
	}
	code, r, out := s.km("POST", importBody(t, []string{ks, other.keystore(t)}, []string{kmPassword, wrong}, ""))
	if code != 200 || !slices.Equal(r.statuses(), []string{"imported", "error"}) {
		t.Fatalf("import: %d %s", code, out)
	}
	if code, _, _ := s.km("GET", ""); code != 200 {
		t.Fatal("list")
	}
	if code, _ := s.post("/api/v1/consensus/sign/"+k.pubkey, s.signToken(), selectionProof(t)); code != 200 {
		t.Fatalf("sign: %d", code)
	}
	if code, r, _ := s.km("DELETE", deleteBody(k.pubkey, other.pubkey)); code != 200 || r.Data[0].Status != "deleted" {
		t.Fatalf("delete: %d", code)
	}
	// The log reaches the test through a pipe, after the responses: it is
	// complete once the signer has exited.
	s.stop()
	logs := s.output.String()
	for name, secret := range map[string]string{
		"password": kmPassword, "wrong password": wrong, "ciphertext": ciphertext, "admin token": s.adminToken(),
		"sign token": s.signToken(), "public key": k.pubkey[2:], "other public key": other.pubkey[2:],
	} {
		if strings.Contains(logs, secret) {
			t.Fatalf("the log holds the %s", name)
		}
	}
	// The refused bodies were logged at DEBUG, by route and reason only:
	// the most verbose lines the signer writes are on.
	if strings.Count(logs, `msg="Failed request"`) < 2 || !strings.Contains(logs, "Keymanager import") ||
		!strings.Contains(logs, "Keymanager delete") {
		t.Fatalf("missing log lines:\n%s", logs)
	}
}

// The files the keymanager writes are 0600 in a directory it creates 0700.
// A key-config directory open to others is refused under
// --strict-file-permissions and loaded with a warning without it, and a
// password file made world-readable fails its key's load under the strict
// policy.
func TestKeymanagerFileModes(t *testing.T) {
	data := t.TempDir()
	dir := filepath.Join(t.TempDir(), "new", "keys")
	s := startKM(t, options{keys: dir, data: data})
	s.waitReady()
	k := newKMKey(t, "km-modes", 0)
	if code, r, out := s.km("POST", importBody(t, []string{k.keystore(t)}, []string{kmPassword}, "")); code != 200 ||
		r.Data[0].Status != "imported" {
		t.Fatalf("import: %d %s", code, out)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("directory: %v %v", fi, err)
	}
	want := []string{k.stem + ".json", k.stem + ".password", k.stem + ".yaml"}
	if got := dirNames(t, dir); !slices.Equal(got, want) {
		t.Fatalf("files %v, want %v", got, want)
	}
	for _, name := range want {
		if fi, err := os.Stat(filepath.Join(dir, name)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", name, fi, err)
		}
	}
	s.stop()

	// A world-readable password file: the key does not load.
	if err := os.Chmod(filepath.Join(dir, k.stem+".password"), 0o644); err != nil {
		t.Fatal(err)
	}
	s = startKM(t, options{keys: dir, data: data})
	s.waitReady()
	if _, r, _ := s.km("GET", ""); len(r.Data) != 0 {
		t.Fatalf("a key with a world-readable password file loaded: %v", r.pubkeys())
	}
	if code, out := keysHealth(t, s, "keys-check/config-files-loading"); code != 503 || !strings.Contains(out, `"error-count":1`) {
		t.Fatalf("health: %d %s", code, out)
	}
	s.stop()

	open := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	refused := launch(t, options{keys: open, consensus: []string{"--key-manager-api-enabled"}})
	if code := refused.exitCode(15 * time.Second); code != 1 || !strings.Contains(refused.output.String(), "chmod 0700") {
		t.Fatalf("an open directory: exit %d\n%s", code, refused.output.String())
	}
	lax := startKM(t, options{keys: open, global: []string{"--strict-file-permissions=false"}})
	lax.waitReady()
	lax.stop()
	if !strings.Contains(lax.output.String(), "accessible to its group or other users") {
		t.Fatalf("no warning:\n%s", lax.output.String())
	}
}

// keysHealth returns /healthcheck's status and the JSON of one check.
func keysHealth(t *testing.T, s *signer, id string) (int, string) {
	t.Helper()
	code, body, _ := s.do(request{path: "/healthcheck", token: s.signToken()})
	var h struct {
		Checks []json.RawMessage `json:"checks"`
	}
	if err := json.Unmarshal([]byte(body), &h); err != nil {
		t.Fatalf("healthcheck %q: %v", body, err)
	}
	for _, c := range h.Checks {
		if strings.Contains(string(c), `"`+id+`"`) {
			return code, string(c)
		}
	}
	t.Fatalf("no check %s in %s", id, body)
	return 0, ""
}

// The keymanager answers during the startup load. A DELETE of a key whose
// files the load has not reached yet deletes it for good: the load ends
// without it, it does not sign, its files are gone and it stays disabled.
// A key imported meanwhile stays loaded after the load.
func TestKeymanagerDuringTheStartupLoad(t *testing.T) {
	data, dir := t.TempDir(), kmDir(t)
	gone, added := newKMKey(t, "km-startup", 0), newKMKey(t, "km-startup", 1)
	s := startKM(t, options{keys: dir, data: data})
	s.waitReady()
	body := importBody(t, []string{gone.keystore(t)}, []string{kmPassword},
		interchangeDoc(goldenGVR(t), historyEntry(gone.pubkey, []uint64{9}, 0, 0)))
	if code, r, out := s.km("POST", body); code != 200 || r.Data[0].Status != "imported" {
		t.Fatalf("import: %d %s", code, out)
	}
	s.stop()

	// Standard-KDF keystores, decrypted one at a time, keep the next
	// startup load busy for seconds.
	slowKeys(t, dir, "km-startup-slow", 4)
	s = startKM(t, options{keys: dir, data: data, global: []string{"--signer-load-parallelism=1"}})
	loading := func() bool {
		code, _, _ := s.do(request{path: "/upcheck"})
		return code == 503
	}
	if !loading() {
		t.Fatal("the signer was ready before the test could reach the startup load")
	}
	code, r, out := s.km("DELETE", deleteBody(gone.pubkey))
	if code != 200 || r.Data[0].Status != "deleted" || !strings.Contains(r.SlashingProtection, gone.pubkey[2:]) {
		t.Fatalf("delete during the load: %d %s", code, out)
	}
	code, r, out = s.km("POST", importBody(t, []string{added.keystore(t)}, []string{kmPassword}, ""))
	if code != 200 || r.Data[0].Status != "imported" {
		t.Fatalf("import during the load: %d %s", code, out)
	}
	if !loading() {
		t.Fatal("the startup load ended before the delete and the import were done; the test proves nothing")
	}
	s.waitReadyWithin(3 * time.Minute)

	_, list, _ := s.km("GET", "")
	if keys := list.pubkeys(); slices.Contains(keys, gone.pubkey) || !slices.Contains(keys, added.pubkey) || len(keys) != 5 {
		t.Fatalf("after the load: %d keys, deleted listed %v, imported listed %v", len(keys),
			slices.Contains(keys, gone.pubkey), slices.Contains(keys, added.pubkey))
	}
	if code, _ := s.post("/api/v1/consensus/sign/"+gone.pubkey, s.signToken(), selectionProof(t)); code != 404 {
		t.Fatalf("the deleted key signs: %d", code)
	}
	if code, _ := s.post("/api/v1/consensus/sign/"+added.pubkey, s.signToken(), selectionProof(t)); code != 200 {
		t.Fatalf("the imported key does not sign: %d", code)
	}
	names := dirNames(t, dir)
	if slices.Contains(names, gone.stem+".yaml") || !slices.Contains(names, added.stem+".yaml") {
		t.Fatalf("files %v", names)
	}
	s.stop()
	if st := storeStatus(t, data, gone.pubkey); !st.Registered || st.Enabled {
		t.Fatalf("deleted key %+v", st)
	}
	if st := storeStatus(t, data, added.pubkey); !st.Enabled {
		t.Fatalf("imported key %+v", st)
	}
}

// A key that `consensus disable-validator` disabled keeps its keymanager
// files, so it is loaded again after the restart: an import of its keystore
// enables it, and the next import is a duplicate.
func TestKeymanagerImportEnablesADisabledKey(t *testing.T) {
	data, dir := t.TempDir(), kmDir(t)
	k := newKMKey(t, "km-disabled", 0)
	body := importBody(t, []string{k.keystore(t)}, []string{kmPassword}, "")
	s := startKM(t, options{keys: dir, data: data})
	s.waitReady()
	if code, r, out := s.km("POST", body); code != 200 || r.Data[0].Status != "imported" {
		t.Fatalf("import: %d %s", code, out)
	}
	s.stop()
	if code, out := runOffline(t, "--data-path="+data, "consensus", "disable-validator", "--key="+k.pubkey); code != 0 {
		t.Fatalf("disable-validator: exit %d %s", code, out)
	}

	s = startKM(t, options{keys: dir, data: data})
	s.waitReady()
	if code, reason := s.sign(t, k.pubkey, goldenAttestation(t)); code != 412 || reason != "VALIDATOR_DISABLED" {
		t.Fatalf("attestation of the disabled key: %d %s", code, reason)
	}
	for _, want := range []string{"imported", "duplicate"} {
		if code, r, out := s.km("POST", body); code != 200 || r.Data[0].Status != want {
			t.Fatalf("import, want %s: %d %s", want, code, out)
		}
	}
	if code, reason := s.sign(t, k.pubkey, goldenAttestation(t)); code != 200 {
		t.Fatalf("attestation after the import: %d %s", code, reason)
	}
	s.stop()
	if st := storeStatus(t, data, k.pubkey); !st.Enabled {
		t.Fatalf("%+v", st)
	}
}
