// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/api/ops"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/signingroot"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystoretest"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/boltstore"
	"github.com/rgeraldes24/go-remotesigner/internal/vectors"
)

// reload posts /reload and waits until it reports want.
func (r *running) reload(t *testing.T, want string) {
	t.Helper()
	if code, body := r.do(t, http.MethodPost, "/reload", r.admin); code != 202 {
		t.Fatalf("POST /reload: %d %s", code, body)
	}
	r.waitReload(t, want)
}

// health returns the healthcheck checks by id.
func (r *running) health(t *testing.T) (int, map[string]map[string]any) {
	t.Helper()
	code, body := r.do(t, http.MethodGet, "/healthcheck", r.sign)
	conforms(t, "HealthCheck", body)
	var h struct {
		Checks []map[string]any
	}
	if err := json.Unmarshal(body, &h); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, c := range h.Checks {
		out[c["id"].(string)] = c
	}
	return code, out
}

// storeStatus opens the stopped signer's store and returns a key's status.
func storeStatus(t *testing.T, path, pubkey string) slashing.ValidatorStatus {
	t.Helper()
	s, err := boltstore.Open(path, boltstore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	pk, err := hex.DecodeString(strings.TrimPrefix(pubkey, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := s.ValidatorStatus(context.Background(), slashing.KeyIDOf(pk))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// A reload while requests sign: the key that stays signs throughout, the
// removed key answers 200 until the reload swaps the key set and 404
// UNKNOWN_KEY after it, never anything else, and the race detector sees no
// race between signing, eviction and zeroization. The removed key's RANDAO
// reveals answer 404 too. It stays registered and enabled in slashing
// protection: once its file is back, a reload loads it again and its next
// RANDAO layer is released from the frontier it had, with no import.
func TestRunReloadDuringSigning(t *testing.T) {
	cfg := baseConfig(t)
	writeInteropKeys(t, cfg.KeyConfigPath)
	keys := vectors.Keys(t)
	stay, gone := keys[0], keys[1]
	r := start(t, cfg)
	r.waitReady(t)

	sel := goldenCase(t, "minimal", signingroot.AggregationSlot, "typical")
	// sign may run on any goroutine: it reports a transport error as 0.
	sign := func(pubkey string) int {
		req, err := http.NewRequest(http.MethodPost, r.base+"/api/v1/consensus/sign/"+pubkey, bytes.NewReader(sel.RequestJSON))
		if err != nil {
			return 0
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+r.sign)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if sign(stay.Pubkey) != 200 || sign(gone.Pubkey) != 200 {
		t.Fatal("signing before the reload failed")
	}
	fi, slot := e2eForkInfo(t), nowSlot()
	if code, body := r.post(t, revealPath(gone.Pubkey), r.sign, revealReq(slot, gone.RandaoCommitment, fi)); code != 200 {
		t.Fatalf("first reveal of the key to remove: %d %s", code, body)
	}

	var (
		stop     atomic.Bool
		wg       sync.WaitGroup
		mu       sync.Mutex
		goneSeen = map[int]int{}
		bad      []string
	)
	for w := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				k := stay
				if w%2 == 1 {
					k = gone
				}
				code := sign(k.Pubkey)
				mu.Lock()
				switch {
				case k == stay && code != 200:
					bad = append(bad, fmt.Sprintf("staying key: %d", code))
				case k == gone && code != 200 && code != 404:
					bad = append(bad, fmt.Sprintf("removed key: %d", code))
				case k == gone:
					goneSeen[code]++
				}
				mu.Unlock()
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	goneFile := filepath.Join(cfg.KeyConfigPath, fmt.Sprintf("interop-%d.yaml", gone.Index))
	goneContent, err := os.ReadFile(goneFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(goneFile); err != nil {
		t.Fatal(err)
	}
	r.reload(t, "completed")
	time.Sleep(50 * time.Millisecond)
	stop.Store(true)
	wg.Wait()
	if len(bad) > 0 {
		t.Fatalf("unexpected answers during the reload: %v", bad[:min(len(bad), 5)])
	}
	if goneSeen[200] == 0 || goneSeen[404] == 0 {
		t.Fatalf("the removed key was never seen on both sides of the swap: %v", goneSeen)
	}
	code, body := r.post(t, "/api/v1/consensus/sign/"+gone.Pubkey, r.sign, sel.RequestJSON)
	if code != 404 || !strings.Contains(string(body), `"reason":"UNKNOWN_KEY"`) {
		t.Fatalf("removed key after the reload: %d %s", code, body)
	}
	conforms(t, "ErrorResponse", body)
	// The next layer, at a slot after the first reveal's and within the
	// reveal window however long the test ran.
	next := func() []byte { return revealReq(max(slot+1, nowSlot()), gone.RandaoFirstReveal, fi) }
	if code, body := r.post(t, revealPath(gone.Pubkey), r.sign, next()); code != 404 ||
		!strings.Contains(string(body), `"reason":"UNKNOWN_KEY"`) {
		t.Fatalf("RANDAO reveal of the removed key: %d %s", code, body)
	}

	if err := os.WriteFile(goneFile, goneContent, 0o600); err != nil {
		t.Fatal(err)
	}
	r.reload(t, "completed")
	if code, body := r.post(t, revealPath(gone.Pubkey), r.sign, next()); code != 200 {
		t.Fatalf("next RANDAO layer of the key loaded again: %d %s", code, body)
	}
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	if st := storeStatus(t, cfg.SlashingProtectionDB(), gone.Pubkey); !st.Registered || !st.Enabled {
		t.Fatalf("the removed key's slashing-protection row changed: %+v", st)
	}
}

// keystoreFixture writes deposit CLI keystores with per-key password files.
type keystoreFixture struct {
	dir, passwords string
	sealer         *keystoretest.Sealer
}

func newKeystoreFixture(t *testing.T) *keystoreFixture {
	t.Helper()
	s, err := keystoretest.NewSealer("secret", keystoretest.Cheapest)
	if err != nil {
		t.Fatal(err)
	}
	return &keystoreFixture{dir: t.TempDir(), passwords: t.TempDir(), sealer: s}
}

// add writes key i's keystore and password file and returns its 0x public
// key and the password file's path.
func (f *keystoreFixture) add(t *testing.T, i int) (pubkey, passwordFile string) {
	t.Helper()
	seed := keystoretest.Seed(t.Name(), i)
	data, err := f.sealer.DepositCLI(seed, i, false)
	if err != nil {
		t.Fatal(err)
	}
	name := keystoretest.DepositFileName(i, 1760000000)
	if _, err := keystoretest.WriteFile(f.dir, name, data); err != nil {
		t.Fatal(err)
	}
	pw, err := keystoretest.WriteFile(f.passwords, strings.TrimSuffix(name, ".json")+".txt", []byte("secret\n"))
	if err != nil {
		t.Fatal(err)
	}
	pk, err := keystoretest.PublicKeyHex(seed)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	for _, p := range []string{filepath.Join(f.dir, name), pw} {
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	return "0x" + pk, pw
}

// A keystore whose password file becomes world-readable is refused on the
// next reload, and its key stays loaded from the previous load: it still
// signs (no 412 VALIDATOR_DISABLED), and the keystore health check is DOWN
// with one error. After the mode is fixed, a reload completes, the check
// is UP again and the key signs, with no re-import.
func TestRunKeystoresPermissionRefusalKeepsKey(t *testing.T) {
	cfg := baseConfig(t)
	cfg.StrictFilePermissions = true
	f := newKeystoreFixture(t)
	cfg.Consensus.Keystores.Path, cfg.Consensus.Keystores.PasswordsPath = f.dir, f.passwords
	pk, pw := f.add(t, 0)
	other, _ := f.add(t, 1)
	writeKeyFile(t, cfg.KeyConfigPath, "raw.yaml", 9)
	r := start(t, cfg)
	r.waitReady(t)

	sel := goldenCase(t, "minimal", signingroot.AggregationSlot, "typical")
	signs := func(pubkey string) {
		t.Helper()
		if code, body := r.post(t, "/api/v1/consensus/sign/"+pubkey, r.sign, sel.RequestJSON); code != 200 {
			t.Fatalf("sign: %d %s", code, body)
		}
	}
	signs(pk)
	signs(other)
	code, checks := r.health(t)
	ks := checks[ops.CheckKeystoresBulkLoading]
	if code != 200 || ks["status"] != "UP" || fmt.Sprint(ks["data"]) != "map[error-count:0 keys-loaded:2]" ||
		fmt.Sprint(checks[ops.CheckConfigFilesLoading]["data"]) != "map[error-count:0 keys-loaded:1]" {
		t.Fatalf("health with keystores: %d %v", code, checks)
	}

	if err := os.Chmod(pw, 0o644); err != nil {
		t.Fatal(err)
	}
	r.reload(t, "completed_with_errors")
	signs(pk)
	code, checks = r.health(t)
	ks = checks[ops.CheckKeystoresBulkLoading]
	if code != 503 || ks["status"] != "DOWN" || fmt.Sprint(ks["data"]) != "map[error-count:1 keys-loaded:2]" ||
		checks[ops.CheckConfigFilesLoading]["status"] != "UP" {
		t.Fatalf("health after the refusal: %d %v", code, checks)
	}

	if err := os.Chmod(pw, 0o600); err != nil {
		t.Fatal(err)
	}
	r.reload(t, "completed")
	signs(pk)
	if code, checks = r.health(t); code != 200 || checks[ops.CheckKeystoresBulkLoading]["status"] != "UP" {
		t.Fatalf("health after the fix: %d %v", code, checks)
	}
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	if st := storeStatus(t, cfg.SlashingProtectionDB(), pk); !st.Registered || !st.Enabled {
		t.Fatalf("the refused key's slashing-protection row changed: %+v", st)
	}
}

// When the keystore directory cannot be read, every keystore keeps its key
// and the reload counts one error; a keystore removed from a readable
// directory is evicted, and a new one is added.
func TestRunKeystoresWholeFailureAndChanges(t *testing.T) {
	cfg := baseConfig(t)
	f := newKeystoreFixture(t)
	cfg.Consensus.Keystores.Path, cfg.Consensus.Keystores.PasswordsPath = f.dir, f.passwords
	a, _ := f.add(t, 0)
	b, _ := f.add(t, 1)
	r := start(t, cfg)
	r.waitReady(t)
	moved := f.dir + ".moved"
	if err := os.Rename(f.dir, moved); err != nil {
		t.Fatal(err)
	}
	r.reload(t, "completed_with_errors")
	if _, checks := r.health(t); fmt.Sprint(checks[ops.CheckKeystoresBulkLoading]["data"]) != "map[error-count:1 keys-loaded:2]" {
		t.Fatalf("health with an unreadable directory: %v", checks)
	}
	if err := os.Rename(moved, f.dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.dir, keystoretest.DepositFileName(1, 1760000000))); err != nil {
		t.Fatal(err)
	}
	c, _ := f.add(t, 2)
	r.reload(t, "completed")
	_, body := r.do(t, http.MethodGet, "/api/v1/consensus/publicKeys", r.sign)
	if s := string(body); !strings.Contains(s, a) || strings.Contains(s, b) || !strings.Contains(s, c) {
		t.Fatal("publicKeys after removing one keystore and adding another")
	}
}

// A reload that runs past --reload-timeout applies what it loaded and keeps
// the previous keys of everything else; the new keystores it did not reach
// are errors.
func TestRunReloadTimeout(t *testing.T) {
	cfg := baseConfig(t)
	cfg.ReloadTimeout = time.Nanosecond
	f := newKeystoreFixture(t)
	cfg.Consensus.Keystores.Path, cfg.Consensus.Keystores.PasswordsPath = f.dir, f.passwords
	a, _ := f.add(t, 0)
	r := start(t, cfg)
	r.waitReady(t) // the startup load is not bounded
	b, _ := f.add(t, 1)
	r.reload(t, "completed_with_errors")
	_, body := r.do(t, http.MethodGet, "/reload", r.sign)
	if !strings.Contains(string(body), "1 key loading error") {
		t.Fatalf("reload status %s", body)
	}
	_, body = r.do(t, http.MethodGet, "/api/v1/consensus/publicKeys", r.sign)
	if s := string(body); !strings.Contains(s, a) || strings.Contains(s, b) {
		t.Fatal("publicKeys after a timed-out reload")
	}
}
