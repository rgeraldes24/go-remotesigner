// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package acceptance

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystore/qrlv1"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystoretest"
	"github.com/rgeraldes24/go-remotesigner/internal/vectors"
)

// keystoreSet is a directory of deposit CLI keystores sharing one password.
type keystoreSet struct {
	dir      string // the keystores
	password string // the shared password file
	sealer   *keystoretest.Sealer
	pubkeys  []string // 0x, of the keystores written with a pubkey
}

// newKeystoreSet makes the qrl-package layout under a new directory:
// keystores/ (0700) and password.txt ("<password>\n", 0600).
func newKeystoreSet(t *testing.T, password string, kdf qrlv1.KDF) *keystoreSet {
	t.Helper()
	root := t.TempDir()
	ks := &keystoreSet{dir: filepath.Join(root, "keystores")}
	if err := os.Mkdir(ks.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	var err error
	if ks.password, err = keystoretest.WriteFile(root, "password.txt", []byte(password+"\n")); err != nil {
		t.Fatal(err)
	}
	if ks.sealer, err = keystoretest.NewSealer(password, kdf); err != nil {
		t.Fatal(err)
	}
	return ks
}

// add writes keystores first..first+n-1 in parallel; withPubkey also
// derives and records their public keys.
func (ks *keystoreSet) add(t *testing.T, tag string, first, n int, withPubkey bool) {
	t.Helper()
	pubkeys := make([]string, n)
	var wg sync.WaitGroup
	errs := make(chan error, n)
	sem := make(chan struct{}, 8)
	for i := range n {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			seed := keystoretest.Seed(tag, first+i)
			data, err := ks.sealer.DepositCLI(seed, first+i, withPubkey)
			if err == nil {
				_, err = keystoretest.WriteFile(ks.dir, keystoretest.DepositFileName(first+i, 1760000000), data)
			}
			if err == nil && withPubkey {
				var pk string
				pk, err = keystoretest.PublicKeyHex(seed)
				pubkeys[i] = "0x" + pk
			}
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if withPubkey {
		ks.pubkeys = append(ks.pubkeys, pubkeys...)
	}
}

func (ks *keystoreSet) flags() []string {
	return []string{"--keystores-path=" + ks.dir, "--keystores-password-file=" + ks.password}
}

// waitReadyWithin waits up to d for /upcheck 200 and returns the time from
// the start of the process.
func (s *signer) waitReadyWithin(d time.Duration) time.Duration {
	s.t.Helper()
	deadline := time.Now().Add(d)
	for {
		select {
		case <-s.done:
			s.t.Fatalf("signer exited: %v\n%s", s.waitErr, s.output.String())
		default:
		}
		if code, _, _ := s.do(request{path: "/upcheck"}); code == 200 {
			return time.Since(s.started)
		}
		if time.Now().After(deadline) {
			s.t.Fatalf("not ready after %v\n%s", d, s.output.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// publicKeys returns the signer's /publicKeys.
func (s *signer) publicKeys() []string {
	s.t.Helper()
	code, body, _ := s.do(request{path: "/api/v1/consensus/publicKeys", token: s.signToken()})
	var pks []string
	if err := json.Unmarshal([]byte(body), &pks); code != 200 || err != nil {
		s.t.Fatalf("publicKeys: %d %v", code, err)
	}
	return pks
}

// reload posts /reload with the admin token and waits for the status want.
func (s *signer) reload(want string, within time.Duration) {
	s.t.Helper()
	if code, body, _ := s.do(request{method: "POST", path: "/reload", token: s.adminToken(),
		contentType: "application/json"}); code != 202 {
		s.t.Fatalf("POST /reload: %d %s", code, body)
	}
	s.waitReloadStatus(want, within)
}

func (s *signer) waitReloadStatus(want string, within time.Duration) {
	s.t.Helper()
	deadline := time.Now().Add(within)
	for {
		_, body, _ := s.do(request{path: "/reload", token: s.signToken()})
		var st struct{ Status string }
		_ = json.Unmarshal([]byte(body), &st)
		if st.Status == want {
			return
		}
		if time.Now().After(deadline) {
			s.t.Fatalf("reload status %s, want %s\n%s", body, want, s.output.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// goldenRequest is the typical minimal-preset golden request of type typ.
// The request names no key, so any loaded key can sign it.
func goldenRequest(t *testing.T, typ string) []byte {
	t.Helper()
	for _, c := range vectors.Signing(t) {
		if c.Preset == "minimal" && c.Type == typ && c.Name == "typical" {
			return c.RequestJSON
		}
	}
	t.Fatalf("no golden %s request", typ)
	return nil
}

// selectionProof is a golden AGGREGATION_SLOT request, which a disabled key
// still signs.
func selectionProof(t *testing.T) []byte { return goldenRequest(t, "AGGREGATION_SLOT") }

// goldenAttestation is a golden ATTESTATION request, which a disabled key
// answers with 412 VALIDATOR_DISABLED. Signing it again with the same key
// is a repeat that slashing protection allows.
func goldenAttestation(t *testing.T) []byte { return goldenRequest(t, "ATTESTATION") }

// loadDecrypts waits until the signer has logged n "Keys loaded" lines and
// returns the number of keystore decrypts the nth reports.
func (s *signer) loadDecrypts(n int) int {
	s.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if all := loadedRE.FindAllStringSubmatch(s.output.String(), -1); len(all) >= n {
			d, err := strconv.Atoi(all[n-1][2])
			if err != nil {
				s.t.Fatal(err)
			}
			return d
		}
		if time.Now().After(deadline) {
			s.t.Fatalf("fewer than %d \"Keys loaded\" lines:\n%s", n, s.output.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// peakRSS samples the RSS of pid until stop is closed and returns the
// largest sample in KiB.
func peakRSS(pid int, stop <-chan struct{}) <-chan int {
	out := make(chan int, 1)
	go func() {
		peak := 0
		for {
			if b, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(pid)).Output(); err == nil {
				if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
					peak = max(peak, n)
				}
			}
			select {
			case <-stop:
				out <- peak
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}()
	return out
}

// 4,096 light-KDF keystores, the qrysm e2e's key count, load under a
// GOMEMLIMIT of 768 MiB: the Argon2id budget is sized from the limit, the
// process stays below it, and every key is served.
func TestKeystores4096UnderGOMEMLIMIT(t *testing.T) {
	const n, limitMiB = 4096, 768
	ks := newKeystoreSet(t, "password", keystoretest.Light)
	ks.add(t, t.Name(), 0, n, false)
	s := launch(t, options{consensus: ks.flags(), env: []string{"GOMEMLIMIT=" + strconv.Itoa(limitMiB) + "MiB"}})
	stop := make(chan struct{})
	peak := peakRSS(s.cmd.Process.Pid, stop)
	// The ports file appears at once; then wait for the load.
	for s.port == "" {
		s.port = portOf(t, s)
	}
	s.base = "http://localhost:" + s.port
	ready := s.waitReadyWithin(10 * time.Minute)
	close(stop)
	peakKiB := <-peak
	t.Logf("%d light keystores ready after %v; peak RSS %d MiB under GOMEMLIMIT=%dMiB", n, ready.Round(time.Millisecond),
		peakKiB>>10, limitMiB)
	if peakKiB > limitMiB<<10 {
		t.Errorf("peak RSS %d MiB is above GOMEMLIMIT %d MiB", peakKiB>>10, limitMiB)
	}
	if got := len(s.publicKeys()); got != n {
		t.Fatalf("%d keys served, want %d", got, n)
	}
	if out := s.output.String(); !strings.Contains(out, "budget-source=GOMEMLIMIT") || !strings.Contains(out, "budget-mib=256") {
		t.Errorf("the Argon2id budget was not sized from GOMEMLIMIT:\n%.2000s", out)
	}
	code, body, _ := s.do(request{path: "/healthcheck", token: s.signToken()})
	if code != 200 || !strings.Contains(body, `"keys-check/keystores-bulk-loading","status":"UP","data":{"error-count":0,"keys-loaded":4096}`) {
		t.Fatalf("healthcheck: %d %s", code, body)
	}
}

// portOf reads the HTTP port from the ports file, or "" while it is not
// there yet.
func portOf(t *testing.T, s *signer) string {
	t.Helper()
	select {
	case <-s.done:
		t.Fatalf("signer exited: %v\n%s", s.waitErr, s.output.String())
	default:
	}
	data, err := os.ReadFile(filepath.Join(s.data, "remotesigner.ports"))
	if err != nil {
		time.Sleep(5 * time.Millisecond)
		return ""
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if p, ok := strings.CutPrefix(line, "http-port="); ok {
			return p
		}
	}
	return ""
}

// Deposit CLI keystores, one of them the deposit CLI's own output (the
// golden vector, written by its Encrypt), with the password the CLI was
// given in one file with a trailing line feed: every key loads and signs,
// and nothing is refused.
func TestKeystoresDepositCLIOutput(t *testing.T) {
	var golden vectors.KeystoreCase
	for _, c := range vectors.Keystores(t) {
		if c.File == "deposit-cli-light.json" {
			golden = c
		}
	}
	ks := newKeystoreSet(t, golden.Password, keystoretest.Light)
	if _, err := keystoretest.WriteFile(ks.dir, keystoretest.DepositFileName(0, 1760000000),
		vectors.Raw(t, "keystores/deposit-cli-light.json")); err != nil {
		t.Fatal(err)
	}
	ks.pubkeys = append(ks.pubkeys, golden.Pubkey)
	ks.add(t, t.Name(), 1, 3, true)
	s := start(t, options{consensus: ks.flags()})
	s.waitReadyWithin(time.Minute)

	got := s.publicKeys()
	want := slices.Clone(ks.pubkeys)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("publicKeys: %d keys, want the %d keystores' keys", len(got), len(want))
	}
	body := selectionProof(t)
	for _, pk := range ks.pubkeys {
		if code, out := s.post("/api/v1/consensus/sign/"+pk, s.signToken(), body); code != 200 {
			t.Fatalf("sign with %.20s: %d %s", pk, code, out)
		}
	}
	code, out, _ := s.do(request{path: "/healthcheck", token: s.signToken()})
	if code != 200 || !strings.Contains(out, `"keys-check/keystores-bulk-loading","status":"UP","data":{"error-count":0,"keys-loaded":4}`) {
		t.Fatalf("healthcheck: %d %s", code, out)
	}
}

// A world-readable password file is refused on reload, and the key it
// guards stays loaded from the previous load: it still signs attestations,
// so it is not disabled (a disabled key answers 412), and the keystore
// health check reports the error. After the mode is fixed, a reload
// completes and the key signs, with no re-import. A keystore removed from
// the directory answers 404 after the reload; POST /reload with the sign
// token is 403.
func TestKeystoresReloadRefusalAndRemoval(t *testing.T) {
	ks := newKeystoreSet(t, "password", keystoretest.Cheapest)
	pwDir := t.TempDir()
	ks.add(t, t.Name(), 0, 3, true)
	for i := range 3 {
		name := strings.TrimSuffix(keystoretest.DepositFileName(i, 1760000000), ".json") + ".txt"
		if _, err := keystoretest.WriteFile(pwDir, name, []byte("password")); err != nil {
			t.Fatal(err)
		}
	}
	s := start(t, options{consensus: []string{"--keystores-path=" + ks.dir, "--keystores-passwords-path=" + pwDir}})
	s.waitReadyWithin(time.Minute)
	att := goldenAttestation(t)
	signs := func(pk string, want int) {
		t.Helper()
		if code, out := s.post("/api/v1/consensus/sign/"+pk, s.signToken(), att); code != want {
			t.Fatalf("attestation with %.20s: %d %s, want %d", pk, code, out, want)
		}
	}
	guarded, removed := ks.pubkeys[0], ks.pubkeys[2]
	signs(guarded, 200)

	code, out, _ := s.do(request{method: "POST", path: "/reload", token: s.signToken(), contentType: "application/json"})
	if code != 403 || reasonOf(t, out) != "FORBIDDEN_SCOPE" {
		t.Fatalf("POST /reload with the sign token: %d %s", code, out)
	}

	pw0 := filepath.Join(pwDir, strings.TrimSuffix(keystoretest.DepositFileName(0, 1760000000), ".json")+".txt")
	time.Sleep(10 * time.Millisecond)
	if err := os.Chmod(pw0, 0o644); err != nil {
		t.Fatal(err)
	}
	s.reload("completed_with_errors", time.Minute)
	signs(guarded, 200)
	code, out, _ = s.do(request{path: "/healthcheck", token: s.signToken()})
	if code != 503 || !strings.Contains(out, `"keys-check/keystores-bulk-loading","status":"DOWN","data":{"error-count":1,"keys-loaded":3}`) {
		t.Fatalf("healthcheck after the refusal: %d %s", code, out)
	}
	if !strings.Contains(s.output.String(), "readable by group or other users") {
		t.Error("the refusal is not logged")
	}

	if err := os.Chmod(pw0, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(ks.dir, keystoretest.DepositFileName(2, 1760000000))); err != nil {
		t.Fatal(err)
	}
	s.reload("completed", time.Minute)
	signs(guarded, 200)
	signs(removed, 404)
	if got := len(s.publicKeys()); got != 2 {
		t.Fatalf("%d keys after removing one keystore", got)
	}
	if code, _, _ := s.do(request{path: "/healthcheck"}); code != 200 {
		t.Fatalf("healthcheck after the fix: %d", code)
	}
}

// consensus disable-validator persists enabled=false in a stopped signer's
// store; after a restart the key's attestations are refused with 412
// VALIDATOR_DISABLED, while reloads never disable a key.
func TestDisableValidatorOffline(t *testing.T) {
	keysDir, data := t.TempDir(), t.TempDir()
	keys := writeInteropKeys(t, keysDir)
	s := start(t, options{keys: keysDir, data: data})
	s.waitReady()
	s.signal(syscall.SIGTERM)
	if code := s.exitCode(15 * time.Second); code != 0 {
		t.Fatalf("exit %d", code)
	}
	var att vectors.SignCase
	for _, c := range vectors.Signing(t) {
		if c.Preset == "minimal" && c.Type == "ATTESTATION" && c.Name == "typical" {
			att = c
		}
	}
	if code, out := runOffline(t, "--data-path="+data, "consensus", "disable-validator", "--key="+att.Pubkey); code != 0 ||
		!strings.Contains(out, "412 VALIDATOR_DISABLED") {
		t.Fatalf("disable-validator: exit %d %s", code, out)
	}
	s = start(t, options{keys: keysDir, data: data})
	s.waitReady()
	code, out := s.post("/api/v1/consensus/sign/"+att.Pubkey, s.signToken(), att.RequestJSON)
	if code != 412 || reasonOf(t, out) != "VALIDATOR_DISABLED" {
		t.Fatalf("attestation of a disabled key: %d %s", code, out)
	}
	if code, _ := s.post("/api/v1/consensus/sign/"+att.Pubkey, s.signToken(), selectionProof(t)); code != 200 {
		t.Fatalf("selection proof of a disabled key: %d", code)
	}
	for _, k := range keys {
		if k.Pubkey == att.Pubkey {
			continue
		}
		if code, out := s.post("/api/v1/consensus/sign/"+k.Pubkey, s.signToken(), att.RequestJSON); code != 200 {
			t.Fatalf("attestation of key %d, which is still enabled: %d %s", k.Index, code, out)
		}
	}
}
