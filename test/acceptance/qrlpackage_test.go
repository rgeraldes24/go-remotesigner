// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package acceptance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystoretest"
)

// The keys qrl-package gives a validator client's signer. The package's
// keystore generator runs the deposit CLI with --lightkdf and the password
// file qrysm-password.txt, which echo writes ("password" and a line feed,
// mode 0644). That fills node-<i>-keystores/validator_keys/ with one
// keystore-<path>-<unix>.json per validator (compact JSON, version 0, a 0x
// pubkey, Argon2id t=8, m=4 MiB, p=1) and a deposit_data-<unix>.json. The
// signer's files are then prepared in one shell step:
//
//	mkdir -p /out/signer/keystores /out/vc
//	cp "$src"/keystore-*.json /out/signer/keystores/            # not deposit_data-*.json
//	cp /qrysm-password/qrysm-password.txt /out/signer/password.txt
//	jq -r .pubkey /out/signer/keystores/*.json | sort > /out/vc/keys.txt
//	chmod 0700 /out/signer /out/signer/keystores
//	chmod 0600 /out/signer/password.txt /out/signer/keystores/*.json
//
// and the signer runs with, after "consensus",
//
//	--keystores-path=/remote-signer/keystores
//	--keystores-password-file=/remote-signer/password.txt
//
// where /remote-signer is /out/signer mounted.

// qrlPackageValidators is the validator count of qrl-tests' single profile.
const qrlPackageValidators = 64

// depositOutput writes what the package's keystore generator leaves for
// one participant and returns validator_keys/ and qrysm-password.txt.
func depositOutput(t *testing.T, n int) (validatorKeys, passwordFile string) {
	t.Helper()
	root := t.TempDir()
	validatorKeys = filepath.Join(root, "node-0-keystores", "validator_keys")
	if err := os.MkdirAll(validatorKeys, 0o755); err != nil {
		t.Fatal(err)
	}
	sealer, err := keystoretest.NewSealer("password", keystoretest.Light)
	if err != nil {
		t.Fatal(err)
	}
	const unix = 1760000000
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data, err := sealer.DepositCLI(keystoretest.Seed(t.Name(), i), i, true)
			if err == nil {
				err = os.WriteFile(filepath.Join(validatorKeys, keystoretest.DepositFileName(i, unix)), data, 0o644)
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
	// The deposit data is a JSON list, not a keystore.
	deposit := fmt.Sprintf(`[{"pubkey":"%s","amount":40000000000000,"fork_version":"0x000000fd"}]`, strings.Repeat("ab", 2592))
	if err := os.WriteFile(filepath.Join(validatorKeys, fmt.Sprintf("deposit_data-%d.json", unix)), []byte(deposit), 0o644); err != nil {
		t.Fatal(err)
	}
	passwordFile = filepath.Join(root, "qrysm-password.txt")
	if err := os.WriteFile(passwordFile, []byte("password\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(passwordFile, 0o644); err != nil { // as echo leaves it, whatever the umask
		t.Fatal(err)
	}
	return validatorKeys, passwordFile
}

// prepareSigner is the package's shell step: it returns /out/signer and
// the sorted keys of /out/vc/keys.txt.
func prepareSigner(t *testing.T, validatorKeys, passwordFile string) (string, []string) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "signer")
	keystores := filepath.Join(out, "keystores")
	if err := os.MkdirAll(keystores, 0o755); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(validatorKeys, "keystore-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var ks struct{ Pubkey string }
		if err := json.Unmarshal(data, &ks); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, ks.Pubkey)
		dst := filepath.Join(keystores, filepath.Base(f))
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	slices.Sort(keys)
	pw, err := os.ReadFile(passwordFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "password.txt"), pw, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{out, keystores} {
		if err := os.Chmod(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return out, keys
}

func keystoresHealth(t *testing.T, s *signer) (int, string) {
	t.Helper()
	code, body, _ := s.do(request{path: "/healthcheck", token: s.signToken()})
	var h struct {
		Checks []struct {
			ID     string
			Status string
			Data   map[string]int
		}
	}
	if err := json.Unmarshal([]byte(body), &h); err != nil {
		t.Fatalf("healthcheck %d %s", code, body)
	}
	for _, c := range h.Checks {
		if c.ID == "keys-check/keystores-bulk-loading" {
			return code, fmt.Sprintf("%s keys-loaded=%d error-count=%d", c.Status, c.Data["keys-loaded"], c.Data["error-count"])
		}
	}
	t.Fatalf("no keystore check: %s", body)
	return 0, ""
}

// The layout qrl-package prepares loads with the flags it passes: every
// validator's key, exactly the keys of the validator client's key file, is
// ready within the package's two-minute readiness timeout, signs, and
// nothing is refused.
func TestKeystoresQRLPackageLayout(t *testing.T) {
	validatorKeys, passwordFile := depositOutput(t, qrlPackageValidators)
	out, keys := prepareSigner(t, validatorKeys, passwordFile)
	if len(keys) != qrlPackageValidators {
		t.Fatalf("keys.txt holds %d keys", len(keys))
	}
	s := start(t, options{consensus: []string{
		"--keystores-path=" + filepath.Join(out, "keystores"),
		"--keystores-password-file=" + filepath.Join(out, "password.txt"),
	}})
	ready := s.waitReadyWithin(2 * time.Minute)
	t.Logf("%d light keystores ready after %v", qrlPackageValidators, ready.Round(time.Millisecond))

	if got := s.publicKeys(); !slices.Equal(got, keys) {
		t.Fatalf("publicKeys: %d keys, want the %d of keys.txt", len(got), len(keys))
	}
	body := selectionProof(t)
	for _, pk := range keys {
		if code, resp := s.post("/api/v1/consensus/sign/"+pk, s.signToken(), body); code != 200 {
			t.Fatalf("sign with %.20s: %d %s", pk, code, resp)
		}
	}
	if code, h := keystoresHealth(t, s); code != 200 || h != fmt.Sprintf("UP keys-loaded=%d error-count=0", qrlPackageValidators) {
		t.Fatalf("healthcheck: %d %s", code, h)
	}
	if out := s.output.String(); strings.Contains(out, "level=error") || strings.Contains(out, "A secret file is readable") {
		t.Errorf("the signer refused or warned about a file:\n%s", out)
	}
}

// The package's layout on a running signer, with its one shared password
// file. When the password file becomes readable by other users, a reload
// refuses it as a whole: every key stays loaded and signs attestations (no
// key is disabled), the reload ends completed_with_errors and the keystore
// check is DOWN with one error. After the mode is fixed, a reload completes
// without a single decrypt, and every key still signs.
func TestKeystoresQRLPackageSharedPasswordRefusedOnReload(t *testing.T) {
	const n = 8
	validatorKeys, passwordFile := depositOutput(t, n)
	out, keys := prepareSigner(t, validatorKeys, passwordFile)
	password := filepath.Join(out, "password.txt")
	// Written well before the signer starts, so that the startup load
	// records versions the reloads can compare with.
	old := time.Now().Add(-time.Hour)
	files, err := filepath.Glob(filepath.Join(out, "keystores", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range append(files, password) {
		if err := os.Chtimes(f, old, old); err != nil {
			t.Fatal(err)
		}
	}
	s := start(t, options{consensus: []string{
		"--keystores-path=" + filepath.Join(out, "keystores"),
		"--keystores-password-file=" + password,
	}})
	s.waitReadyWithin(2 * time.Minute)
	att := goldenAttestation(t)
	signAll := func(when string) {
		t.Helper()
		if got := s.publicKeys(); !slices.Equal(got, keys) {
			t.Fatalf("%s: publicKeys lists %d keys, want the %d of keys.txt", when, len(got), len(keys))
		}
		for _, pk := range keys {
			if code, resp := s.post("/api/v1/consensus/sign/"+pk, s.signToken(), att); code != 200 {
				t.Fatalf("%s: attestation with %.20s: %d %s", when, pk, code, resp)
			}
		}
	}
	signAll("after the startup load")
	if d := s.loadDecrypts(1); d != n {
		t.Fatalf("the startup load ran %d decrypts, want %d", d, n)
	}

	if err := os.Chmod(password, 0o644); err != nil {
		t.Fatal(err)
	}
	s.reload("completed_with_errors", time.Minute)
	signAll("after the refusal")
	if code, h := keystoresHealth(t, s); code != 503 || h != fmt.Sprintf("DOWN keys-loaded=%d error-count=1", n) {
		t.Fatalf("healthcheck after the refusal: %d %s", code, h)
	}
	if !strings.Contains(s.output.String(), "readable by group or other users") {
		t.Error("the refusal is not logged")
	}

	if err := os.Chmod(password, 0o600); err != nil {
		t.Fatal(err)
	}
	s.reload("completed", time.Minute)
	if d := s.loadDecrypts(3); d != 0 {
		t.Errorf("the reload after the fix ran %d decrypts, want 0", d)
	}
	signAll("after the fix")
	if code, h := keystoresHealth(t, s); code != 200 || h != fmt.Sprintf("UP keys-loaded=%d error-count=0", n) {
		t.Fatalf("healthcheck after the fix: %d %s", code, h)
	}
}

// What the package's preparation step avoids. Pointed at validator_keys/
// itself, the signer treats every *.json file as a keystore, as Web3Signer
// does: the deposit data fails to load and is reported, while every key
// still loads. And the password file as echo writes it (0644) is refused
// under --strict-file-permissions, the default, so no key loads; with
// --strict-file-permissions=false it loads with a warning.
func TestKeystoresQRLPackageUnprepared(t *testing.T) {
	validatorKeys, passwordFile := depositOutput(t, 4)
	_, keys := prepareSigner(t, validatorKeys, passwordFile)
	safePassword := filepath.Join(t.TempDir(), "password.txt")
	if err := os.WriteFile(safePassword, []byte("password\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("deposit data in the keystore directory", func(t *testing.T) {
		s := start(t, options{consensus: []string{"--keystores-path=" + validatorKeys,
			"--keystores-password-file=" + safePassword}})
		s.waitReadyWithin(time.Minute)
		if got := s.publicKeys(); !slices.Equal(got, keys) {
			t.Fatalf("publicKeys: %d keys, want %d", len(got), len(keys))
		}
		if code, h := keystoresHealth(t, s); code != 503 || h != "DOWN keys-loaded=4 error-count=1" {
			t.Fatalf("healthcheck: %d %s", code, h)
		}
		if st := s.reloadStatus(); st["status"] != "completed_with_errors" {
			t.Fatalf("GET /reload: %v", st)
		}
		if !strings.Contains(s.output.String(), "deposit_data-1760000000.json") {
			t.Error("the refused deposit data file is not named in the log")
		}
	})

	t.Run("password file as echo writes it", func(t *testing.T) {
		flags := []string{"--keystores-path=" + validatorKeys, "--keystores-password-file=" + passwordFile}
		s := start(t, options{consensus: flags})
		s.waitReadyWithin(time.Minute)
		if got := s.publicKeys(); len(got) != 0 {
			t.Fatalf("%d keys loaded with a world-readable password file", len(got))
		}
		if code, h := keystoresHealth(t, s); code != 503 || h != "DOWN keys-loaded=0 error-count=1" {
			t.Fatalf("healthcheck: %d %s", code, h)
		}
		if !strings.Contains(s.output.String(), "readable by group or other users") {
			t.Error("the refusal is not logged")
		}

		lax := start(t, options{global: []string{"--strict-file-permissions=false"}, consensus: flags})
		lax.waitReadyWithin(time.Minute)
		if got := lax.publicKeys(); !slices.Equal(got, keys) {
			t.Fatalf("--strict-file-permissions=false: %d keys, want %d", len(got), len(keys))
		}
		if !strings.Contains(lax.output.String(), "A secret file is readable by its group or other users") {
			t.Error("no warning for the world-readable password file")
		}
	})
}
