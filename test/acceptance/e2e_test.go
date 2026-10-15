// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package acceptance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/vectors"
)

// harnessGenesis is the --network-genesis-time defaultArgs passes; the
// end-to-end network has 10 s slots.
const harnessGenesis = 1_760_000_000

func currentSlot() uint64 { return uint64(time.Now().Unix()-harnessGenesis) / 10 }

// writeInteropKeys writes the golden interop keys as file-raw key files.
func writeInteropKeys(t *testing.T, dir string) []vectors.Key {
	t.Helper()
	keys := vectors.Keys(t)
	for _, k := range keys {
		content := "type: file-raw\nkeyType: ML_DSA_87\nprivateKey: \"" + k.Seed + "\"\n"
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("interop-%d.yaml", k.Index)), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return keys
}

func (s *signer) post(path, token string, body []byte) (int, string) {
	s.t.Helper()
	code, out, _ := s.do(request{method: "POST", path: path, token: token, contentType: "application/json",
		body: bytes.NewReader(body)})
	return code, out
}

// reveal posts a RANDAO reveal request and returns the status and the
// reveal or the reason.
func (s *signer) reveal(pubkey string, slot uint64, commitment, forkInfo string) (int, string) {
	s.t.Helper()
	body := `{"slot":"` + strconv.FormatUint(slot, 10) + `","randao_commitment":"` + commitment + `","fork_info":` + forkInfo + `}`
	code, out := s.post("/api/v1/consensus/randao_reveal/"+pubkey, s.signToken(), []byte(body))
	if code != 200 {
		return code, reasonOf(s.t, out)
	}
	var r struct {
		Reveal string `json:"randao_reveal"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		s.t.Fatalf("reveal body %q: %v", out, err)
	}
	return code, r.Reveal
}

// runOffline runs an offline subcommand of the binary.
func runOffline(t *testing.T, args ...string) (int, string) {
	t.Helper()
	out, err := exec.Command(binary, args...).CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, string(out)
}

// The integration run: the binary with the interop keys signs one golden
// request of every type and drives the RANDAO reveal through first use, new
// layer, retry, refusal and admin reset; the metrics listener reports it
// all; after a restart the RANDAO state and the TOFU pin are still there;
// and the offline commands refuse a running signer's store and work on a
// stopped one.
func TestIntegrationEveryRequestType(t *testing.T) {
	keysDir, data := t.TempDir(), t.TempDir()
	keys := writeInteropKeys(t, keysDir)
	opts := options{keys: keysDir, data: data,
		global:    []string{"--metrics-enabled", "--metrics-port=0"},
		consensus: []string{"--voluntary-exit-signing-enabled", "--randao-full-scan-min-interval=1ms"}}
	s := start(t, opts)
	s.waitReady()
	tok := s.signToken()

	code, body, _ := s.do(request{path: "/api/v1/consensus/publicKeys", token: tok})
	var pks []string
	if err := json.Unmarshal([]byte(body), &pks); code != 200 || err != nil || len(pks) != len(keys) {
		t.Fatalf("publicKeys: %d %v %.100s", code, err, body)
	}
	code, body, _ = s.do(request{path: "/api/v1/consensus/capabilities", token: tok})
	if code != 200 || !strings.Contains(body, `"randao_reveal":true`) || !strings.Contains(body, `"VOLUNTARY_EXIT"`) {
		t.Fatalf("capabilities: %d %s", code, body)
	}

	// One golden request of every type, each verified under its key.
	types := map[string]bool{}
	var forkInfo string
	for _, c := range vectors.Signing(t) {
		if c.Preset != "minimal" || types[c.Type] {
			continue
		}
		types[c.Type] = true
		if forkInfo == "" {
			forkInfo = `{"fork":{"previous_version":"` + c.Network.GenesisForkVersion + `","current_version":"` +
				c.Network.GenesisForkVersion + `","epoch":"0"},"genesis_validators_root":"` + c.Network.GVR + `"}`
		}
		code, out := s.post("/api/v1/consensus/sign/"+c.Pubkey, tok, c.RequestJSON)
		if code != 200 {
			t.Fatalf("%s: %d %s", c.ID(), code, out)
		}
		var resp struct {
			Signature string `json:"signature"`
		}
		if err := json.Unmarshal([]byte(out), &resp); err != nil {
			t.Fatal(err)
		}
		pkb := vectors.Hex(t, c.Pubkey)
		pk, err := mldsa87.ParsePublicKey(pkb)
		if err != nil {
			t.Fatal(err)
		}
		root := vectors.Hex32(t, c.SigningRoot)
		if !mldsa87.Verify(&pk, root[:], vectors.Hex(t, resp.Signature)) {
			t.Fatalf("%s: the signature does not verify", c.ID())
		}
		if c.DeterministicSignature != "" && resp.Signature != c.DeterministicSignature {
			t.Fatalf("%s: not qrysm's deterministic signature", c.ID())
		}
	}
	if len(types) != 9 {
		t.Fatalf("signed %d types, want 9", len(types))
	}

	// RANDAO, as the qrysm VC drives it.
	k0, k1 := keys[0], keys[1]
	slot := currentSlot()
	if code, r := s.reveal(k0.Pubkey, slot, k0.RandaoCommitment, forkInfo); code != 200 || r != k0.RandaoFirstReveal {
		t.Fatalf("first use: %d %s", code, r)
	}
	code, next := s.reveal(k0.Pubkey, slot+1, k0.RandaoFirstReveal, forkInfo)
	if code != 200 {
		t.Fatalf("new layer: %d %s", code, next)
	}
	if code, r := s.reveal(k0.Pubkey, slot+1, k0.RandaoFirstReveal, forkInfo); code != 200 || r != next {
		t.Fatalf("retry: %d %s", code, r)
	}
	if code, r := s.reveal(k0.Pubkey, slot+1, next, forkInfo); code != 412 || r != "RANDAO_SLOT_NOT_INCREASING" {
		t.Fatalf("walking within a slot: %d %s", code, r)
	}
	if code, r := s.reveal(k1.Pubkey, slot+1, k0.RandaoCommitment, forkInfo); code != 422 || r != "RANDAO_UNKNOWN_COMMITMENT" {
		t.Fatalf("another key's commitment: %d %s", code, r)
	}
	if code, r := s.reveal(k1.Pubkey, slot+1, k1.RandaoCommitment, forkInfo); code != 200 || r != k1.RandaoFirstReveal {
		t.Fatalf("key 1 first use: %d %s", code, r)
	}

	// Admin reset: the sign token is refused, the admin token clears the
	// frontier, and the next reveal is a first use.
	reset := "/api/v1/consensus/randao_state/" + k0.Pubkey
	if code, body, _ := s.do(request{method: "DELETE", path: reset, token: tok}); code != 403 || reasonOf(t, body) != "FORBIDDEN_SCOPE" {
		t.Fatalf("sign token on the reset: %d %s", code, body)
	}
	if code, body, _ := s.do(request{method: "DELETE", path: reset, token: s.adminToken()}); code != 200 {
		t.Fatalf("reset: %d %s", code, body)
	}
	if code, r := s.reveal(k0.Pubkey, slot+1, next, forkInfo); code != 200 {
		t.Fatalf("first use after the reset: %d %s", code, r)
	}

	code, text := scrape(t, s.metricsPort(), "")
	if code != 200 {
		t.Fatalf("scrape: %d", code)
	}
	want := []string{
		`consensus_randao_reveals_total{result="first_use"} 3`,
		`consensus_randao_reveals_total{result="new_layer"} 1`,
		`consensus_randao_reveals_total{result="re_reveal"} 1`,
		`consensus_randao_reveals_total{result="refused"} 2`,
		`consensus_randao_reveals_total{result="gap_advanced"} 0`,
		`consensus_randao_reveals_total{result="error"} 0`,
		"consensus_randao_new_layer_rate_limited_total 0",
		"signing_verify_failures_total 0",
		"signing_keys_quarantined 0",
		"consensus_slashingprotection_permitted_signings_total 2",
	}
	for ty := range types {
		want = append(want, fmt.Sprintf(`signing_requests_total{result="ok",type=%q} 1`, ty))
	}
	for _, w := range want {
		if !strings.Contains(text, w) {
			t.Errorf("scrape lacks %s", w)
		}
	}
	if strings.Contains(text, `prevented_signings_total{reason="slashing_double_proposal"} 1`) || strings.Contains(text, `code="500"`) {
		t.Error("a prevented signing or a 5xx")
	}

	// The store is the signer's while it runs.
	if code, out := runOffline(t, "--data-path="+data, "consensus", "randao-state", "reset", "--key="+k1.Pubkey); code != 1 ||
		!strings.Contains(out, "stop the signer") {
		t.Fatalf("offline reset of a running signer's store: %d %s", code, out)
	}
	if code, out := runOffline(t, "--data-path="+data, "consensus", "migrate"); code != 1 || !strings.Contains(out, "stop the signer") {
		t.Fatalf("migrate of a running signer's store: %d %s", code, out)
	}

	s.signal(syscall.SIGTERM)
	if code := s.exitCode(15 * time.Second); code != 0 {
		t.Fatalf("exit %d", code)
	}

	// Restart: the bbolt frontier and the GVR pin survive, so key 1's
	// repeated first commitment is a re-reveal.
	s2 := start(t, opts)
	s2.waitReady()
	if code, r := s2.reveal(k1.Pubkey, currentSlot(), k1.RandaoCommitment, forkInfo); code != 200 || r != k1.RandaoFirstReveal {
		t.Fatalf("re-reveal after a restart: %d %s", code, r)
	}
	code, text = scrape(t, s2.metricsPort(), "")
	if code != 200 || !strings.Contains(text, `consensus_randao_reveals_total{result="re_reveal"} 1`) ||
		!strings.Contains(text, "consensus_randao_slow_path_scans_total 0") {
		t.Fatalf("after the restart, key 1's state was not read from the store:\n%s", text)
	}
	s2.signal(syscall.SIGTERM)
	if code := s2.exitCode(15 * time.Second); code != 0 {
		t.Fatalf("exit %d", code)
	}

	// Stopped: the offline commands work.
	if code, out := runOffline(t, "--data-path="+data, "consensus", "migrate"); code != 0 || !strings.Contains(out, "already at schema version") {
		t.Fatalf("migrate: %d %s", code, out)
	}
	if code, out := runOffline(t, "--data-path="+data, "consensus", "randao-state", "reset", "--key="+k1.Pubkey); code != 0 {
		t.Fatalf("offline reset: %d %s", code, out)
	}
}

// vectorgen verify against the built binary (PLAN S5b). The signer runs
// with the interop keys on each end-to-end network bound to the fixture
// GVR, with protection disabled (loopback only) so that no fixture is
// refused as a repeat, in two configurations that between them leave no
// fixture unchecked:
//
//   - without genesis time, so that no clock bound refuses the fixtures
//     at the slot and epoch limits, and with exits enabled: every sign and
//     negative fixture except the exits-disabled one; RANDAO is skipped;
//   - with genesis time and exits disabled: the RANDAO fixtures, the
//     exits-disabled fixture, and the rest again (those at the limits are
//     skipped by the clock bound).
//
// It builds tools/vectorgen, which links qrysm, so it runs only when
// REMOTESIGNER_VECTORS_VERIFY is set (make vectors-verify-binary).
func TestVectorgenVerify(t *testing.T) {
	if os.Getenv("REMOTESIGNER_VECTORS_VERIFY") == "" {
		t.Skip("set REMOTESIGNER_VECTORS_VERIFY=1 to build tools/vectorgen and verify the binary")
	}
	runs := []struct {
		name      string
		consensus []string
		maySkip   []string // the skips the other run covers
	}{
		{"no genesis time", []string{"--voluntary-exit-signing-enabled"},
			[]string{"RANDAO: the signer reports", "needs voluntary exits enabled=false"}},
		{"genesis time", []string{"--network-genesis-time=" + strconv.Itoa(harnessGenesis)},
			[]string{"refused by the signer's clock bound", "needs voluntary exits enabled=true"}},
	}
	for _, preset := range vectors.Presets {
		for _, run := range runs {
			t.Run(preset+"/"+run.name, func(t *testing.T) {
				var gvr, name string
				for _, nf := range vectors.Negative(t) {
					if nf.Preset == preset {
						gvr, name = nf.Network.GVR, nf.Network.ConfigName
					}
				}
				keysDir := t.TempDir()
				writeInteropKeys(t, keysDir)
				args := append([]string{"--network=" + name, "--network-genesis-validators-root=" + gvr,
					"--slashing-protection-enabled=false"}, run.consensus...)
				s := start(t, options{keys: keysDir, noNetwork: true, consensus: args})
				s.waitReady()
				verify := exec.Command("go", "run", ".", "verify", "-signer", s.base,
					"-token-file", filepath.Join(s.data, "auth-token"))
				verify.Dir = "../../tools/vectorgen"
				out, err := verify.CombinedOutput()
				t.Logf("vectorgen verify:\n%s", out)
				if err != nil {
					t.Fatalf("vectorgen verify: %v", err)
				}
				for line := range strings.SplitSeq(string(out), "\n") {
					if !strings.HasPrefix(line, "skip:") {
						continue
					}
					covered := false
					for _, m := range run.maySkip {
						covered = covered || strings.Contains(line, m)
					}
					if !covered {
						t.Errorf("unexpected %s", line)
					}
				}
			})
		}
	}
}
