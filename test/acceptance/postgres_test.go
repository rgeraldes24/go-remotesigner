// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package acceptance

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystoretest"
	"github.com/rgeraldes24/go-remotesigner/internal/randao/onion"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/pgstore/pgtest"
	"github.com/rgeraldes24/go-remotesigner/internal/vectors"
)

// pgFlags are the store flags of a signer or store command on db.
func pgFlags(t *testing.T, db *pgtest.DB) []string {
	t.Helper()
	return []string{"--slashing-protection-db-url=" + db.URL,
		"--slashing-protection-db-password-file=" + db.PasswordFile(t)}
}

// migratedDB is a fresh database with the schema consensus migrate creates.
func migratedDB(t *testing.T) *pgtest.DB {
	t.Helper()
	db := pgtest.New(t)
	code, out := runOffline(t, append([]string{"consensus", "migrate"}, pgFlags(t, db)...)...)
	if code != 0 || !strings.Contains(out, "slashing-protection schema version 1 created") {
		t.Fatalf("consensus migrate: exit %d %s", code, out)
	}
	return db
}

// An unmigrated database refuses to start, naming consensus migrate; consensus migrate creates the schema, and
// running it again changes nothing; a schema written by a newer release refuses to start.
func TestPostgresSchemaRefusals(t *testing.T) {
	db := pgtest.New(t)
	store := pgFlags(t, db)
	s := launch(t, options{consensus: store})
	if code := s.exitCode(15 * time.Second); code != 1 || !strings.Contains(s.output.String(), "consensus migrate") {
		t.Fatalf("start on an empty database: exit %d\n%s", code, s.output.String())
	}
	if code, out := runOffline(t, append([]string{"consensus", "migrate"}, store...)...); code != 0 ||
		!strings.Contains(out, "schema version 1 created") {
		t.Fatalf("consensus migrate: exit %d %s", code, out)
	}
	if code, out := runOffline(t, append([]string{"consensus", "migrate"}, store...)...); code != 0 ||
		!strings.Contains(out, "already at schema version 1; nothing to do") {
		t.Fatalf("consensus migrate again: exit %d %s", code, out)
	}
	s = start(t, options{consensus: store})
	s.waitReady()
	s.signal(syscall.SIGTERM)
	if code := s.exitCode(15 * time.Second); code != 0 {
		t.Fatalf("stop: exit %d", code)
	}

	db.Exec(t, `UPDATE database_version SET version = version + 1`)
	s = launch(t, options{consensus: store})
	if code := s.exitCode(15 * time.Second); code != 1 || !strings.Contains(s.output.String(), "downgrade is not supported") {
		t.Fatalf("start on a newer schema: exit %d\n%s", code, s.output.String())
	}
}

type revealResult struct {
	replica int
	code    int
	body    string
	err     error
}

// revealRaw posts a reveal request; it is safe to call from any goroutine.
func revealRaw(s *signer, token, pubkey string, slot uint64, commitment, forkInfo string) (int, string, error) {
	body := `{"slot":"` + strconv.FormatUint(slot, 10) + `","randao_commitment":"` + commitment + `","fork_info":` + forkInfo + `}`
	req, err := http.NewRequest(http.MethodPost, s.base+"/api/v1/consensus/randao_reveal/"+pubkey, strings.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out), err
}

// metricValue reads one sample of a scrape, 0 when it is absent.
func metricValue(t *testing.T, text, sample string) float64 {
	t.Helper()
	m := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(sample) + ` (\S+)$`).FindStringSubmatch(text)
	if m == nil {
		return 0
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// Two replicas on one database alternate proposals for one key over 20 slots: each slot's reveal request goes to
// both at once, the slot's leader first. Every request is answered 200 with the same reveal from both replicas, so
// no layer is released twice: per slot one replica moves the frontier and the other re-reveals that layer, and
// across the 20 slots the frontier moves 20 times, to 20 distinct layers, with no 412 or 429. Then each of 10 more
// slots goes to one replica only, the two in turn: every one moves the frontier, although the next layer a replica
// precomputed after its own last move is stale by then, because the other replica moved the frontier since. Each
// replica has its own new-layer bucket, so their burst covers the moves each makes.
func TestPostgresReplicasAlternateProposals(t *testing.T) {
	db := migratedDB(t)
	keysDir := t.TempDir()
	keys := writeInteropKeys(t, keysDir)
	k := keys[0]
	const (
		slots     = 20 // served by both replicas
		alternate = 10 // served by one replica each, in turn
	)
	replicas := make([]*signer, 2)
	for i := range replicas {
		replicas[i] = start(t, options{keys: keysDir,
			global: []string{"--metrics-enabled", "--metrics-port=0"},
			consensus: append(pgFlags(t, db), "--signing-clock-skew-slots="+strconv.Itoa(slots+alternate+2),
				"--randao-new-layer-burst="+strconv.Itoa(slots+alternate+2), "--randao-full-scan-min-interval=1ms")})
		replicas[i].waitReady()
	}
	tokens := []string{replicas[0].signToken(), replicas[1].signToken()}
	var forkInfo string
	for _, c := range vectors.Signing(t) {
		if c.Preset == "minimal" {
			forkInfo = `{"fork":{"previous_version":"` + c.Network.GenesisForkVersion + `","current_version":"` +
				c.Network.GenesisForkVersion + `","epoch":"0"},"genesis_validators_root":"` + c.Network.GVR + `"}`
			break
		}
	}

	first := currentSlot()
	commitment := k.RandaoCommitment
	released := map[string]bool{}
	for i := range slots + alternate {
		slot := first + uint64(i)
		leader := i % 2
		serving := []int{leader, 1 - leader}
		if i >= slots {
			serving = serving[:1]
		}
		results := make(chan revealResult, len(serving))
		var wg sync.WaitGroup
		for _, r := range serving {
			wg.Go(func() {
				code, body, err := revealRaw(replicas[r], tokens[r], k.Pubkey, slot, commitment, forkInfo)
				results <- revealResult{replica: r, code: code, body: body, err: err}
			})
			time.Sleep(time.Millisecond) // the leader's request is sent first
		}
		wg.Wait()
		close(results)
		var reveals []string
		for res := range results {
			if res.err != nil || res.code != 200 {
				t.Fatalf("slot %d, replica %d: %d %s %v", slot, res.replica, res.code, res.body, res.err)
			}
			var out struct {
				Reveal string `json:"randao_reveal"`
			}
			if err := json.Unmarshal([]byte(res.body), &out); err != nil {
				t.Fatal(err)
			}
			reveals = append(reveals, out.Reveal)
		}
		if len(reveals) == 2 && reveals[0] != reveals[1] {
			t.Fatalf("slot %d: the replicas released %s and %s", slot, reveals[0], reveals[1])
		}
		if released[reveals[0]] {
			t.Fatalf("slot %d: %s released again", slot, reveals[0])
		}
		released[reveals[0]] = true
		if i == 0 && reveals[0] != k.RandaoFirstReveal {
			t.Fatalf("first reveal %s, want the key's first reveal %s", reveals[0], k.RandaoFirstReveal)
		}
		// The next proposal's commitment is this slot's reveal, as the chain records it.
		var c [onion.Size]byte
		copy(c[:], vectors.Hex(t, reveals[0]))
		if got := onion.Step(c); "0x"+fmt.Sprintf("%x", got[:]) != commitment {
			t.Fatalf("slot %d: the reveal does not hash to the commitment", slot)
		}
		commitment = reveals[0]
	}

	var moves, reReveals float64
	for i, r := range replicas {
		code, text := scrape(t, r.metricsPort(), "")
		if code != 200 {
			t.Fatalf("scrape replica %d: %d", i, code)
		}
		for _, sample := range []string{
			`consensus_randao_reveals_total{result="refused"}`,
			`consensus_randao_reveals_total{result="error"}`,
			`consensus_randao_new_layer_rate_limited_total`,
			`http_request_duration_seconds_count{code="412",route="/api/v1/consensus/randao_reveal/{identifier}"}`,
			`http_request_duration_seconds_count{code="429",route="/api/v1/consensus/randao_reveal/{identifier}"}`,
			`http_request_duration_seconds_count{code="500",route="/api/v1/consensus/randao_reveal/{identifier}"}`,
		} {
			if v := metricValue(t, text, sample); v != 0 {
				t.Errorf("replica %d: %s %v, want 0", i, sample, v)
			}
		}
		n := metricValue(t, text, `consensus_randao_reveals_total{result="first_use"}`) +
			metricValue(t, text, `consensus_randao_reveals_total{result="new_layer"}`) +
			metricValue(t, text, `consensus_randao_reveals_total{result="gap_advanced"}`)
		re := metricValue(t, text, `consensus_randao_reveals_total{result="re_reveal"}`)
		t.Logf("replica %d moved the frontier %v times and re-revealed %v layers", i, n, re)
		moves, reReveals = moves+n, reReveals+re
	}
	if moves != slots+alternate || reReveals != slots {
		t.Errorf("%v frontier moves and %v re-reveals across the replicas, want %d and %d", moves, reReveals,
			slots+alternate, slots)
	}
	var index, last int64
	conn := db.Connect(t)
	if err := conn.QueryRow(context.Background(), `SELECT deepest_index, last_new_slot FROM randao_reveal_state`).
		Scan(&index, &last); err != nil {
		t.Fatal(err)
	}
	if want := onion.DefaultLength - slots - alternate; uint64(index) != want || uint64(last) != first+slots+alternate-1 {
		t.Errorf("stored frontier m=%d last=%d, want m=%d last=%d", index, last, want, first+slots+alternate-1)
	}

	// consensus randao-state reset runs online: the key's row is gone, and its next reveal on a replica is a first use
	// of the commitment it is sent, one layer below it.
	code, out := runOffline(t, append([]string{"consensus", "randao-state", "reset", "--key=" + k.Pubkey}, pgFlags(t, db)...)...)
	if code != 0 || !strings.Contains(out, "its next reveal is a first use") {
		t.Fatalf("randao-state reset online: exit %d %s", code, out)
	}
	var rows int
	if err := conn.QueryRow(context.Background(), `SELECT count(*) FROM randao_reveal_state`).Scan(&rows); err != nil ||
		rows != 0 {
		t.Fatalf("%d frontier rows after the reset (%v), want 0", rows, err)
	}
	slot := first + slots + alternate
	code, body, err := revealRaw(replicas[1], tokens[1], k.Pubkey, slot, commitment, forkInfo)
	if err != nil || code != 200 {
		t.Fatalf("reveal after the reset: %d %s %v", code, body, err)
	}
	if err := conn.QueryRow(context.Background(), `SELECT deepest_index, last_new_slot FROM randao_reveal_state`).
		Scan(&index, &last); err != nil {
		t.Fatal(err)
	}
	if want := onion.DefaultLength - slots - alternate - 1; uint64(index) != want || uint64(last) != slot {
		t.Errorf("frontier after the reset m=%d last=%d, want m=%d last=%d", index, last, want, slot)
	}
}

// attestationAt is the golden attestation with its source and target epochs moved to source and target and no
// signing root, so the signer computes it.
func attestationAt(t *testing.T, source, target uint64) []byte {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(goldenAttestation(t), &v); err != nil {
		t.Fatal(err)
	}
	delete(v, "signing_root")
	a := v["attestation"].(map[string]any)
	a["source"].(map[string]any)["epoch"] = strconv.FormatUint(source, 10)
	a["target"].(map[string]any)["epoch"] = strconv.FormatUint(target, 10)
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// validatorRow reads a key's enabled flag and its row version (xmin): a row that no one wrote keeps its xmin.
func validatorRow(t *testing.T, db *pgtest.DB, pubkey string) (bool, string) {
	t.Helper()
	var (
		enabled bool
		xmin    string
	)
	err := db.Connect(t).QueryRow(context.Background(), `SELECT enabled, xmin::text FROM validators WHERE public_key = $1`,
		vectors.Hex(t, pubkey)).Scan(&enabled, &xmin)
	if err != nil {
		t.Fatal(err)
	}
	return enabled, xmin
}

// Replica A reloads while the password file of one of its keystores is unreadable: the reload completes with
// errors, A keeps the key it loaded before, and replica B keeps signing that key. No replica writes the key's row
// at any point (its enabled flag stays true and its row version does not change), neither at startup, nor in A's
// reload, nor while B signs.
func TestPostgresReplicaReloadKeepsKeyEnabled(t *testing.T) {
	db := migratedDB(t)
	ks := newKeystoreSet(t, "password", keystoretest.Cheapest)
	ks.add(t, t.Name(), 0, 2, true)
	passwordsDir := func() string {
		dir := t.TempDir()
		for i := range 2 {
			name := strings.TrimSuffix(keystoretest.DepositFileName(i, 1760000000), ".json") + ".txt"
			if _, err := keystoretest.WriteFile(dir, name, []byte("password")); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	dirA, dirB := passwordsDir(), passwordsDir()
	replica := func(pw string) *signer {
		s := start(t, options{consensus: append(pgFlags(t, db), "--keystores-path="+ks.dir, "--keystores-passwords-path="+pw)})
		s.waitReadyWithin(time.Minute)
		return s
	}
	a, b := replica(dirA), replica(dirB)
	pk := ks.pubkeys[0]
	enabled, xmin := validatorRow(t, db, pk)
	if !enabled {
		t.Fatal("the key starts disabled")
	}

	target := uint64(1000)
	signs := func(s *signer, name string) {
		t.Helper()
		target++
		if code, out := s.post("/api/v1/consensus/sign/"+pk, s.signToken(), attestationAt(t, target-1, target)); code != 200 {
			t.Fatalf("replica %s, attestation at %d: %d %s", name, target, code, out)
		}
	}
	signs(b, "B")
	pwA := filepath.Join(dirA, strings.TrimSuffix(keystoretest.DepositFileName(0, 1760000000), ".json")+".txt")
	if err := os.Chmod(pwA, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(pwA, 0o600) })
	a.reload("completed_with_errors", time.Minute)
	for range 3 {
		signs(b, "B")
	}
	signs(a, "A")
	if got := len(a.publicKeys()); got != 2 {
		t.Fatalf("replica A has %d keys after the failed reload, want both", got)
	}
	if e, x := validatorRow(t, db, pk); !e || x != xmin {
		t.Fatalf("the key's row: enabled %v, version %s; want enabled and version %s, unwritten", e, x, xmin)
	}
}

// consensus disable-validator runs online against the shared database while both replicas run: the next
// attestation for the key is refused with 412 VALIDATOR_DISABLED on either replica, without a restart, while its
// selection proofs still sign and the other keys still attest. consensus export reads the same database online.
func TestPostgresDisableValidatorOnline(t *testing.T) {
	db := migratedDB(t)
	keysDir := t.TempDir()
	keys := writeInteropKeys(t, keysDir)
	replicas := []*signer{
		start(t, options{keys: keysDir, consensus: pgFlags(t, db)}),
		start(t, options{keys: keysDir, consensus: pgFlags(t, db)}),
	}
	for _, r := range replicas {
		r.waitReady()
	}
	pk := keys[0].Pubkey
	if code, out := replicas[0].post("/api/v1/consensus/sign/"+pk, replicas[0].signToken(), attestationAt(t, 10, 11)); code != 200 {
		t.Fatalf("attestation before the disable: %d %s", code, out)
	}
	code, out := runOffline(t, append([]string{"consensus", "disable-validator", "--key=" + pk}, pgFlags(t, db)...)...)
	if code != 0 || !strings.Contains(out, "412 VALIDATOR_DISABLED") {
		t.Fatalf("disable-validator online: exit %d %s", code, out)
	}
	for i, r := range replicas {
		code, out := r.post("/api/v1/consensus/sign/"+pk, r.signToken(), attestationAt(t, 11, 12+uint64(i)))
		if code != 412 || reasonOf(t, out) != "VALIDATOR_DISABLED" {
			t.Fatalf("replica %d, attestation of the disabled key: %d %s", i, code, out)
		}
		if code, _ := r.post("/api/v1/consensus/sign/"+pk, r.signToken(), selectionProof(t)); code != 200 {
			t.Fatalf("replica %d, selection proof of the disabled key: %d", i, code)
		}
		other := keys[1+i].Pubkey
		if code, out := r.post("/api/v1/consensus/sign/"+other, r.signToken(), attestationAt(t, 10, 11)); code != 200 {
			t.Fatalf("replica %d, attestation of an enabled key: %d %s", i, code, out)
		}
	}
	if code, out := runOffline(t, append([]string{"consensus", "disable-validator", "--key=" + pk}, pgFlags(t, db)...)...); code != 0 ||
		!strings.Contains(out, "already disabled") {
		t.Fatalf("disable-validator again: exit %d %s", code, out)
	}
	file := filepath.Join(t.TempDir(), "export.json")
	code, out = runOffline(t, append([]string{"consensus", "export", "--to=" + file}, pgFlags(t, db)...)...)
	if code != 0 || !strings.Contains(out, "exported 3 validator(s), 0 block(s) and 3 attestation(s)") {
		t.Fatalf("export online: exit %d %s", code, out)
	}
}

// The history commands run online against the database two replicas sign from (docs/operations/postgres.md,
// section 6), and both replicas apply what each command wrote from their next request, without a restart: consensus
// import of qrysm's export, the high watermark set and removed, and the low-watermark repair.
func TestPostgresStoreCommandsOnline(t *testing.T) {
	file, gvr := qrysmExport(t)
	db := migratedDB(t)
	keysDir := t.TempDir()
	keys := writeInteropKeys(t, keysDir)
	store := pgFlags(t, db)
	opts := options{keys: keysDir, noNetwork: true,
		consensus: append([]string{"--network=end-to-end-mainnet", "--network-genesis-validators-root=" + gvr}, store...)}
	replicas := []*signer{start(t, opts), start(t, opts)}
	for _, r := range replicas {
		r.waitReady()
	}
	command := func(args ...string) string {
		t.Helper()
		code, out := runOffline(t, append(append([]string{"consensus"}, args...), store...)...)
		if code != 0 {
			t.Fatalf("consensus %s online: exit %d %s", strings.Join(args, " "), code, out)
		}
		return out
	}
	pk, golden := attestation(t, "", "")
	refused := func(what string, body []byte, want string) {
		t.Helper()
		for i, r := range replicas {
			if code, reason := r.sign(t, pk, body); code != 412 || reason != want {
				t.Fatalf("replica %d, %s: %d %s; want 412 %s", i, what, code, reason, want)
			}
		}
	}
	highWatermark := func(want string) {
		t.Helper()
		for i, r := range replicas {
			if code, body, _ := r.do(request{path: "/api/v1/consensus/highWatermark", token: r.signToken()}); code != 200 ||
				body != want {
				t.Fatalf("replica %d, highWatermark: %d %s; want %s", i, code, body, want)
			}
		}
	}

	if out := command("import", "--from="+file); !strings.Contains(out, "imported 4 of 4 validator(s)") {
		t.Fatalf("import online: %s", out)
	}
	// qrysm signed (9, 10) for key 0: the golden (8, 10) is a double vote.
	refused("the golden attestation after the import", golden, "SLASHING_DOUBLE_VOTE")

	command("set-high-watermark", "--epoch=40", "--slot=5120")
	highWatermark(`{"epoch":"40","slot":"5120"}`)
	_, beyond := attestation(t, "12", "41")
	refused("an attestation beyond the high watermark", beyond, "SLASHING_ABOVE_HIGH_WATERMARK")
	command("set-high-watermark", "--remove")
	highWatermark(`{}`)

	// The replicas registered their keys, which include the four the import wrote.
	if out := command("watermark-repair", "--epoch=40", "--slot=2560"); !strings.Contains(out,
		fmt.Sprintf("raised the low watermarks of %d validator(s)", len(keys))) {
		t.Fatalf("watermark-repair online: %s", out)
	}
	_, below := attestation(t, "12", "13")
	refused("an attestation below the repaired watermark", below, "SLASHING_BELOW_WATERMARK")
	_, above := attestation(t, "40", "41")
	for i, r := range replicas {
		// The second replica answers the first one's attestation as a repeat of the same message.
		if code, reason := r.sign(t, pk, above); code != 200 {
			t.Fatalf("replica %d, an attestation above the repaired watermark: %d %s", i, code, reason)
		}
	}
}
