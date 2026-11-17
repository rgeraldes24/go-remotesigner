// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package acceptance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/randao/onion"
	"github.com/rgeraldes24/go-remotesigner/internal/vectors"
)

// B16, the soak: 4,096 file-raw keys, the mainnet duty schedule of every
// slot replayed against the built binary at mainnet cadence for a
// configurable duration (docs/benchmarks.md). Each slot of a network of
// 4,096 validators (128 slots per epoch, so 32 attesters per slot, and a
// sync committee of 126 distinct members per 8-epoch period) brings:
//
//   - at the start: the proposer's RANDAO reveal, then its block; the slot's
//     aggregator's AGGREGATION_SLOT selection proof; 8 sync aggregators'
//     SYNC_COMMITTEE_SELECTION_PROOF;
//   - at 1/3 of the slot: 32 ATTESTATION and 126 SYNC_COMMITTEE_MESSAGE;
//   - at 2/3: 1 AGGREGATE_AND_PROOF (32 signatures) and 8
//     SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF (128 signatures, 1.2 MB each).
//
// That is 178 requests a slot, the expected load of a signer that holds every
// key of the mainnet cap. Every duty must be answered 200 before its slot
// ends; the signer's RSS must stay within ±10 % and its goroutines must not
// grow between the start of the run (after warm-up) and its end.
//
// With REMOTESIGNER_B16_DURATION set (make b16) it runs that long, with
// REMOTESIGNER_B16_SLOT seconds per slot (default 60, mainnet's), and
// asserts the whole threshold. Without it, it runs a smoke of b16SmokeSlots
// slots of 6 s each, which every go test run, CI's included, makes: the
// same schedule and keys, asserting only that no duty fails.
const (
	b16Keys          = 4096
	b16SlotsPerEpoch = 128
	b16Attesters     = b16Keys / b16SlotsPerEpoch
	b16SyncMembers   = 126
	b16SyncPeriod    = 8 * b16SlotsPerEpoch
	b16SyncAgg       = 8
	b16SmokeSlots    = 3
	b16SmokeSlot     = 6 * time.Second
	// b16GoroutineSlack is how many more goroutines than at the start the
	// end of a soak may show: connections opened and closed by the client's
	// transport come and go.
	b16GoroutineSlack = 16
)

// b16Templates are the mainnet golden requests the schedule edits, by type.
type b16Templates map[string]map[string]any

func b16LoadTemplates(t *testing.T) (b16Templates, vectors.Network) {
	t.Helper()
	want := map[string]string{
		"BLOCK_V2": "typical", "ATTESTATION": "typical", "AGGREGATION_SLOT": "typical",
		"AGGREGATE_AND_PROOF": "signatures_32", "SYNC_COMMITTEE_MESSAGE": "typical",
		"SYNC_COMMITTEE_SELECTION_PROOF": "typical", "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF": "signatures_128",
	}
	out := b16Templates{}
	var n vectors.Network
	for _, c := range vectors.Signing(t) {
		if c.Preset != "mainnet" || want[c.Type] != c.Name {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(c.RequestJSON, &m); err != nil {
			t.Fatal(err)
		}
		delete(m, "signing_root") // the signer computes it
		out[c.Type], n = m, c.Network
	}
	if len(out) != len(want) {
		t.Fatalf("mainnet templates of %d types, want %d", len(out), len(want))
	}
	return out, n
}

// b16Body sets path (a dot-separated chain of object keys) of the template
// to each value and encodes it. Templates are edited and encoded one at a
// time, by the scheduler alone.
func (tm b16Templates) body(t *testing.T, typ string, set map[string]any) []byte {
	t.Helper()
	m := tm[typ]
	for path, v := range set {
		obj := m
		keys := strings.Split(path, ".")
		for _, k := range keys[:len(keys)-1] {
			obj = obj[k].(map[string]any)
		}
		obj[keys[len(keys)-1]] = v
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// b16Root is a 32-byte root that names a slot and a purpose.
func b16Root(purpose string, slot uint64) string {
	h := sha256.Sum256([]byte(purpose + "/" + strconv.FormatUint(slot, 10)))
	return "0x" + hex.EncodeToString(h[:])
}

// b16Duty is one request of the schedule.
type b16Duty struct {
	typ, path string
	body      []byte
	key       int
}

// b16Result is one answered duty.
type b16Result struct {
	typ     string
	latency time.Duration
	err     string // "" when answered 200 in time
}

type b16Driver struct {
	t        *testing.T
	s        *signer
	client   *http.Client
	token    string
	ids      []string
	seeds    [][mldsa87.SeedSize]byte
	tmpl     b16Templates
	forkInfo map[string]any
	genesis  time.Time
	slot     time.Duration

	mu          sync.Mutex
	results     []b16Result
	commitments map[int]string // the RANDAO commitment each proposer reveals next
}

func (d *b16Driver) slotStart(s uint64) time.Time { return d.genesis.Add(time.Duration(s) * d.slot) }

// post sends a duty and records whether it was answered 200 before deadline.
func (d *b16Driver) post(duty b16Duty, deadline time.Time) []byte {
	start := time.Now()
	res := b16Result{typ: duty.typ}
	req, err := http.NewRequest(http.MethodPost, d.s.base+duty.path, bytes.NewReader(duty.body))
	if err != nil {
		d.t.Error(err)
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+d.token)
	var out []byte
	resp, err := d.client.Do(req)
	switch {
	case err != nil:
		res.err = err.Error()
	default:
		out, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			res.err = fmt.Sprintf("%d %.200s", resp.StatusCode, out)
		}
	}
	res.latency = time.Since(start)
	if res.err == "" && time.Now().After(deadline) {
		res.err = fmt.Sprintf("answered %v after the slot ended", time.Since(deadline))
	}
	d.mu.Lock()
	d.results = append(d.results, res)
	d.mu.Unlock()
	return out
}

// fire sends duties at once and returns when every one is answered.
func (d *b16Driver) fire(duties []b16Duty, deadline time.Time, wg *sync.WaitGroup) {
	for _, duty := range duties {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.post(duty, deadline)
		}()
	}
}

func (d *b16Driver) sign(typ string, key int, set map[string]any) b16Duty {
	return b16Duty{typ: typ, key: key, path: "/api/v1/consensus/sign/" + d.ids[key], body: d.tmpl.body(d.t, typ, set)}
}

// runSlot replays slot s: the duties of its start, of 1/3 and of 2/3, each
// due by the end of the slot.
func (d *b16Driver) runSlot(s uint64, wg *sync.WaitGroup) {
	start, deadline := d.slotStart(s), d.slotStart(s+1)
	epoch := s / b16SlotsPerEpoch
	slot := strconv.FormatUint(s, 10)
	committee := make([]int, b16Attesters)
	for i := range committee {
		committee[i] = int(s%b16SlotsPerEpoch)*b16Attesters + i
	}
	period := s / b16SyncPeriod
	members := make([]int, b16SyncMembers)
	for i := range members {
		members[i] = int((period*b16SyncMembers + uint64(i)) % b16Keys)
	}
	aggregator := committee[0]
	data := func() map[string]any {
		return map[string]any{
			"slot": slot, "index": "0", "beacon_block_root": b16Root("head", s),
			"source": map[string]any{"epoch": strconv.FormatUint(epoch-1, 10), "root": b16Root("source", epoch-1)},
			"target": map[string]any{"epoch": strconv.FormatUint(epoch, 10), "root": b16Root("target", epoch)},
		}
	}

	time.Sleep(time.Until(start))
	// The proposer: its RANDAO reveal, then its block, in order.
	proposer := int(s % b16Keys)
	block := d.sign("BLOCK_V2", proposer, map[string]any{
		"beacon_block.block_header.slot": slot, "beacon_block.block_header.proposer_index": strconv.Itoa(proposer),
		"beacon_block.block_header.body_root": b16Root("body", s),
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.mu.Lock()
		commitment, ok := d.commitments[proposer]
		d.mu.Unlock()
		if !ok {
			top := onion.Top(d.seeds[proposer][:], onion.DefaultLength)
			commitment = "0x" + hex.EncodeToString(top[:])
		}
		body, err := json.Marshal(map[string]any{"slot": slot, "randao_commitment": commitment, "fork_info": d.forkInfo})
		if err != nil {
			d.t.Error(err)
			return
		}
		out := d.post(b16Duty{typ: "RANDAO_REVEAL", path: "/api/v1/consensus/randao_reveal/" + d.ids[proposer],
			body: body}, deadline)
		var r struct {
			Reveal string `json:"randao_reveal"`
		}
		if json.Unmarshal(out, &r) == nil && r.Reveal != "" {
			d.mu.Lock()
			d.commitments[proposer] = r.Reveal
			d.mu.Unlock()
		}
		d.post(block, deadline)
	}()
	first := []b16Duty{d.sign("AGGREGATION_SLOT", aggregator, map[string]any{"aggregation_slot.slot": slot})}
	for _, m := range members[:b16SyncAgg] {
		first = append(first, d.sign("SYNC_COMMITTEE_SELECTION_PROOF", m, map[string]any{
			"sync_aggregator_selection_data.slot": slot}))
	}
	d.fire(first, deadline, wg)

	var third []b16Duty
	for _, k := range committee {
		third = append(third, d.sign("ATTESTATION", k, map[string]any{"attestation": data()}))
	}
	for _, m := range members {
		third = append(third, d.sign("SYNC_COMMITTEE_MESSAGE", m, map[string]any{
			"sync_committee_message.slot": slot, "sync_committee_message.beacon_block_root": b16Root("head", s)}))
	}
	time.Sleep(time.Until(start.Add(d.slot / 3)))
	d.fire(third, deadline, wg)

	last := []b16Duty{d.sign("AGGREGATE_AND_PROOF", aggregator, map[string]any{
		"aggregate_and_proof.aggregator_index": strconv.Itoa(aggregator), "aggregate_and_proof.aggregate.data": data()})}
	for _, m := range members[:b16SyncAgg] {
		last = append(last, d.sign("SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF", m, map[string]any{
			"contribution_and_proof.aggregator_index":               strconv.Itoa(m),
			"contribution_and_proof.contribution.slot":              slot,
			"contribution_and_proof.contribution.beacon_block_root": b16Root("head", s),
		}))
	}
	time.Sleep(time.Until(start.Add(2 * d.slot / 3)))
	d.fire(last, deadline, wg)
}

// b16Sample is the signer's state at the end of a slot.
type b16Sample struct {
	rssKiB, goroutines int
}

// sample reads the signer's RSS and its goroutines (go_goroutines).
func (d *b16Driver) sample(port string) b16Sample {
	smp := b16Sample{rssKiB: rssKiB(d.t, d.s.cmd.Process.Pid)}
	if code, text := scrape(d.t, port, ""); code == http.StatusOK {
		for line := range strings.SplitSeq(text, "\n") {
			if v, ok := strings.CutPrefix(line, "go_goroutines "); ok {
				smp.goroutines, _ = strconv.Atoi(strings.TrimSpace(v))
			}
		}
	}
	return smp
}

func median(xs []int) int {
	s := slices.Clone(xs)
	slices.Sort(s)
	return s[len(s)/2]
}

func TestB16DutySoak(t *testing.T) {
	soak := os.Getenv("REMOTESIGNER_B16_DURATION")
	slotLength, slots := b16SmokeSlot, uint64(b16SmokeSlots)
	if soak != "" {
		duration, err := time.ParseDuration(soak)
		if err != nil {
			t.Fatalf("REMOTESIGNER_B16_DURATION: %v", err)
		}
		slotLength = 60 * time.Second
		if v := os.Getenv("REMOTESIGNER_B16_SLOT"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 3 {
				t.Fatalf("REMOTESIGNER_B16_SLOT=%q: want whole seconds, at least 3", v)
			}
			slotLength = time.Duration(n) * time.Second
		}
		slots = uint64(duration / slotLength)
		if slots < 10 {
			t.Fatalf("a soak of %v at %v per slot is %d slots; want at least 10", duration, slotLength, slots)
		}
	}

	tmpl, n := b16LoadTemplates(t)
	keys := t.TempDir()
	ids := writeKeys(t, keys, b16Keys)
	seeds := make([][mldsa87.SeedSize]byte, b16Keys)
	for i := range seeds {
		seeds[i][0], seeds[i][1] = byte(i), byte(i>>8) // as writeKeys writes them
	}
	// A file network: the end-to-end mainnet network (mainnet preset, 128
	// slots per epoch) at the soak's slot length. Genesis is far enough back
	// that the first slot is in epoch 2, so attestations have a source epoch.
	embedded, err := os.ReadFile("../../internal/network/embedded/end-to-end-mainnet.yaml")
	if err != nil {
		t.Fatal(err)
	}
	netFile := filepath.Join(t.TempDir(), "b16.yaml")
	cfg := fmt.Sprintf("%s\nCONFIG_NAME: 'b16-soak'\nSECONDS_PER_SLOT: %d\n", embedded, int(slotLength/time.Second))
	if err := os.WriteFile(netFile, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	genesis := time.Now().Add(-2*b16SlotsPerEpoch*slotLength - slotLength/2).Truncate(time.Second)
	s := start(t, options{keys: keys, noNetwork: true,
		global: []string{"--metrics-enabled", "--metrics-port=0", "--logging=INFO"},
		consensus: []string{"--network=" + netFile, "--network-genesis-validators-root=" + n.GVR,
			"--network-genesis-time=" + strconv.FormatInt(genesis.Unix(), 10)}})
	ready := s.waitReady()
	port := s.metricsPort()

	var forkInfo map[string]any
	if err := json.Unmarshal(must1(json.Marshal(tmpl["ATTESTATION"]["fork_info"])), &forkInfo); err != nil {
		t.Fatal(err)
	}
	d := &b16Driver{t: t, s: s, client: &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()},
		token: s.signToken(), ids: ids, seeds: seeds, tmpl: tmpl, forkInfo: forkInfo,
		genesis: time.Unix(genesis.Unix(), 0), slot: slotLength, commitments: map[int]string{}}

	now := uint64(time.Since(d.genesis) / slotLength)
	first := now + 1
	t.Logf("B16: %d keys ready after %v; %d slots of %v from slot %d (epoch %d)", b16Keys, ready, slots, slotLength,
		first, first/b16SlotsPerEpoch)
	var (
		wg      sync.WaitGroup
		samples []b16Sample
	)
	for sl := first; sl < first+slots; sl++ {
		d.runSlot(sl, &wg)
		time.Sleep(time.Until(d.slotStart(sl + 1).Add(-slotLength / 10)))
		samples = append(samples, d.sample(port))
	}
	wg.Wait()

	byType := map[string][]time.Duration{}
	failures := map[string]int{}
	var examples []string
	for _, r := range d.results {
		byType[r.typ] = append(byType[r.typ], r.latency)
		if r.err != "" {
			failures[r.typ]++
			if len(examples) < 5 {
				examples = append(examples, r.typ+": "+r.err)
			}
		}
	}
	types := slices.Sorted(func(yield func(string) bool) {
		for k := range byType {
			if !yield(k) {
				return
			}
		}
	})
	for _, typ := range types {
		lat := byType[typ]
		t.Logf("B16 %s: %d duties, %d failed, p50 %v, p99 %v, max %v", typ, len(lat), failures[typ],
			percentile(lat, 0.5), percentile(lat, 0.99), percentile(lat, 1))
	}
	if want := int(slots) * 178; len(d.results) != want {
		t.Errorf("B16: %d duties answered, want %d", len(d.results), want)
	}
	total := 0
	for _, f := range failures {
		total += f
	}
	if total > 0 {
		t.Errorf("B16: %d failed duties, want 0; for example %v", total, examples)
	}

	rss, gor := make([]int, len(samples)), make([]int, len(samples))
	for i, smp := range samples {
		rss[i], gor[i] = smp.rssKiB, smp.goroutines
	}
	// Warm-up is the first tenth of the run; the start is the tenth after
	// it, and the end the last tenth.
	tenth := max(1, len(samples)/10)
	base, end := samples[min(tenth, len(samples)-1):min(2*tenth, len(samples))], samples[len(samples)-tenth:]
	vals := func(ss []b16Sample, f func(b16Sample) int) []int {
		out := make([]int, len(ss))
		for i, s := range ss {
			out[i] = f(s)
		}
		return out
	}
	baseRSS, endRSS := median(vals(base, func(s b16Sample) int { return s.rssKiB })),
		median(vals(end, func(s b16Sample) int { return s.rssKiB }))
	baseG, endG := median(vals(base, func(s b16Sample) int { return s.goroutines })),
		median(vals(end, func(s b16Sample) int { return s.goroutines }))
	t.Logf("B16: RSS %d → %d KiB (%+.1f %%; min %d, max %d); goroutines %d → %d (min %d, max %d)", baseRSS, endRSS,
		100*float64(endRSS-baseRSS)/float64(baseRSS), slices.Min(rss), slices.Max(rss), baseG, endG,
		slices.Min(gor), slices.Max(gor))
	if soak == "" {
		return // the smoke runs too briefly for the memory and goroutine trends
	}
	if diff := endRSS - baseRSS; diff*10 > baseRSS || -diff*10 > baseRSS {
		t.Errorf("B16: RSS moved from %d to %d KiB, more than ±10 %%", baseRSS, endRSS)
	}
	if endG > baseG+b16GoroutineSlack {
		t.Errorf("B16: goroutines grew from %d to %d", baseG, endG)
	}
}

func must1[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
