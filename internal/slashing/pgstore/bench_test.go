// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package pgstore_test

import (
	"context"
	"errors"
	"net/url"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/pgstore"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/pgstore/pgtest"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

// The Postgres benchmarks run only with REMOTESIGNER_BENCH=1 and a test server (make bench-postgres): their timing
// depends on the machine and on where the database runs.
func benchPostgres(t *testing.T) {
	t.Helper()
	if os.Getenv("REMOTESIGNER_BENCH") == "" {
		t.Skip("set REMOTESIGNER_BENCH=1 to run the Postgres benchmarks (make bench-postgres)")
	}
	pgtest.Skip(t)
}

func pct(ds []time.Duration, p float64) time.Duration {
	s := slices.Clone(ds)
	slices.Sort(s)
	return s[min(len(s)-1, int(p*float64(len(s))))].Round(10 * time.Microsecond)
}

// B13: Postgres slashing transactions with the signing profile (a pool of 16), through the engine: single
// attestations and blocks one after another (p50 ≤ 5 ms, p99 ≤ 20 ms), bursts of 33 concurrent attestations (the
// p99 of 200 bursts' wall times ≤ 100 ms), and a database that stops answering, which must fail a check-and-record
// in at most 5 s.
func TestB13Postgres(t *testing.T) {
	benchPostgres(t)
	const (
		keys   = 64
		single = 1000
		bursts = 200
		burstN = 33
	)
	db := migrated(t)
	u, err := url.Parse(db.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := pgtest.NewStallProxy(t, u.Host)
	u.Host = proxy.Addr()
	s := open(t, pgstore.Config{URL: u.String(), Password: db.Password})
	e := slashing.NewEngine(s)
	all := make([][]byte, keys)
	for i := range all {
		all[i] = slashingtest.Key(i)
	}
	must(t, e.RegisterValidators(bg, all))

	target := make([]uint64, keys)
	attest := func(k int) (time.Duration, error) {
		target[k]++
		t0 := time.Now()
		d, err := e.CheckAndRecordAttestation(bg, slashing.AttestationRequest{PublicKey: all[k],
			GenesisValidatorsRoot: slashingtest.GVR, SourceEpoch: target[k] - 1, TargetEpoch: target[k],
			SigningRoot: slashingtest.RootOf(target[k])})
		if err == nil && !d.Allowed {
			err = errors.New(string(d.Reason))
		}
		return time.Since(t0), err
	}
	for i := range 50 { // warm the pool and the plans
		if _, err := attest(i % keys); err != nil {
			t.Fatal(err)
		}
	}

	atts := make([]time.Duration, single)
	for i := range atts {
		if atts[i], err = attest(i % keys); err != nil {
			t.Fatal(err)
		}
	}
	blocks := make([]time.Duration, single)
	for i := range blocks {
		t0 := time.Now()
		d, err := e.CheckAndRecordBlock(bg, slashing.BlockRequest{PublicKey: all[i%keys],
			GenesisValidatorsRoot: slashingtest.GVR, Slot: uint64(100 + i), SigningRoot: slashingtest.RootOf(uint64(i))})
		blocks[i] = time.Since(t0)
		if err != nil || !d.Allowed {
			t.Fatalf("block %d: %+v %v", i, d, err)
		}
	}
	walls := make([]time.Duration, bursts)
	var lat []time.Duration
	for b := range walls {
		got := make([]time.Duration, burstN)
		errs := make([]error, burstN)
		var wg sync.WaitGroup
		t0 := time.Now()
		for i := range burstN {
			wg.Go(func() { got[i], errs[i] = attest((b + i) % keys) })
		}
		wg.Wait()
		walls[b] = time.Since(t0)
		if err := errors.Join(errs...); err != nil {
			t.Fatal(err)
		}
		lat = append(lat, got...)
		time.Sleep(100 * time.Millisecond)
	}

	proxy.Stall()
	stalled, stallErr := attest(0)
	proxy.Resume()

	t.Logf("B13 attestation: p50 %s, p99 %s (%d)", pct(atts, 0.5), pct(atts, 0.99), single)
	t.Logf("B13 block: p50 %s, p99 %s (%d)", pct(blocks, 0.5), pct(blocks, 0.99), single)
	t.Logf("B13 burst of %d: wall p50 %s, p99 %s, max %s; per call p50 %s, p99 %s (%d bursts)", burstN,
		pct(walls, 0.5), pct(walls, 0.99), slices.Max(walls).Round(10*time.Microsecond), pct(lat, 0.5), pct(lat, 0.99), bursts)
	t.Logf("B13 stalled database: failed after %s: %v", stalled.Round(time.Millisecond), stallErr)
	for _, c := range []struct {
		what      string
		got, want time.Duration
	}{
		{"attestation p50", pct(atts, 0.5), 5 * time.Millisecond},
		{"attestation p99", pct(atts, 0.99), 20 * time.Millisecond},
		{"block p50", pct(blocks, 0.5), 5 * time.Millisecond},
		{"block p99", pct(blocks, 0.99), 20 * time.Millisecond},
		{"burst wall p99", pct(walls, 0.99), 100 * time.Millisecond},
		{"stalled database", stalled, 5 * time.Second},
	} {
		if c.got > c.want {
			t.Errorf("%s %s, threshold %s", c.what, c.got, c.want)
		}
	}
	if !errors.Is(stallErr, context.DeadlineExceeded) {
		t.Errorf("the stalled call failed with %v, want its deadline", stallErr)
	}
}

// B14 (Postgres variant): one pruning run over 4,096 validators that each keep 512 epochs, one attestation per epoch
// and one block every 32 epochs, on the mainnet preset's 128 slots per epoch, as the signer prunes a Postgres store:
// one connection of its own, one validator per transaction, and a rest after each as long as it took. The run must take at most 5 minutes, and
// attestation signing on the signing pool during it must keep its p99 within twice the p99 without it. The
// histories and the signing load are the bbolt variant's (boltstore's b14_test.go): the steady state, 512 epochs
// plus the six a 12 h interval adds, and the first run on twice the window, which deletes half of 4.2 million
// attestations; bursts of 32 concurrent attestations from 32 distinct keys, four times a second.
func TestB14PruningPostgres(t *testing.T) {
	benchPostgres(t)
	for _, tc := range []struct {
		name  string
		extra int
	}{
		{"steady state", 6},
		{"first run on twice the window", b14Kept},
	} {
		t.Run(tc.name, func(t *testing.T) { testB14Postgres(t, tc.extra) })
	}
}

const (
	b14Validators   = 4096
	b14Kept         = 512
	b14SlotsPer     = 128
	b14BlockEvery   = 32
	b14Burst        = 32
	b14BurstEvery   = 250 * time.Millisecond
	b14BaselineRuns = 40
)

func testB14Postgres(t *testing.T, extra int) {
	db := migrated(t)
	cfg := config(db)
	s := open(t, cfg)
	epochs := b14Kept + extra
	keys := make([][]byte, b14Validators)
	for i := range keys {
		keys[i] = slashingtest.Key(i)
	}
	t0 := time.Now()
	must(t, s.RegisterValidators(bg, keys))
	if _, err := s.PinGenesisValidatorsRoot(bg, slashingtest.GVR); err != nil {
		t.Fatal(err)
	}
	// The history is written in SQL: through the store it would take one round trip per record. Roots are
	// slashingtest.RootOf(epoch).
	conn := db.Connect(t)
	seed := func(sql string, args ...any) {
		t.Helper()
		ctx, cancel := context.WithTimeout(bg, 20*time.Minute)
		defer cancel()
		if _, err := conn.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	seed(`INSERT INTO signed_attestations (validator_id, source_epoch, target_epoch, signing_root)
		SELECT v.id, greatest(e, 1) - 1, e, decode('a5' || repeat('00', 23) || lpad(to_hex(e), 16, '0'), 'hex')
		FROM validators v, generate_series(0, $1::bigint - 1) e`, epochs)
	seed(`INSERT INTO signed_blocks (validator_id, slot, signing_root)
		SELECT v.id, e * $2::bigint + 7, decode('a5' || repeat('00', 23) || lpad(to_hex(e), 16, '0'), 'hex')
		FROM validators v, generate_series(0, $1::bigint - 1, $3::bigint) e`, epochs, b14SlotsPer, b14BlockEvery)
	seed(`INSERT INTO low_watermarks (validator_id, slot, source_epoch, target_epoch) SELECT id, 7, 0, 0 FROM validators`)
	seed(`VACUUM ANALYZE`)
	var size string
	if err := conn.QueryRow(bg, `SELECT pg_size_pretty(pg_database_size(current_database()))`).Scan(&size); err != nil {
		t.Fatal(err)
	}
	t.Logf("seeded %d validators x %d epochs (%d attestations, %d blocks) in %s; database %s", b14Validators, epochs,
		b14Validators*epochs, b14Validators*((epochs-1)/b14BlockEvery+1), time.Since(t0).Round(time.Second), size)

	e := slashing.NewEngine(s)
	must(t, e.RegisterValidators(bg, keys))
	signer := &b14Signer{engine: e, keys: keys, target: uint64(epochs)}
	baseline := signer.bursts(t, b14BaselineRuns, nil)

	// The pruner's store, as the runner opens it: one connection, no idle one kept.
	prune := cfg
	prune.MaxConns, prune.MinConns = 1, 0
	ps := open(t, prune)
	done := make(chan struct{})
	var (
		res     slashing.PruneResult
		pruneD  time.Duration
		pruneEr error
	)
	go func() {
		defer close(done)
		t0 := time.Now()
		res, pruneEr = slashing.Prune(bg, ps, slashing.PruneConfig{EpochsToKeep: b14Kept, SlotsPerEpoch: b14SlotsPer,
			Batch: 1, Pace: 1})
		pruneD = time.Since(t0)
	}()
	during := signer.bursts(t, 0, done)
	if pruneEr != nil {
		t.Fatal(pruneEr)
	}
	wantAtts := b14Validators * extra
	if res.Validators != b14Validators || res.Attestations < wantAtts || res.Attestations > wantAtts+len(baseline)+len(during) {
		t.Fatalf("prune result %+v, want %d validators and %d attestations (plus one per key that signed) deleted", res,
			b14Validators, wantAtts)
	}
	b99, d99 := pct(baseline, 0.99), pct(during, 0.99)
	t.Logf("B14 prune: %s for %d validators, %d attestations and %d blocks deleted", pruneD.Round(time.Millisecond),
		res.Validators, res.Attestations, res.Blocks)
	t.Logf("B14 signing baseline: %d attestations, p50 %s, p99 %s", len(baseline), pct(baseline, 0.5), b99)
	t.Logf("B14 signing during the prune: %d attestations, p50 %s, p99 %s (%.2fx the baseline p99)", len(during),
		pct(during, 0.5), d99, float64(d99)/float64(b99))
	if pruneD > 5*time.Minute {
		t.Errorf("the prune took %s, threshold 5 min", pruneD)
	}
	if d99 > 2*b99 {
		t.Errorf("signing p99 during the prune %s is above twice the baseline p99 %s", d99, b99)
	}
}

// b14Signer signs bursts of attestations, each burst from the next b14Burst keys at the next target epoch.
type b14Signer struct {
	engine *slashing.Engine
	keys   [][]byte
	next   int
	target uint64
}

func (b *b14Signer) bursts(t *testing.T, n int, done <-chan struct{}) []time.Duration {
	t.Helper()
	var lat []time.Duration
	tick := time.NewTicker(b14BurstEvery)
	defer tick.Stop()
	for i := 0; n == 0 || i < n; i++ {
		lat = append(lat, b.burst(t)...)
		select {
		case <-done:
			return lat
		case <-tick.C:
		}
	}
	return lat
}

func (b *b14Signer) burst(t *testing.T) []time.Duration {
	t.Helper()
	lat := make([]time.Duration, b14Burst)
	var wg sync.WaitGroup
	for i := range b14Burst {
		key := b.keys[(b.next+i)%len(b.keys)]
		req := slashing.AttestationRequest{PublicKey: key, GenesisValidatorsRoot: slashingtest.GVR,
			SourceEpoch: b.target - 1, TargetEpoch: b.target, SigningRoot: slashingtest.RootOf(b.target)}
		wg.Go(func() {
			t0 := time.Now()
			d, err := b.engine.CheckAndRecordAttestation(bg, req)
			lat[i] = time.Since(t0)
			if err != nil || !d.Allowed {
				t.Errorf("attestation refused: %+v %v", d, err)
			}
		})
	}
	wg.Wait()
	b.next += b14Burst
	if b.next >= len(b.keys) {
		b.next, b.target = 0, b.target+1
	}
	return lat
}
