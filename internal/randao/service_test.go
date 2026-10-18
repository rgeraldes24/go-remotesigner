// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package randao

import (
	"context"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/metrics"
	"github.com/rgeraldes24/go-remotesigner/internal/randao/onion"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/boltstore"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/memstore"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

// The test network: the end-to-end timing (10 s slots, 6 slots per epoch).
const (
	testGenesis = 1_760_000_000
	testSPS     = 10
	testSPE     = 6
	testLayers  = 64 // a short onion keeps the scans cheap
)

// seedKey is a SeedHolder over a fixed seed.
type seedKey struct {
	seed    [mldsa87.SeedSize]byte
	removed bool
}

func (k *seedKey) WithSeed(fn func(*[mldsa87.SeedSize]byte) error) error {
	if k.removed {
		return mldsa87.ErrZeroized
	}
	s := k.seed
	return fn(&s)
}

// clock is a settable test clock.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// atSlot sets the clock to the start of slot s.
func (c *clock) atSlot(s uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = time.Unix(int64(testGenesis+s*testSPS), 0)
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type fixture struct {
	t     *testing.T
	s     *Service
	store slashing.Store
	m     *metrics.Metrics
	clock *clock
	key   *seedKey
	id    slashing.KeyID
	x     []([onion.Size]byte) // x[j] of the key's onion, j ≤ testLayers
}

type option func(*Config)

func quiet() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l
}

func newFixture(t *testing.T, store slashing.Store, opts ...option) *fixture {
	t.Helper()
	m, err := metrics.New(metrics.Config{})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, store: store, m: m, clock: &clock{}, key: &seedKey{}}
	for i := range f.key.seed {
		f.key.seed[i] = byte(i + 1)
	}
	pk := slashingtest.Key(0)
	f.id = slashing.KeyIDOf(pk)
	if err := store.RegisterValidators(context.Background(), [][]byte{pk}); err != nil {
		t.Fatal(err)
	}
	x := onion.Base(f.key.seed[:])
	for range testLayers + 2 {
		f.x = append(f.x, x)
		x = onion.Step(x)
	}
	cfg := Config{
		Store: store, GenesisTime: testGenesis, GenesisKnown: true, SecondsPerSlot: testSPS, SlotsPerEpoch: testSPE,
		ClockSkewSlots: 1, MaxLayers: testLayers, ReorgWindow: 8, FullScanMinInterval: testSPS * time.Second,
		NewLayerBurst: DefaultNewLayerBurst, NewLayerRefillEpochs: DefaultRefillEpochs,
		Now: f.clock.Now, Metrics: m, Log: quiet(),
	}
	for _, o := range opts {
		o(&cfg)
	}
	f.s = New(cfg)
	t.Cleanup(f.s.Close)
	f.clock.atSlot(1000)
	return f
}

// reveal requests the pre-image of x_j at slot.
func (f *fixture) reveal(slot uint64, j int) Outcome {
	f.t.Helper()
	return f.s.Reveal(context.Background(), Request{ID: f.id, Key: f.key, Slot: slot, Commitment: f.x[j], LogID: "test"})
}

// ok checks a release of x_{j-1} with the given class.
func (f *fixture) ok(out Outcome, j int, class string) {
	f.t.Helper()
	if out.Err != nil {
		f.t.Fatalf("refused %v, want %s of x_%d", out.Err, class, j-1)
	}
	if out.Reveal != f.x[j-1] || out.Result != class {
		f.t.Fatalf("released %x as %s, want x_%d as %s", out.Reveal[:4], out.Result, j-1, class)
	}
}

func (f *fixture) refusedWith(out Outcome, want apierr.Reason) {
	f.t.Helper()
	if out.Err == nil || out.Err.Reason != want {
		f.t.Fatalf("outcome %+v, want %s", out, want)
	}
	if out.Result != metrics.RandaoRefused {
		f.t.Fatalf("result %q, want refused", out.Result)
	}
}

// frontier checks the stored state.
func (f *fixture) frontier(m uint64, last uint64) {
	f.t.Helper()
	st, ok, err := f.store.RandaoState(context.Background(), f.id)
	if err != nil || !ok || st.Index != m || st.Reveal != f.x[m] || st.LastSlot != last {
		f.t.Fatalf("state %+v %v %v, want m=%d last=%d", st, ok, err, m, last)
	}
}

func withConfig(fn func(*Config)) option { return fn }

func TestWindow(t *testing.T) {
	at := func(s int64) time.Time { return time.Unix(testGenesis+s*testSPS, 0) }
	tests := []struct {
		now  time.Time
		skew uint64
		slot uint64
		want bool
	}{
		{at(100), 1, 98, false},
		{at(100), 1, 99, true},
		{at(100), 1, 100, true},
		{at(100), 1, 101, true},
		{at(100), 1, 102, false},
		{at(100), 3, 103, true},
		{at(0), 1, 0, true},
		{at(0), 1, 1, true},
		{at(0), 1, 2, false},
		{at(100).Add(9 * time.Second), 1, 99, true}, // still slot 100
		{at(-1), 1, 0, true},                        // now_slot -1: [-2, 0]
		{at(-1), 1, 1, false},
		{at(-2), 1, 0, false},
		{at(0), math.MaxUint64, math.MaxUint64, true},
		{time.Unix(0, 0), 1, 0, false}, // long before genesis
	}
	for _, tc := range tests {
		if got := window(tc.now, testGenesis, testSPS, tc.skew, tc.slot); got != tc.want {
			t.Errorf("window(now=%v, skew=%d, slot=%d) = %v, want %v", tc.now.Unix(), tc.skew, tc.slot, got, tc.want)
		}
	}
}

func TestBucket(t *testing.T) {
	period := time.Minute
	var b bucket
	t0 := time.Unix(testGenesis, 0)
	for i := range 3 {
		if !b.ready(t0, period, 3) {
			t.Fatalf("token %d missing from a full bucket", i)
		}
		b.take(t0, period)
	}
	if b.ready(t0.Add(59*time.Second), period, 3) {
		t.Fatal("a token before one refill period")
	}
	if !b.ready(t0.Add(time.Minute), period, 3) {
		t.Fatal("no token after one refill period")
	}
	b.take(t0.Add(time.Minute), period)
	if !b.ready(t0.Add(time.Hour), period, 3) {
		t.Fatal("no token after an hour")
	}
	// The bucket never holds more than burst tokens.
	for range 3 {
		b.take(t0.Add(time.Hour), period)
	}
	if b.ready(t0.Add(time.Hour), period, 3) {
		t.Fatal("more than burst tokens after a long idle time")
	}
	var off bucket
	for range 100 {
		if !off.ready(t0, 0, 0) {
			t.Fatal("a bucket with no period refused")
		}
		off.take(t0, 0)
	}
}

func TestNegativeCacheEvicts(t *testing.T) {
	c := newNegativeCache(2)
	k := func(b byte) negKey { return negKey{commitment: [32]byte{b}} }
	c.add(k(1))
	c.add(k(2))
	c.contains(k(1)) // 2 is now the least recently used
	c.add(k(3))
	if !c.contains(k(1)) || c.contains(k(2)) || !c.contains(k(3)) {
		t.Fatal("eviction order")
	}
}

// First use, new layer, re-reveal (orphaned or missed proposal) and retry.
func TestFirstUseNewLayerReReveal(t *testing.T) {
	f := newFixture(t, memstore.New())
	f.ok(f.reveal(1000, testLayers), testLayers, metrics.RandaoFirstUse)
	f.frontier(testLayers-1, 1000)
	f.ok(f.reveal(1000, testLayers), testLayers, metrics.RandaoReReveal) // retry within the slot
	f.clock.atSlot(1100)
	f.ok(f.reveal(1100, testLayers-1), testLayers-1, metrics.RandaoNewLayer)
	f.frontier(testLayers-2, 1100)
	f.ok(f.reveal(1101, testLayers), testLayers, metrics.RandaoReReveal) // orphaned or missed: x_{m+2}
	f.frontier(testLayers-2, 1100)
	if n, ok := f.s.MinLayersRemaining(); !ok || n != testLayers-2 {
		t.Fatalf("min layers %d %v", n, ok)
	}
	if v := testutil.ToFloat64(f.m.RandaoMinLayersRemaining); v != testLayers-2 {
		t.Fatalf("gauge %v", v)
	}
	if v := testutil.ToFloat64(f.m.RandaoSlowPathScans); v != 1 {
		t.Fatalf("%v slow-path scans, want only the first use's", v)
	}
}

// After a frontier move the next layer is precomputed, so the next new
// layer needs no computation from x_0.
func TestPrecompute(t *testing.T) {
	f := newFixture(t, memstore.New())
	f.ok(f.reveal(1000, testLayers), testLayers, metrics.RandaoFirstUse)
	f.precomputed(testLayers - 2)
	f.clock.atSlot(1001)
	f.ok(f.reveal(1001, testLayers-1), testLayers-1, metrics.RandaoNewLayer)
	if hot, scan := f.durations(metrics.RandaoPathHot), f.durations(metrics.RandaoPathScan); hot != 1 || scan != 1 {
		t.Fatalf("%d hot and %d scan reveals, want 1 and 1", hot, scan)
	}
}

// precomputed waits for the background computation of x_m.
func (f *fixture) precomputed(m uint64) {
	f.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.s.mu.Lock()
		n := f.s.keys[f.id].next
		f.s.mu.Unlock()
		if n != nil && n.index == m {
			if n.value != f.x[m] {
				f.t.Fatalf("precomputed x_%d = %x", n.index, n.value[:4])
			}
			return
		}
		if time.Now().After(deadline) {
			f.t.Fatalf("x_%d never precomputed", m)
		}
		time.Sleep(time.Millisecond)
	}
}

// durations returns the number of reveals timed under path.
func (f *fixture) durations(path string) uint64 {
	f.t.Helper()
	var m dto.Metric
	if err := f.m.RandaoRevealDuration.WithLabelValues(path).(prometheus.Histogram).Write(&m); err != nil {
		f.t.Fatal(err)
	}
	return m.GetHistogram().GetSampleCount()
}

// Burst test: with last 10,000 slots old, at most skew + 2 = 3 new
// layers are released in one slot, then one per slot (bucket off) or none
// until the bucket refills (bucket on).
func TestBurst(t *testing.T) {
	for _, bucketOn := range []bool{false, true} {
		t.Run(map[bool]string{false: "bucket off", true: "bucket on"}[bucketOn], func(t *testing.T) {
			f := newFixture(t, memstore.New(), withConfig(func(c *Config) {
				if !bucketOn {
					c.NewLayerRefillEpochs = 0
				}
			}))
			const now = 20_000
			f.clock.atSlot(now - 10_000)
			f.ok(f.reveal(now-10_000, testLayers), testLayers, metrics.RandaoFirstUse)
			f.clock.atSlot(now)
			j := testLayers - 1
			released := 0
			for slot := uint64(now - 3); slot <= now+3; slot++ {
				if out := f.reveal(slot, j); out.Err == nil {
					released++
					j--
				}
			}
			if released != 3 {
				t.Fatalf("%d new layers in one slot, want 3", released)
			}
			f.frontier(uint64(j), now+1)
			f.clock.atSlot(now + 1)
			if out := f.reveal(now+1, j); out.Err == nil {
				t.Fatal("a second new layer at a slot already used")
			}
			out := f.reveal(now+2, j)
			if bucketOn {
				f.refusedWith(out, apierr.RandaoNewLayerRateLimited)
				return
			}
			f.ok(out, j, metrics.RandaoNewLayer)
			if out := f.reveal(now+2, j-1); out.Err == nil {
				t.Fatal("two new layers in the next slot")
			}
		})
	}
}

// Gap advance: 50 different deeper commitments presented within one slot
// release exactly one layer; a first use seeded with the deposit
// commitment x_L is healed by the next honest request.
func TestGapAdvance(t *testing.T) {
	t.Run("one layer per slot", func(t *testing.T) {
		f := newFixture(t, memstore.New(), withConfig(func(c *Config) { c.MaxLayers = 200 }))
		// a 200-layer onion: re-derive x up to 200
		x := onion.Base(f.key.seed[:])
		f.x = f.x[:0]
		for range 202 {
			f.x = append(f.x, x)
			x = onion.Step(x)
		}
		f.ok(f.reveal(1000, 200), 200, metrics.RandaoFirstUse)
		f.clock.atSlot(2000)
		released := 0
		for i := range 50 {
			slot := uint64(1999 + i%3)
			if out := f.reveal(slot, 190-i*3); out.Err == nil {
				released++
				if out.Result != metrics.RandaoGapAdvanced {
					t.Fatalf("result %s", out.Result)
				}
			} else if r := out.Err.Reason; r != apierr.RandaoScanRateLimited {
				t.Fatalf("refusal %s, want the scan budget", r)
			}
		}
		if released != 1 {
			t.Fatalf("%d layers released, want 1", released)
		}
		f.frontier(189, 1999)
		if v := testutil.ToFloat64(f.m.RandaoReveals.WithLabelValues(metrics.RandaoGapAdvanced)); v != 0 {
			t.Fatalf("the service counted %v; the handler counts", v)
		}
	})
	t.Run("healed first use", func(t *testing.T) {
		f := newFixture(t, memstore.New())
		f.ok(f.reveal(1000, testLayers), testLayers, metrics.RandaoFirstUse) // a malicious BN sent x_L
		f.clock.atSlot(1001)
		f.ok(f.reveal(1001, testLayers-5), testLayers-5, metrics.RandaoGapAdvanced) // the chain is at x_{L-5}
		f.frontier(testLayers-6, 1001)
		f.clock.atSlot(1002)
		f.ok(f.reveal(1002, testLayers-6), testLayers-6, metrics.RandaoNewLayer)
	})
}

// The bucket: the 4th frontier move within one epoch is refused and
// counted; with --randao-new-layer-refill-epochs=0 it is released.
func TestNewLayerBucket(t *testing.T) {
	for _, refill := range []uint64{1, 0} {
		f := newFixture(t, memstore.New(), withConfig(func(c *Config) { c.NewLayerRefillEpochs = refill }))
		j := testLayers
		for i := range 3 {
			f.clock.atSlot(uint64(1000 + i))
			f.ok(f.reveal(uint64(1000+i), j), j, map[bool]string{true: metrics.RandaoFirstUse, false: metrics.RandaoNewLayer}[i == 0])
			j--
		}
		f.clock.atSlot(1003)
		out := f.reveal(1003, j)
		if refill == 0 {
			f.ok(out, j, metrics.RandaoNewLayer)
			continue
		}
		f.refusedWith(out, apierr.RandaoNewLayerRateLimited)
		if v := testutil.ToFloat64(f.m.RandaoNewLayerRateLimited); v != 1 {
			t.Fatalf("rate-limited counter %v", v)
		}
		// Re-reveals stay free.
		f.ok(f.reveal(1003, j+1), j+1, metrics.RandaoReReveal)
		f.clock.atSlot(1000 + testSPE)
		f.ok(f.reveal(1000+testSPE, j), j, metrics.RandaoNewLayer)
	}
}

func TestRefusals(t *testing.T) {
	t.Run("exhausted", func(t *testing.T) {
		f := newFixture(t, memstore.New())
		f.refusedWith(f.reveal(1000, 0), apierr.RandaoOnionExhausted)
		f.clock.advance(time.Minute)
		f.ok(f.reveal(1006, 1), 1, metrics.RandaoFirstUse)
		f.clock.atSlot(1007)
		f.refusedWith(f.reveal(1007, 0), apierr.RandaoOnionExhausted) // c == R at m = 0
	})
	t.Run("unknown is negative-cached", func(t *testing.T) {
		f := newFixture(t, memstore.New())
		f.refusedWith(f.reveal(1000, testLayers+1), apierr.RandaoUnknownCommitment)
		f.refusedWith(f.reveal(1000, testLayers+1), apierr.RandaoUnknownCommitment) // no scan, so no 429
		if v := testutil.ToFloat64(f.m.RandaoSlowPathScans); v != 1 {
			t.Fatalf("%v scans", v)
		}
		out := f.reveal(1000, testLayers)
		f.refusedWith(out, apierr.RandaoScanRateLimited)
		if out.RetryAfter != testSPS*time.Second {
			t.Fatalf("Retry-After %v", out.RetryAfter)
		}
	})
	t.Run("genesis unknown", func(t *testing.T) {
		f := newFixture(t, memstore.New(), withConfig(func(c *Config) { c.GenesisKnown = false }))
		f.refusedWith(f.reveal(1000, testLayers), apierr.RandaoSlotOutOfWindow)
		// Re-reveals are still served.
		if _, err := f.store.CompareAndSwapRandaoState(context.Background(), f.id, nil,
			slashing.RandaoState{Index: 10, Reveal: f.x[10], LastSlot: 5}); err != nil {
			t.Fatal(err)
		}
		f.ok(f.reveal(1000, 12), 12, metrics.RandaoReReveal)
		f.refusedWith(f.reveal(1000, 10), apierr.RandaoSlotOutOfWindow)
	})
	t.Run("validator disabled", func(t *testing.T) {
		f := newFixture(t, memstore.New())
		if err := f.store.SetValidatorEnabled(context.Background(), f.id, false); err != nil {
			t.Fatal(err)
		}
		f.refusedWith(f.reveal(1000, testLayers), apierr.ValidatorDisabled)
	})
	t.Run("key removed", func(t *testing.T) {
		f := newFixture(t, memstore.New())
		f.key.removed = true
		out := f.reveal(1000, testLayers)
		if out.Err == nil || out.Err.Reason != apierr.UnknownKey || out.Result != "" {
			t.Fatalf("outcome %+v", out)
		}
	})
	t.Run("deep reorg beyond the window", func(t *testing.T) {
		f := newFixture(t, memstore.New())
		f.ok(f.reveal(1000, 20), 20, metrics.RandaoFirstUse)
		f.clock.atSlot(1001)
		f.ok(f.reveal(1001, 19+8), 19+8, metrics.RandaoReReveal) // within W = 8 above R: no scan
		f.ok(f.reveal(1001, 19+9), 19+9, metrics.RandaoReReveal) // beyond: a scan
		if v := testutil.ToFloat64(f.m.RandaoSlowPathScans); v != 2 {
			t.Fatalf("%v scans", v)
		}
		f.frontier(19, 1000)
	})
}

// An admin reset makes the next reveal a first use, still subject to the
// new-layer conditions.
func TestReset(t *testing.T) {
	f := newFixture(t, memstore.New())
	f.ok(f.reveal(1000, testLayers), testLayers, metrics.RandaoFirstUse)
	if err := f.s.Reset(context.Background(), f.id); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := f.store.RandaoState(context.Background(), f.id); ok {
		t.Fatal("state survived the reset")
	}
	if _, ok := f.s.MinLayersRemaining(); ok {
		t.Fatal("a reset key is still tracked")
	}
	f.clock.atSlot(1001)
	f.ok(f.reveal(1001, testLayers-1), testLayers-1, metrics.RandaoFirstUse)
	f.frontier(testLayers-2, 1001)
	if err := f.s.Reset(context.Background(), slashing.KeyIDOf(slashingtest.Key(9))); err != ErrNotRegistered {
		t.Fatalf("reset of an unknown key: %v", err)
	}
}

func TestTrack(t *testing.T) {
	f := newFixture(t, memstore.New())
	if v := testutil.ToFloat64(f.m.RandaoMinLayersRemaining); !math.IsNaN(v) {
		t.Fatalf("gauge %v before any frontier", v)
	}
	if _, err := f.store.CompareAndSwapRandaoState(context.Background(), f.id, nil,
		slashing.RandaoState{Index: 500, LastSlot: 1}); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Track(context.Background(), []slashing.KeyID{f.id}); err != nil {
		t.Fatal(err)
	}
	if n, ok := f.s.MinLayersRemaining(); !ok || n != 500 {
		t.Fatalf("min layers %d %v", n, ok)
	}
	if err := f.s.Track(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.s.MinLayersRemaining(); ok {
		t.Fatal("an unloaded key is still tracked")
	}
}

// A key that a reload evicts (Track leaves it out) loses its precomputed
// layer, which is not public yet: the value is wiped and no new one is
// kept while the key stays evicted. Listed again, it is precomputed after
// its next frontier move as before.
func TestTrackWipesEvictedKeys(t *testing.T) {
	f := newFixture(t, memstore.New())
	f.ok(f.reveal(1000, testLayers), testLayers, metrics.RandaoFirstUse)
	f.precomputed(testLayers - 2)
	f.s.mu.Lock()
	held := f.s.keys[f.id].next
	f.s.mu.Unlock()

	if err := f.s.Track(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	f.s.mu.Lock()
	next, evicted := f.s.keys[f.id].next, f.s.keys[f.id].evicted
	f.s.mu.Unlock()
	if next != nil || !evicted || held.value != [onion.Size]byte{} {
		t.Fatalf("after eviction: next %v, evicted %v, old layer %x", next, evicted, held.value[:4])
	}
	// A precomputation that finishes after the eviction keeps nothing.
	f.s.precompute(f.s.state(f.id), f.key, testLayers-1)
	f.s.Close()
	f.s.mu.Lock()
	next = f.s.keys[f.id].next
	f.s.mu.Unlock()
	if next != nil {
		t.Fatalf("x_%d kept for an evicted key", next.index)
	}
}

// With bbolt, a store restored from an old backup sees the
// chain's deeper commitment as a gap, advances by one released layer, and
// a retry after a lost response is an idempotent re-reveal.
func TestRestoredBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "slashing-protection.db")
	open := func() *boltstore.Store {
		s, err := boltstore.Open(path, boltstore.Options{})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	s1 := open()
	f := newFixture(t, s1)
	f.ok(f.reveal(1000, testLayers), testLayers, metrics.RandaoFirstUse)
	f.s.Close()
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}
	backup, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	s2 := open()
	f2 := newFixture(t, s2, withConfig(func(c *Config) { c.NewLayerRefillEpochs = 0 }))
	for i := range 3 {
		f2.clock.atSlot(uint64(1001 + i))
		f2.ok(f2.reveal(uint64(1001+i), testLayers-1-i), testLayers-1-i, metrics.RandaoNewLayer)
	}
	f2.frontier(testLayers-4, 1003)
	f2.s.Close()
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, backup, 0o600); err != nil {
		t.Fatal(err)
	}
	s3 := open()
	t.Cleanup(func() { _ = s3.Close() })
	f3 := newFixture(t, s3)
	f3.frontier(testLayers-1, 1000)
	f3.clock.atSlot(1010)
	f3.ok(f3.reveal(1010, testLayers-4), testLayers-4, metrics.RandaoGapAdvanced)
	f3.frontier(testLayers-5, 1010)
	f3.ok(f3.reveal(1010, testLayers-4), testLayers-4, metrics.RandaoReReveal) // the retry
}

// Concurrent requests for one key serialise: the same new layer requested
// eight times at once is released once as a new layer and seven times as
// a re-reveal.
func TestConcurrentSameLayer(t *testing.T) {
	f := newFixture(t, memstore.New())
	f.ok(f.reveal(1000, testLayers), testLayers, metrics.RandaoFirstUse)
	f.clock.atSlot(1001)
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		classes = map[string]int{}
	)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out := f.reveal(1001, testLayers-1)
			mu.Lock()
			defer mu.Unlock()
			if out.Err != nil || out.Reveal != f.x[testLayers-2] {
				t.Errorf("outcome %+v", out)
			}
			classes[out.Result]++
		}()
	}
	wg.Wait()
	if classes[metrics.RandaoNewLayer] != 1 || classes[metrics.RandaoReReveal] != 7 {
		t.Fatalf("classes %v", classes)
	}
}

// gatedKey holds its first seed loan after arm until release is closed,
// standing in for a slow scan.
type gatedKey struct {
	*seedKey
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (k *gatedKey) WithSeed(fn func(*[mldsa87.SeedSize]byte) error) error {
	if k.armed.CompareAndSwap(true, false) {
		close(k.entered)
		<-k.release
	}
	return k.seedKey.WithSeed(fn)
}

// A slow-path scan in flight does not delay a legitimate reveal for
// the same key, which finishes within 100 ms; the scan's result is then
// classified against the frontier those reveals moved.
func TestScanDoesNotBlockKey(t *testing.T) {
	f := newFixture(t, memstore.New(), withConfig(func(c *Config) { c.Concurrency = 2 }))
	f.ok(f.reveal(1000, testLayers), testLayers, metrics.RandaoFirstUse) // m = L-1
	f.precomputed(testLayers - 2)
	f.clock.atSlot(1002)

	g := &gatedKey{seedKey: f.key, entered: make(chan struct{}), release: make(chan struct{})}
	g.armed.Store(true)
	request := func(slot uint64, j int) Request {
		return Request{ID: f.id, Key: g, Slot: slot, Commitment: f.x[j], LogID: "test"}
	}
	// x_{L-5} is deeper than R = x_{L-1}: a gap advance, found by a scan.
	scanned := make(chan Outcome, 1)
	go func() { scanned <- f.s.Reveal(context.Background(), request(1002, testLayers-5)) }()
	select {
	case <-g.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the scan never started")
	}

	within := func(r Request) Outcome {
		t.Helper()
		done := make(chan Outcome, 1)
		start := time.Now()
		go func() { done <- f.s.Reveal(context.Background(), r) }()
		select {
		case out := <-done:
			if d := time.Since(start); d > 100*time.Millisecond {
				t.Fatalf("reveal took %v behind a scan", d)
			}
			return out
		case <-time.After(100 * time.Millisecond):
			close(g.release)
			t.Fatal("a reveal for the key waited for the scan")
			return Outcome{}
		}
	}
	f.ok(within(request(1002, testLayers)), testLayers, metrics.RandaoReReveal)
	f.ok(within(request(1001, testLayers-1)), testLayers-1, metrics.RandaoNewLayer) // m = L-2
	select {
	case out := <-scanned:
		t.Fatalf("the scan finished before its release: %+v", out)
	default:
	}

	close(g.release)
	f.ok(<-scanned, testLayers-5, metrics.RandaoGapAdvanced)
	f.frontier(testLayers-6, 1002)
}

// racingStore is a store shared with another signer: its first compare-and-set lets the other signer win, by
// storing what the other signer would store for the same request (the same next frontier), and reports the lost
// race; with always set, every compare-and-set reports a lost race.
type racingStore struct {
	slashing.Store
	always atomic.Bool
	races  atomic.Int32
}

func (s *racingStore) CompareAndSwapRandaoState(ctx context.Context, id slashing.KeyID, old *slashing.RandaoState,
	next slashing.RandaoState) (bool, error) {
	if s.always.Load() {
		s.races.Add(1)
		return false, nil
	}
	if s.races.Add(1) == 1 {
		ok, err := s.Store.CompareAndSwapRandaoState(ctx, id, old, next)
		if err != nil || !ok {
			return ok, err
		}
		return false, nil
	}
	return s.Store.CompareAndSwapRandaoState(ctx, id, old, next)
}

// Two signers sharing a store serve the same request for the same slot: the one whose compare-and-set loses
// classifies the request again and answers it as a re-reveal of the layer the other released (G1 §8 V7), for a
// first use and for a new layer alike. A frontier that keeps moving fails with 500 STORE_UNAVAILABLE.
func TestLostRaceReReveals(t *testing.T) {
	for _, tc := range []struct {
		name  string
		prime bool // release one layer first, so the race is over a new layer
	}{{"first use", false}, {"new layer", true}} {
		t.Run(tc.name, func(t *testing.T) {
			store := &racingStore{Store: memstore.New()}
			f := newFixture(t, store)
			j := testLayers
			if tc.prime {
				store.races.Store(1)
				f.ok(f.reveal(1000, j), j, metrics.RandaoFirstUse)
				f.clock.atSlot(1001)
				store.races.Store(0)
				j--
			}
			f.ok(f.reveal(f.slot(), j), j, metrics.RandaoReReveal)
			if n := store.races.Load(); n != 1 {
				t.Fatalf("%d compare-and-sets, want 1", n)
			}
			f.frontier(uint64(j-1), f.slot())
		})
	}
	t.Run("frontier keeps moving", func(t *testing.T) {
		store := &racingStore{Store: memstore.New()}
		f := newFixture(t, store)
		store.races.Store(1)
		f.ok(f.reveal(1000, testLayers), testLayers, metrics.RandaoFirstUse)
		f.clock.atSlot(1001)
		store.races.Store(0)
		store.always.Store(true)
		out := f.reveal(1001, testLayers-1)
		if out.Err == nil || out.Err.Reason != apierr.StoreUnavailable || out.Result != metrics.RandaoError {
			t.Fatalf("outcome %+v, want 500 STORE_UNAVAILABLE", out)
		}
		if n := store.races.Load(); n != MaxRaces {
			t.Fatalf("%d compare-and-sets, want %d", n, MaxRaces)
		}
	})
}

// slot is the clock's current slot.
func (f *fixture) slot() uint64 {
	return uint64(f.clock.Now().Unix()-testGenesis) / testSPS
}
