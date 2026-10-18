// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package randao is the RANDAO reveal service: it decides which layer of a
// key's hash onion may be released for a commitment, and records the
// frontier before the layer leaves the signer (docs/contract.md section
// 14).
//
// Per key the store keeps the frontier (m, R = x_m, last): the deepest
// layer released and the slot of the last release that moved it. A
// commitment is classified against it:
//
//   - no frontier: first use, found by a scan from x_0;
//   - c == R: a new layer, x_{m-1};
//   - c within --randao-reorg-window layers above R: a re-reveal of a
//     layer that is already public;
//   - otherwise a scan from x_0 (the slow path): deeper than m advances
//     the frontier (gap_advanced), further above R is a deep-reorg
//     re-reveal, and not found is 422 RANDAO_UNKNOWN_COMMITMENT.
//
// Every release that moves the frontier must pass the new-layer
// conditions: the slot lies in [now_slot - 1, now_slot + skew], it is
// after the last frontier-moving slot, the key's new-layer bucket holds a
// token, a deeper layer exists, and the validator is enabled. The new
// frontier is then committed with compare-and-set, and only after that is
// the layer returned. The slow path runs at most once per key per
// --randao-full-scan-min-interval (else 429), and unknown commitments are
// remembered in a negative cache.
//
// No onion is built ahead of time. After each frontier move the next layer
// is computed in the background, so that the following new layer is
// served without a scan; it is kept in memory only and never stored. When
// a reload evicts a key (Track no longer lists it), its precomputed layer
// is wiped and no new one is kept.
package randao

import (
	"context"
	"errors"
	"math"
	"runtime"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/metrics"
	"github.com/rgeraldes24/go-remotesigner/internal/randao/onion"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// Defaults of the --randao-* flags.
const (
	DefaultMaxLayers     = onion.DefaultLength
	DefaultReorgWindow   = 1024
	DefaultNewLayerBurst = 3
	DefaultRefillEpochs  = 1
	// NegativeCacheSize is the number of unknown (key, commitment) pairs
	// remembered.
	NegativeCacheSize = 1024
	// LowLayersThreshold: keys-check/randao is DOWN when a key has fewer
	// layers left.
	LowLayersThreshold = 1024
)

// SeedHolder is a key that can compute onion layers: it lends a temporary
// copy of its 48-byte wallet seed. *mldsa87.Key implements it; a key
// without a seed (a future KMS key) cannot reveal.
type SeedHolder interface {
	WithSeed(fn func(seed *[mldsa87.SeedSize]byte) error) error
}

// Config configures a Service.
type Config struct {
	// Store holds the frontiers: the bbolt store, or the memory store when
	// slashing protection is disabled.
	Store slashing.Store
	// GenesisTime is the network's genesis time; GenesisKnown is false when
	// it is unknown, and then no layer can move the frontier.
	GenesisTime    uint64
	GenesisKnown   bool
	SecondsPerSlot uint64
	SlotsPerEpoch  uint64
	// ClockSkewSlots is the upper edge of the slot window
	// (--signing-clock-skew-slots).
	ClockSkewSlots uint64
	// MaxLayers bounds a scan from x_0 (--randao-max-layers).
	MaxLayers uint64
	// ReorgWindow is how many layers above R a re-reveal is looked for
	// without a scan (--randao-reorg-window).
	ReorgWindow uint64
	// FullScanMinInterval is the per-key slow-path budget
	// (--randao-full-scan-min-interval); zero means no limit.
	FullScanMinInterval time.Duration
	// NewLayerBurst and NewLayerRefillEpochs shape the per-key new-layer
	// bucket; zero refill epochs turn it off.
	NewLayerBurst        uint64
	NewLayerRefillEpochs uint64
	// Concurrency bounds the onion computations running at once; zero
	// means max(1, GOMAXPROCS/2).
	Concurrency int
	// Now is the clock; nil means time.Now.
	Now     func() time.Time
	Metrics *metrics.Metrics
	Log     logrus.FieldLogger
}

// Request is one reveal request for a loaded key, after the HTTP layer has
// checked the identifier, the body and fork_info.
type Request struct {
	ID         slashing.KeyID
	Key        SeedHolder
	Slot       uint64
	Commitment [onion.Size]byte
	// LogID is the key's short log form.
	LogID string
}

// Outcome is the answer to a request.
type Outcome struct {
	// Reveal is the released layer when Err is nil.
	Reveal [onion.Size]byte
	// Result is the value of the result label of
	// consensus_randao_reveals_total: the class of a release, or
	// metrics.RandaoRefused or metrics.RandaoError; it is empty for an
	// error the counter does not record (404).
	Result string
	// Err is the refusal or failure.
	Err *apierr.Error
	// RetryAfter is set with RANDAO_SCAN_RATE_LIMITED.
	RetryAfter time.Duration
}

// ErrNotRegistered is returned by Reset for a key the store does not know.
var ErrNotRegistered = errors.New("randao: key is not registered in the slashing-protection store")

// Service serves reveals. It is safe for concurrent use.
type Service struct {
	cfg    Config
	period time.Duration // bucket refill period; 0 = bucket off
	sem    chan struct{}

	mu       sync.Mutex
	keys     map[slashing.KeyID]*keyState
	negative *negativeCache
	closed   bool
	wg       sync.WaitGroup
}

// keyState is what the service holds per key in memory.
type keyState struct {
	// mu serialises the requests and resets of the key: classification
	// and the read-modify-write of its frontier. A slow-path scan runs
	// without it.
	mu       sync.Mutex
	bucket   bucket
	lastScan time.Time
	scanned  bool

	// guarded by Service.mu
	next    *layer // precomputed x_{m-1}, keyed by m
	layers  uint64 // m of the stored frontier, for the gauge
	tracked bool
	evicted bool // the last Track left the key out: keep no precomputed layer
}

// dropNext wipes and forgets the precomputed layer. It needs Service.mu.
func (ks *keyState) dropNext() {
	if ks.next != nil {
		clear(ks.next.value[:])
		ks.next = nil
	}
}

// layer is the value of one onion index.
type layer struct {
	index uint64
	value [onion.Size]byte
}

// New returns a Service. Call Close when done.
func New(cfg Config) *Service {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = logrus.New()
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = max(1, runtime.GOMAXPROCS(0)/2)
	}
	s := &Service{
		cfg:      cfg,
		sem:      make(chan struct{}, cfg.Concurrency),
		keys:     map[slashing.KeyID]*keyState{},
		negative: newNegativeCache(NegativeCacheSize),
	}
	if cfg.NewLayerRefillEpochs > 0 {
		s.period = time.Duration(cfg.NewLayerRefillEpochs*cfg.SlotsPerEpoch*cfg.SecondsPerSlot) * time.Second
	}
	s.setGauge()
	return s
}

// RefillPeriod is the new-layer bucket's refill period, zero when the
// bucket is off.
func (s *Service) RefillPeriod() time.Duration { return s.period }

// Close waits for the background precomputations and stops new ones.
func (s *Service) Close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *Service) state(id slashing.KeyID) *keyState {
	s.mu.Lock()
	defer s.mu.Unlock()
	ks, ok := s.keys[id]
	if !ok {
		ks = &keyState{}
		s.keys[id] = ks
	}
	return ks
}

// Reveal serves one request.
func (s *Service) Reveal(ctx context.Context, r Request) Outcome {
	start := time.Now()
	path := metrics.RandaoPathHot
	ks := s.state(r.ID)
	out, scan := s.classify(ctx, ks, r, &path)
	if scan {
		out = s.scan(ctx, ks, r, &path)
	}
	if out.Err == nil && s.cfg.Metrics != nil {
		s.cfg.Metrics.RandaoRevealDuration.WithLabelValues(path).Observe(time.Since(start).Seconds())
	}
	return out
}

// classify answers the commitment from the stored frontier under the key's
// lock. When it needs the slow path it takes the key's scan budget and
// reports scan instead of answering.
func (s *Service) classify(ctx context.Context, ks *keyState, r Request, path *string) (out Outcome, scan bool) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	st, ok, err := s.cfg.Store.RandaoState(ctx, r.ID)
	if err != nil {
		return storeFailure(err), false
	}
	if ok {
		if r.Commitment == st.Reveal {
			return s.advance(ctx, ks, r, &st, st.Index, nil, metrics.RandaoNewLayer, path), false
		}
		if v, ok := walk(st.Reveal, r.Commitment, s.cfg.ReorgWindow); ok {
			return released(v, metrics.RandaoReReveal), false
		}
	}
	s.mu.Lock()
	unknown := s.negative.contains(negKey{id: r.ID, commitment: r.Commitment})
	s.mu.Unlock()
	if unknown {
		return refused(apierr.RandaoUnknownCommitment, "commitment is not in this key's onion"), false
	}
	now := s.cfg.Now()
	if wait := ks.scanWait(now, s.cfg.FullScanMinInterval); wait > 0 {
		out := refused(apierr.RandaoScanRateLimited, "slow-path scan budget used up for this key")
		out.RetryAfter = wait
		return out, false
	}
	ks.lastScan, ks.scanned = now, true
	return Outcome{}, true
}

// scan is the slow path: a scan from x_0 for the commitment. The scan is
// stateless and costs up to --randao-max-layers hashes, so it runs without
// the key's lock, and a concurrent legitimate reveal for the key does not
// wait for it. The frontier may have moved meanwhile, so the result is
// classified against the frontier re-read under the lock.
func (s *Service) scan(ctx context.Context, ks *keyState, r Request, path *string) Outcome {
	*path = metrics.RandaoPathScan
	if s.cfg.Metrics != nil {
		s.cfg.Metrics.RandaoSlowPathScans.Inc()
	}
	var (
		j      uint64
		reveal [onion.Size]byte
		found  bool
	)
	err := s.withSeed(ctx, r.Key, func(seed *[mldsa87.SeedSize]byte) {
		j, reveal, found = onion.Find(seed[:], r.Commitment, s.cfg.MaxLayers)
	})
	if err != nil {
		return seedFailure(err)
	}
	if !found {
		s.mu.Lock()
		s.negative.add(negKey{id: r.ID, commitment: r.Commitment})
		s.mu.Unlock()
		return refused(apierr.RandaoUnknownCommitment, "commitment is not in this key's onion")
	}

	ks.mu.Lock()
	defer ks.mu.Unlock()
	st, ok, err := s.cfg.Store.RandaoState(ctx, r.ID)
	if err != nil {
		return storeFailure(err)
	}
	switch {
	case !ok:
		return s.advance(ctx, ks, r, nil, j, &reveal, metrics.RandaoFirstUse, path)
	case j == st.Index:
		// The frontier moved to the commitment during the scan.
		return s.advance(ctx, ks, r, &st, j, &reveal, metrics.RandaoNewLayer, path)
	case j < st.Index:
		out := s.advance(ctx, ks, r, &st, j, &reveal, metrics.RandaoGapAdvanced, path)
		if out.Err == nil {
			s.cfg.Log.WithFields(logrus.Fields{"key": r.LogID, "m": st.Index, "j": j}).
				Warn("RANDAO commitment was deeper than any layer this signer released (another source revealed for this key, or the store was restored): the frontier advanced")
		}
		return out
	default:
		// j > m: x_{j-1} is at or above R, so already public; beyond the
		// reorg window this is a deep-reorg re-reveal.
		return released(reveal, metrics.RandaoReReveal)
	}
}

// advance releases layer j-1 of the onion for the commitment x_j, moving
// the frontier from cur (nil: none) to it, after the new-layer conditions
// in their contract order. reveal is x_{j-1} when a scan already found it.
func (s *Service) advance(ctx context.Context, ks *keyState, r Request, cur *slashing.RandaoState, j uint64,
	reveal *[onion.Size]byte, result string, path *string) Outcome {
	now := s.cfg.Now()
	if !s.cfg.GenesisKnown || !window(now, s.cfg.GenesisTime, s.cfg.SecondsPerSlot, s.cfg.ClockSkewSlots, r.Slot) {
		return refused(apierr.RandaoSlotOutOfWindow, "slot is outside the reveal window, or genesis time is unknown")
	}
	if cur != nil && r.Slot <= cur.LastSlot {
		return refused(apierr.RandaoSlotNotIncreasing, "slot is not after the last frontier-moving reveal")
	}
	if !ks.bucket.ready(now, s.period, s.cfg.NewLayerBurst) {
		if s.cfg.Metrics != nil {
			s.cfg.Metrics.RandaoNewLayerRateLimited.Inc()
		}
		s.cfg.Log.WithField("key", r.LogID).Warn("RANDAO new-layer bucket is empty for this key: reveal refused")
		return refused(apierr.RandaoNewLayerRateLimited, "new-layer bucket empty")
	}
	if j == 0 {
		return refused(apierr.RandaoOnionExhausted, "the commitment is x_0")
	}
	vs, err := s.cfg.Store.ValidatorStatus(ctx, r.ID)
	if err != nil {
		return storeFailure(err)
	}
	if !vs.Enabled {
		return refused(apierr.ValidatorDisabled, "validator is disabled")
	}

	if reveal == nil {
		v, scanned, err := s.layer(ctx, ks, r.Key, j-1)
		if err != nil {
			return seedFailure(err)
		}
		if scanned {
			*path = metrics.RandaoPathScan
		}
		reveal = &v
	}
	if onion.Step(*reveal) != r.Commitment {
		return failure(apierr.Internal, "computed layer does not hash to the commitment")
	}
	next := slashing.RandaoState{Index: j - 1, Reveal: *reveal, LastSlot: r.Slot}
	swapped, err := s.cfg.Store.CompareAndSwapRandaoState(ctx, r.ID, cur, next)
	if err != nil {
		return storeFailure(err)
	}
	if !swapped {
		return failure(apierr.StoreUnavailable, "the stored frontier changed during the request")
	}
	ks.bucket.take(now, s.period)
	s.track(ks, next.Index)
	s.precompute(ks, r.Key, next.Index)
	return released(*reveal, result)
}

// walk looks for c among the w layers above r: when c = Step^k(r) with
// 1 ≤ k ≤ w it returns Step^(k-1)(r), the pre-image of c.
func walk(r, c [onion.Size]byte, w uint64) ([onion.Size]byte, bool) {
	prev := r
	for k := uint64(1); k <= w; k++ {
		x := onion.Step(prev)
		if x == c {
			return prev, true
		}
		prev = x
	}
	return [onion.Size]byte{}, false
}

// layer returns x_m: the precomputed value, else a computation from x_0.
func (s *Service) layer(ctx context.Context, ks *keyState, key SeedHolder, m uint64) ([onion.Size]byte, bool, error) {
	// The value is copied under the lock: Track may wipe it.
	var v [onion.Size]byte
	s.mu.Lock()
	hit := ks.next != nil && ks.next.index == m
	if hit {
		v = ks.next.value
	}
	s.mu.Unlock()
	if hit {
		return v, false, nil
	}
	err := s.withSeed(ctx, key, func(seed *[mldsa87.SeedSize]byte) {
		v = onion.Advance(onion.Base(seed[:]), m)
	})
	return v, true, err
}

// precompute computes x_{m-1} in the background once the frontier is at m.
func (s *Service) precompute(ks *keyState, key SeedHolder, m uint64) {
	if m == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		var v [onion.Size]byte
		err := s.withSeed(context.Background(), key, func(seed *[mldsa87.SeedSize]byte) {
			v = onion.Advance(onion.Base(seed[:]), m-1)
		})
		if err != nil {
			return
		}
		s.mu.Lock()
		if !ks.evicted {
			ks.next = &layer{index: m - 1, value: v}
		}
		s.mu.Unlock()
		clear(v[:])
	}()
}

// withSeed runs fn on the key's seed within the concurrency bound.
func (s *Service) withSeed(ctx context.Context, key SeedHolder, fn func(seed *[mldsa87.SeedSize]byte)) error {
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-s.sem }()
	return key.WithSeed(func(seed *[mldsa87.SeedSize]byte) error {
		fn(seed)
		return nil
	})
}

// scanWait returns how long the key must wait for its next scan.
func (ks *keyState) scanWait(now time.Time, interval time.Duration) time.Duration {
	if !ks.scanned || interval <= 0 {
		return 0
	}
	if elapsed := now.Sub(ks.lastScan); elapsed < interval {
		return interval - elapsed
	}
	return 0
}

// Reset clears a registered key's frontier, so that its next reveal is a
// first use. It keeps the key's bucket. It returns ErrNotRegistered for a
// key the store does not know.
func (s *Service) Reset(ctx context.Context, id slashing.KeyID) error {
	ks := s.state(id)
	ks.mu.Lock()
	defer ks.mu.Unlock()
	vs, err := s.cfg.Store.ValidatorStatus(ctx, id)
	if err != nil {
		return err
	}
	if !vs.Registered {
		return ErrNotRegistered
	}
	if err := s.cfg.Store.DeleteRandaoState(ctx, id); err != nil {
		return err
	}
	s.mu.Lock()
	ks.dropNext()
	ks.tracked = false
	s.mu.Unlock()
	s.setGauge()
	return nil
}

// Track reads the stored frontiers of the loaded keys, so that the
// min-layers gauge and the health check cover exactly them; keys left out
// are no longer counted. The runner calls it after every key load.
//
// The keys left out are the ones the load evicted: their precomputed
// layers, which are not public yet, are wiped first, even when reading the
// frontiers fails, and none is kept for them until a later Track lists
// them again. Their buckets and scan budgets stay, so that a reload does
// not refill them.
func (s *Service) Track(ctx context.Context, ids []slashing.KeyID) error {
	s.evict(ids)
	type frontier struct {
		id slashing.KeyID
		m  uint64
		ok bool
	}
	fs := make([]frontier, 0, len(ids))
	for _, id := range ids {
		st, ok, err := s.cfg.Store.RandaoState(ctx, id)
		if err != nil {
			return err
		}
		fs = append(fs, frontier{id: id, m: st.Index, ok: ok})
	}
	s.mu.Lock()
	for _, ks := range s.keys {
		ks.tracked = false
	}
	for _, f := range fs {
		ks, ok := s.keys[f.id]
		if !ok {
			ks = &keyState{}
			s.keys[f.id] = ks
		}
		ks.layers, ks.tracked = f.m, f.ok
	}
	s.mu.Unlock()
	s.setGauge()
	return nil
}

// evict marks every key that ids leaves out as evicted and wipes its
// precomputed layer; the keys in ids are no longer evicted.
func (s *Service) evict(ids []slashing.KeyID) {
	loaded := make(map[slashing.KeyID]struct{}, len(ids))
	for _, id := range ids {
		loaded[id] = struct{}{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, ks := range s.keys {
		_, ok := loaded[id]
		ks.evicted = !ok
		if !ok {
			ks.dropNext()
		}
	}
}

// track records a key's new frontier.
func (s *Service) track(ks *keyState, m uint64) {
	s.mu.Lock()
	ks.layers, ks.tracked = m, true
	s.mu.Unlock()
	s.setGauge()
}

// MinLayersRemaining returns the fewest layers any tracked key has left
// (its m), or false when no tracked key has a frontier.
func (s *Service) MinLayersRemaining() (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.minLayers()
}

// minLayers needs s.mu.
func (s *Service) minLayers() (uint64, bool) {
	var (
		least uint64
		found bool
	)
	for _, ks := range s.keys {
		if ks.tracked && (!found || ks.layers < least) {
			least, found = ks.layers, true
		}
	}
	return least, found
}

// setGauge updates consensus_randao_min_layers_remaining: NaN while no
// tracked key has a frontier.
func (s *Service) setGauge() {
	if s.cfg.Metrics == nil {
		return
	}
	m, ok := s.MinLayersRemaining()
	v := math.NaN()
	if ok {
		v = float64(m)
	}
	s.cfg.Metrics.RandaoMinLayersRemaining.Set(v)
}

func released(v [onion.Size]byte, result string) Outcome {
	return Outcome{Reveal: v, Result: result}
}

func refused(r apierr.Reason, detail string) Outcome {
	return Outcome{Result: metrics.RandaoRefused, Err: apierr.New(r, detail)}
}

func failure(r apierr.Reason, detail string) Outcome {
	return Outcome{Result: metrics.RandaoError, Err: apierr.New(r, detail)}
}

func storeFailure(err error) Outcome {
	if errors.Is(err, slashing.ErrValidatorNotRegistered) {
		return Outcome{Err: apierr.New(apierr.UnknownKey, "key is not registered in the store")}
	}
	return failure(apierr.StoreUnavailable, "randao state: "+err.Error())
}

// seedFailure maps a failed seed loan: a key removed during the request is
// unknown, a cancelled request an internal error.
func seedFailure(err error) Outcome {
	if errors.Is(err, mldsa87.ErrZeroized) {
		return Outcome{Err: apierr.New(apierr.UnknownKey, "key removed during the request")}
	}
	return failure(apierr.Internal, "onion computation: "+err.Error())
}
