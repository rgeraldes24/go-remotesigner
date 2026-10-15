// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package consensus

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/metrics"
	"github.com/rgeraldes24/go-remotesigner/internal/network"
	"github.com/rgeraldes24/go-remotesigner/internal/randao"
	"github.com/rgeraldes24/go-remotesigner/internal/signer"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/vectors"
)

// testGenesis is the genesis time the RANDAO tests' clock counts from.
const testGenesis = 1_760_000_000

// testClock is a settable clock.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) atSlot(s, secondsPerSlot uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = time.Unix(int64(testGenesis+s*secondsPerSlot), 0)
}

type randaoFixture struct {
	*signFixture
	reveal   *RandaoReveal
	reset    *RandaoReset
	svc      *randao.Service
	clock    *testClock
	sps      uint64
	forkInfo json.RawMessage
}

// presetNetwork returns the negative-fixture network of a preset: its
// config name, fork version and GVR.
func presetNetwork(t *testing.T, preset string) vectors.Network {
	t.Helper()
	for _, nf := range vectors.Negative(t) {
		if nf.Preset == preset {
			return nf.Network
		}
	}
	t.Fatalf("no network for preset %s", preset)
	return vectors.Network{}
}

// newRandaoFixture builds the reveal handler over the interop keys on the
// network sources src, with a memory store.
func newRandaoFixture(t *testing.T, src network.Sources, o signOptions, cfg func(*randao.Config)) *randaoFixture {
	t.Helper()
	o.network = src
	sf := newSignFixture(t, o)
	n, err := network.Load(src)
	if err != nil {
		t.Fatal(err)
	}
	f := &randaoFixture{signFixture: sf, clock: &testClock{}, sps: n.Config.SecondsPerSlot}
	f.clock.atSlot(1000, f.sps)
	rc := randao.Config{
		Store: sf.store, GenesisTime: testGenesis, GenesisKnown: true,
		SecondsPerSlot: n.Config.SecondsPerSlot, SlotsPerEpoch: n.Config.SlotsPerEpoch, ClockSkewSlots: 1,
		MaxLayers: randao.DefaultMaxLayers, ReorgWindow: randao.DefaultReorgWindow,
		FullScanMinInterval: time.Duration(n.Config.SecondsPerSlot) * time.Second,
		NewLayerBurst:       randao.DefaultNewLayerBurst, NewLayerRefillEpochs: randao.DefaultRefillEpochs,
		Now: f.clock.Now, Metrics: sf.m, Log: sf.log,
	}
	if cfg != nil {
		cfg(&rc)
	}
	f.svc = randao.New(rc)
	t.Cleanup(f.svc.Close)
	f.reveal = &RandaoReveal{Policy: sf.pol, Signer: sf.h.Signer, Reveals: f.svc, Pinner: sf.store, Metrics: sf.m, Log: sf.log}
	f.reset = &RandaoReset{Reveals: f.svc, Log: sf.log}
	return f
}

// newPresetFixture binds the handler to a preset's network and GVR.
func newPresetFixture(t *testing.T, preset string, cfg func(*randao.Config)) *randaoFixture {
	t.Helper()
	n := presetNetwork(t, preset)
	f := newRandaoFixture(t, goldenSources(t, n), signOptions{}, cfg)
	f.forkInfo = forkInfoOf(n)
	return f
}

func forkInfoOf(n vectors.Network) json.RawMessage {
	return json.RawMessage(`{"fork":{"previous_version":"` + n.GenesisForkVersion + `","current_version":"` +
		n.GenesisForkVersion + `","epoch":"0"},"genesis_validators_root":"` + n.GVR + `"}`)
}

func revealBody(slot uint64, commitment string, forkInfo json.RawMessage) []byte {
	return []byte(`{"slot":"` + strconv.FormatUint(slot, 10) + `","randao_commitment":"` + commitment +
		`","fork_info":` + string(forkInfo) + `}`)
}

func (f *randaoFixture) post(ident string, body []byte) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/consensus/randao_reveal/"+ident, bytes.NewReader(body))
	r.SetPathValue("identifier", ident)
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.reveal.ServeHTTP(rec, r)
	return rec
}

func (f *randaoFixture) del(h http.Handler, ident string) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/consensus/randao_state/"+ident, nil)
	r.SetPathValue("identifier", ident)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// revealOf decodes a 200 response.
func revealOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || len(resp) != 1 || resp["randao_reveal"] == "" {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	return resp["randao_reveal"]
}

func (f *randaoFixture) reveals(result string) float64 {
	return counter(f.t, f.m.RandaoReveals.WithLabelValues(result))
}

// V5 (randao/requests.json): every refused request gets its status and
// reason; then the first reveal of keys 0 and 1 is the interop first
// reveal.
func TestRandaoGoldenRequests(t *testing.T) {
	var file struct {
		Cases []vectors.RandaoRequest `json:"cases"`
	}
	vectors.Load(t, "randao/requests.json", &file)
	keys := vectors.Keys(t)
	for _, preset := range vectors.Presets {
		t.Run(preset, func(t *testing.T) {
			t.Parallel()
			f := newPresetFixture(t, preset, nil)
			const now = 1000
			n := 0
			for _, c := range file.Cases {
				if c.Preset != preset {
					continue
				}
				n++
				slot := uint64(now + c.SlotOffset)
				rec := f.post(keys[c.KeyIndex].Pubkey, revealBody(slot, c.RandaoCommitment, c.ForkInfo))
				if got := reason(t, rec, c.Expect.Status); string(got) != c.Expect.Reason {
					t.Fatalf("%s: reason %s, want %s", c.Name, got, c.Expect.Reason)
				}
			}
			if n < 5 {
				t.Fatalf("only %d cases", n)
			}
			for _, k := range keys[:2] {
				got := revealOf(t, f.post(k.Pubkey, revealBody(now, k.RandaoCommitment, f.forkInfo)))
				if got != k.RandaoFirstReveal {
					t.Fatalf("key %d: reveal %s, want %s", k.Index, got, k.RandaoFirstReveal)
				}
			}
			if f.reveals(metrics.RandaoFirstUse) != 2 || f.reveals(metrics.RandaoRefused) != 4 {
				t.Fatalf("first_use %v refused %v", f.reveals(metrics.RandaoFirstUse), f.reveals(metrics.RandaoRefused))
			}
		})
	}
}

// V6 (randao/frontier.json): G1 §5 scenarios 1-15 as scripted HTTP
// sequences, each from an empty state, with the stored frontier checked
// after every step. Scenario 7 (the BN orphaning the validator's own late
// block) is a new layer at the signer, as in next_proposal; 9 (a second
// signer) is gap_advanced.
func TestRandaoFrontierScripts(t *testing.T) {
	var fr vectors.Frontier
	vectors.Load(t, "randao/frontier.json", &fr)
	if len(fr.Scripts) < 15 {
		t.Fatalf("only %d scripts", len(fr.Scripts))
	}
	k := vectors.Keys(t)[fr.KeyIndex]
	preset := map[string]string{"end-to-end": "minimal", "end-to-end-mainnet": "mainnet"}[fr.Network]
	for _, sc := range fr.Scripts {
		t.Run(sc.Name, func(t *testing.T) {
			t.Parallel()
			sig := sc.Signer
			f := newPresetFixture(t, preset, func(c *randao.Config) {
				c.MaxLayers, c.ReorgWindow, c.ClockSkewSlots = sig.RandaoMaxLayers, sig.RandaoReorgWindow, sig.SigningClockSkewSlots
				c.NewLayerBurst, c.NewLayerRefillEpochs = sig.RandaoNewLayerBurst, sig.RandaoNewLayerRefillEpochs
				c.FullScanMinInterval = time.Duration(sig.RandaoFullScanMinIntervalSlots*c.SecondsPerSlot) * time.Second
			})
			id := slashing.KeyID(f.pks[fr.KeyIndex].ID())
			for i, st := range sc.Steps {
				f.clock.atSlot(vectors.U64(t, st.NowSlot), f.sps)
				before := f.reveals(st.Expect.Result)
				rec := f.post(k.Pubkey, revealBody(vectors.U64(t, st.Slot), st.RandaoCommitment, f.forkInfo))
				if st.Expect.Status == 200 {
					if got := revealOf(t, rec); got != st.Expect.RandaoReveal {
						t.Fatalf("step %d: reveal %s, want %s", i, got, st.Expect.RandaoReveal)
					}
				} else if got := reason(t, rec, st.Expect.Status); string(got) != st.Expect.Reason {
					t.Fatalf("step %d: reason %s, want %s", i, got, st.Expect.Reason)
				}
				if st.Expect.Status == 429 && rec.Header().Get("Retry-After") == "" {
					t.Fatalf("step %d: 429 without Retry-After", i)
				}
				if got := f.reveals(st.Expect.Result) - before; got != 1 {
					t.Fatalf("step %d: result %s counted %v times", i, st.Expect.Result, got)
				}
				state, ok, err := f.store.RandaoState(context.Background(), id)
				if err != nil {
					t.Fatal(err)
				}
				want := st.Expect.State
				switch {
				case want == nil && ok:
					t.Fatalf("step %d: state %+v, want none", i, state)
				case want != nil && (!ok || state.Index != want.M || state.Reveal != vectors.Hex32(t, want.Reveal) ||
					state.LastSlot != vectors.U64(t, want.Last)):
					t.Fatalf("step %d: state %+v (%v), want %+v", i, state, ok, *want)
				}
			}
		})
	}
}

// The handler's own refusals: identifier, body, fork_info, unknown and
// quarantined keys, a key without a seed, and the trust-on-first-use pin.
func TestRandaoHandlerRefusals(t *testing.T) {
	f := newPresetFixture(t, "minimal", nil)
	k := vectors.Keys(t)[0]
	good := revealBody(1000, k.RandaoCommitment, f.forkInfo)
	n := presetNetwork(t, "minimal")
	tests := []struct {
		name   string
		ident  string
		body   []byte
		status int
		reason apierr.Reason
	}{
		{"bad identifier", "0x1234", good, 400, apierr.BadIdentifier},
		{"unknown key", "0x" + strings.Repeat("ab", 32), good, 404, apierr.UnknownKey},
		{"missing fork_info", k.Pubkey, []byte(`{"slot":"1000","randao_commitment":"` + k.RandaoCommitment + `"}`), 400, apierr.MissingForkInfo},
		{"unknown field", k.Pubkey, edit(t, good, func(v map[string]any) { v["epoch"] = "1" }), 400, apierr.UnknownField},
		{"numeric slot", k.Pubkey, edit(t, good, func(v map[string]any) { v["slot"] = 1000 }), 400, apierr.BadField},
		{"wrong GVR", k.Pubkey, revealBody(1000, k.RandaoCommitment, forkInfoOf(vectors.Network{
			GenesisForkVersion: n.GenesisForkVersion, GVR: "0x" + strings.Repeat("11", 32)})), 400, apierr.ForkInfoMismatch},
		{"wrong fork", k.Pubkey, revealBody(1000, k.RandaoCommitment, forkInfoOf(vectors.Network{
			GenesisForkVersion: "0x000000fe", GVR: n.GVR})), 400, apierr.ForkInfoMismatch},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := reason(t, f.post(tc.ident, tc.body), tc.status); got != tc.reason {
				t.Fatalf("reason %s, want %s", got, tc.reason)
			}
		})
	}
	if f.reveals(metrics.RandaoRefused) != 0 || f.reveals(metrics.RandaoError) != 0 {
		t.Fatal("400 and 404 are not counted")
	}
	// The sha256 alias names the same key.
	if got := revealOf(t, f.post(f.alias(0), good)); got != k.RandaoFirstReveal {
		t.Fatalf("alias reveal %s", got)
	}

	t.Run("quarantined", func(t *testing.T) {
		f := newRandaoFixture(t, goldenSources(t, n), signOptions{corrupt: true}, nil)
		var c vectors.SignCase
		for _, sc := range firstCases(t) {
			if sc.KeyIndex == 0 {
				c = sc
				break
			}
		}
		if rec := f.signFixture.post(f.ident(0), c.RequestJSON); rec.Code != 500 {
			t.Fatalf("faulty sign: %d", rec.Code)
		}
		if r := reason(t, f.post(f.ident(0), revealBody(1000, k.RandaoCommitment, forkInfoOf(n))), 503); r != apierr.KeyQuarantined {
			t.Fatalf("reason %s", r)
		}
		if f.reveals(metrics.RandaoError) != 1 {
			t.Fatal("503 not counted as error")
		}
	})

	t.Run("no seed", func(t *testing.T) {
		f := newPresetFixture(t, "minimal", nil)
		f.reveal.Signer = signer.New(signer.Config{
			Lookup: func(id signer.ID) (signer.Key, bool) {
				k, ok := f.keys[id]
				return noSeed{k.Key}, ok
			},
			SelectionProofMode: mldsa87.Deterministic,
			Log:                f.log,
		})
		if r := reason(t, f.post(f.ident(0), good), 422); r != apierr.RandaoUnsupportedForKey {
			t.Fatalf("reason %s", r)
		}
		if f.reveals(metrics.RandaoRefused) != 1 {
			t.Fatal("422 not counted as refused")
		}
	})

	t.Run("pins the GVR on first use", func(t *testing.T) {
		genesis := uint64(testGenesis)
		f := newRandaoFixture(t, network.Sources{Network: fileNetwork, GenesisTime: &genesis}, signOptions{}, nil)
		if _, pinned := f.pol.GenesisValidatorsRoot(); pinned {
			t.Fatal("pinned before the first request")
		}
		if got := revealOf(t, f.post(f.ident(0), revealBody(1000, k.RandaoCommitment, forkInfoOf(n)))); got != k.RandaoFirstReveal {
			t.Fatalf("reveal %s", got)
		}
		gvr, pinned := f.pol.GenesisValidatorsRoot()
		if !pinned || gvr != vectors.Hex32(t, n.GVR) {
			t.Fatal("the first reveal did not pin the GVR")
		}
		if stored, ok, _ := f.store.GenesisValidatorsRoot(context.Background()); !ok || stored != slashing.Root(gvr) {
			t.Fatal("the store was not pinned")
		}
	})
}

// noSeed is a key that signs but lends no seed, like a future KMS key.
type noSeed struct{ k *mldsa87.Key }

func (n noSeed) PublicKey() mldsa87.PublicKey { return n.k.PublicKey() }
func (n noSeed) Sign(m []byte, mode mldsa87.Mode) (signer.Signature, error) {
	return n.k.Sign(m, mode)
}

// The admin reset clears the frontier: the next reveal is a first use.
func TestRandaoReset(t *testing.T) {
	f := newPresetFixture(t, "minimal", nil)
	k := vectors.Keys(t)[0]
	revealOf(t, f.post(k.Pubkey, revealBody(1000, k.RandaoCommitment, f.forkInfo)))

	if r := reason(t, f.del(f.reset, "0x12"), 400); r != apierr.BadIdentifier {
		t.Fatalf("bad identifier: %s", r)
	}
	if r := reason(t, f.del(f.reset, "0x"+strings.Repeat("cd", 32)), 404); r != apierr.UnknownKey {
		t.Fatalf("unknown key: %s", r)
	}
	rec := f.del(f.reset, f.alias(0))
	if rec.Code != 200 || rec.Body.String() != `{"code":200,"message":"randao state cleared"}` {
		t.Fatalf("reset: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.del(f.reset, k.Pubkey); rec.Code != 200 {
		t.Fatalf("reset without state: %d", rec.Code)
	}
	f.clock.atSlot(1001, f.sps)
	revealOf(t, f.post(k.Pubkey, revealBody(1001, k.RandaoCommitment, f.forkInfo)))
	if f.reveals(metrics.RandaoFirstUse) != 2 {
		t.Fatalf("first_use %v, want 2", f.reveals(metrics.RandaoFirstUse))
	}

	disabled := &RandaoReset{Log: f.log}
	if r := reason(t, f.del(disabled, k.Pubkey), 404); r != apierr.ProtectionDisabled {
		t.Fatalf("protection disabled: %s", r)
	}
}
