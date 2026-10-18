// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package keymanager

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/argon"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystoretest"
	"github.com/rgeraldes24/go-remotesigner/internal/signer/provider"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/boltstore"
)

var bg = context.Background()

// gvr is the network the test stores are bound to.
var gvr = slashing.Root{0x94, 0x71, 0xe8, 0xfb}

// lockedBuffer collects log output safely.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// fixture is a Manager over a bbolt store in a temporary directory.
type fixture struct {
	dir     string
	keys    *provider.Provider
	store   slashing.Store
	engine  *slashing.Engine
	sem     *argon.Semaphore
	m       *Manager
	log     *lockedBuffer
	changed int
}

type fixtureOptions struct {
	unbound bool // the store has no genesis validators root
	store   func(slashing.Store) slashing.Store
}

func newFixture(t *testing.T, opts ...fixtureOptions) *fixture {
	t.Helper()
	var o fixtureOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	bo := boltstore.Options{}
	if !o.unbound {
		root := gvr
		bo.GenesisValidatorsRoot = &root
	}
	s, err := boltstore.Open(filepath.Join(t.TempDir(), "sp.db"), bo)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	f := &fixture{dir: filepath.Join(t.TempDir(), "keys"), store: s, sem: argon.New(4, 1<<30), log: &lockedBuffer{}}
	if o.store != nil {
		f.store = o.store(s)
	}
	if err := PrepareDir(f.dir, true, nil); err != nil {
		t.Fatal(err)
	}
	l := logrus.New()
	l.SetOutput(f.log)
	l.SetLevel(logrus.TraceLevel)
	f.keys = provider.New(l)
	t.Cleanup(f.keys.Close)
	f.engine = slashing.NewEngine(f.store)
	f.m = New(Config{
		Dir: f.dir, Keys: f.keys, Engine: f.engine, Store: f.store, History: true,
		GenesisValidatorsRoot: func() (slashing.Root, bool) { return gvr, !o.unbound },
		Decrypt:               f.sem.Decrypt, Workers: 4, Changed: func() { f.changed++ }, Log: l,
	})
	return f
}

var (
	sealerOnce sync.Once
	sealer     *keystoretest.Sealer
	sealerErr  error
)

const password = "correct horse battery staple"

// testKey is a key with its keystores.
type testKey struct {
	seed *[mldsa87.SeedSize]byte
	pk   mldsa87.PublicKey
	hex  string // 0x + 5,184 hex characters
}

func newKey(t *testing.T, tag string, i int) testKey {
	t.Helper()
	seed := keystoretest.Seed(tag, i)
	h, err := keystoretest.PublicKeyHex(seed)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := hex.DecodeString(h)
	pk, err := mldsa87.ParsePublicKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{seed: seed, pk: pk, hex: "0x" + h}
}

func testSealer(t *testing.T) *keystoretest.Sealer {
	t.Helper()
	sealerOnce.Do(func() { sealer, sealerErr = keystoretest.NewSealer(password, keystoretest.Cheapest) })
	if sealerErr != nil {
		t.Fatal(sealerErr)
	}
	return sealer
}

// qrlV1 is the key's qrysm keystore v1 under password.
func (k testKey) qrlV1(t *testing.T) []byte {
	t.Helper()
	ks, err := testSealer(t).QRLV1(k.seed, true)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

// depositCLI is the key's deposit CLI keystore (key i of its phrase).
func (k testKey) depositCLI(t *testing.T, i int) []byte {
	t.Helper()
	ks, err := testSealer(t).DepositCLI(k.seed, i, true)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

// edit changes a keystore's JSON.
func edit(t *testing.T, ks []byte, fn func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(ks, &m); err != nil {
		t.Fatal(err)
	}
	fn(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func kdfParams(m map[string]any) map[string]any {
	return m["crypto"].(map[string]any)["kdf"].(map[string]any)["params"].(map[string]any)
}

// importReq builds an import request; history is the interchange, or "".
func importReq(history string, pairs ...[]byte) ImportRequest {
	var r ImportRequest
	for i := 0; i+1 < len(pairs); i += 2 {
		r.Keystores = append(r.Keystores, bytes.Clone(pairs[i]))
		r.Passwords = append(r.Passwords, bytes.Clone(pairs[i+1]))
	}
	if history != "" {
		r.SlashingProtection = []byte(history)
	}
	return r
}

// entry is one interchange data element: blocks at slots and attestations
// (source, target).
func entry(pubkey string, slots []uint64, atts ...[2]uint64) string {
	var bs, as []string
	for _, s := range slots {
		bs = append(bs, fmt.Sprintf(`{"slot":"%d","signing_root":"0x%064x"}`, s, s))
	}
	for _, a := range atts {
		as = append(as, fmt.Sprintf(`{"source_epoch":"%d","target_epoch":"%d","signing_root":"0x%064x"}`, a[0], a[1], a[1]))
	}
	return fmt.Sprintf(`{"pubkey":"%s","signed_blocks":[%s],"signed_attestations":[%s]}`, pubkey,
		strings.Join(bs, ","), strings.Join(as, ","))
}

func doc(root slashing.Root, entries ...string) string {
	return `{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x` + hex.EncodeToString(root[:]) +
		`"},"data":[` + strings.Join(entries, ",") + `]}`
}

func statuses(rs []Result) []Status {
	out := make([]Status, len(rs))
	for i, r := range rs {
		out[i] = r.Status
	}
	return out
}

func wantStatuses(t *testing.T, rs []Result, want ...Status) {
	t.Helper()
	if got := statuses(rs); !slices.Equal(got, want) {
		t.Fatalf("statuses %v (%+v), want %v", got, rs, want)
	}
}

// files lists the key-config directory.
func (f *fixture) files(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func (f *fixture) status(t *testing.T, k testKey) slashing.ValidatorStatus {
	t.Helper()
	st, err := f.store.ValidatorStatus(bg, slashing.KeyID(k.pk.ID()))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// history returns a key's blocks, attestations and low watermark.
func (f *fixture) history(t *testing.T, k testKey) string {
	t.Helper()
	id := slashing.KeyID(k.pk.ID())
	var out strings.Builder
	err := f.store.ViewHistory(bg, func(v slashing.HistoryView) error {
		low, err := v.LowWatermark(id)
		if err != nil {
			return nil // unregistered
		}
		fmt.Fprintf(&out, "low %v %v %v;", deref(low.Slot), deref(low.SourceEpoch), deref(low.TargetEpoch))
		if err := v.Blocks(id, func(b slashing.SignedBlock) error {
			fmt.Fprintf(&out, " b%d", b.Slot)
			return nil
		}); err != nil {
			return err
		}
		return v.Attestations(id, func(a slashing.SignedAttestation) error {
			fmt.Fprintf(&out, " a%d-%d", a.SourceEpoch, a.TargetEpoch)
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func deref(p *uint64) any {
	if p == nil {
		return "-"
	}
	return *p
}

func (f *fixture) loaded(k testKey) bool {
	_, ok := f.keys.Entry(k.pk.ID())
	return ok
}
