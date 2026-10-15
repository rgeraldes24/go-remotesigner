// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package slashing_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/memstore"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

func TestPublicKeyLength(t *testing.T) {
	e := slashing.NewEngine(memstore.New())
	for _, n := range []int{0, 48, slashing.PublicKeyLength - 1, slashing.PublicKeyLength + 1} {
		pk := make([]byte, n)
		if err := e.RegisterValidators(ctx, [][]byte{slashingtest.Key(0), pk}); !errors.Is(err, slashing.ErrInvalidPublicKey) {
			t.Errorf("RegisterValidators(%d bytes): %v, want ErrInvalidPublicKey", n, err)
		}
		if _, err := e.CheckAndRecordBlock(ctx, slashing.BlockRequest{PublicKey: pk}); !errors.Is(err, slashing.ErrInvalidPublicKey) {
			t.Errorf("CheckAndRecordBlock(%d bytes): %v, want ErrInvalidPublicKey", n, err)
		}
		if _, err := e.CheckAndRecordAttestation(ctx, slashing.AttestationRequest{PublicKey: pk}); !errors.Is(err, slashing.ErrInvalidPublicKey) {
			t.Errorf("CheckAndRecordAttestation(%d bytes): %v, want ErrInvalidPublicKey", n, err)
		}
	}
	// A batch with one bad key registers nothing.
	if _, err := e.ValidatorEnabled(ctx, slashingtest.Key(0)); !errors.Is(err, slashing.ErrValidatorNotRegistered) {
		t.Errorf("ValidatorEnabled after a failed batch: %v, want ErrValidatorNotRegistered", err)
	}
}

func TestValidatorEnabled(t *testing.T) {
	f := newFixture(t)
	key := slashingtest.Key(0)
	for _, enabled := range []bool{true, false, true} {
		if err := f.engine.SetValidatorEnabled(ctx, key, enabled); err != nil {
			t.Fatal(err)
		}
		got, err := f.engine.ValidatorEnabled(ctx, key)
		if err != nil || got != enabled {
			t.Fatalf("ValidatorEnabled = %v, %v; want %v", got, err, enabled)
		}
	}
	if err := f.engine.SetValidatorEnabled(ctx, slashingtest.Key(1), false); !errors.Is(err, slashing.ErrValidatorNotRegistered) {
		t.Errorf("SetValidatorEnabled(unregistered): %v, want ErrValidatorNotRegistered", err)
	}
	// Registering again keeps the flag.
	f.disable()
	if err := f.engine.RegisterValidators(ctx, [][]byte{key}); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.engine.ValidatorEnabled(ctx, key); got {
		t.Error("re-registering re-enabled a disabled key")
	}
}

func TestEngineHighWatermark(t *testing.T) {
	f := newFixture(t)
	h := slashing.HighWatermark{Epoch: slashingtest.U64(4), Slot: slashingtest.U64(5)}
	f.highWatermark(h)
	got, err := f.engine.HighWatermark(ctx)
	if err != nil || !got.IsSet() || *got.Epoch != 4 || *got.Slot != 5 {
		t.Fatalf("HighWatermark = %+v, %v", got, err)
	}
}

// The pinned root is read from the store once and then served from memory.
func TestGenesisValidatorsRootIsCached(t *testing.T) {
	mem := memstore.New()
	counting := &pinCounter{Store: mem}
	e := slashing.NewEngine(counting)
	if err := e.RegisterValidators(ctx, [][]byte{slashingtest.Key(0)}); err != nil {
		t.Fatal(err)
	}
	for s := range uint64(5) {
		d, err := e.CheckAndRecordBlock(ctx, slashing.BlockRequest{
			PublicKey: slashingtest.Key(0), GenesisValidatorsRoot: slashingtest.GVR, Slot: 10 + s, SigningRoot: signingRoot,
		})
		if err != nil || !d.Allowed {
			t.Fatalf("block %d: %+v, %v", s, d, err)
		}
	}
	if counting.pins != 1 {
		t.Fatalf("PinGenesisValidatorsRoot called %d times, want 1", counting.pins)
	}
}

func TestStoreErrorsAreErrors(t *testing.T) {
	boom := errors.New("store unavailable")
	f := newFixture(t)
	e := slashing.NewEngine(&failingStore{Store: f.mem, err: boom})
	if err := e.RegisterValidators(ctx, [][]byte{slashingtest.Key(0)}); err != nil {
		t.Fatal(err)
	}
	d, err := e.CheckAndRecordBlock(ctx, slashing.BlockRequest{PublicKey: slashingtest.Key(0), GenesisValidatorsRoot: slashingtest.GVR, Slot: 1})
	if !errors.Is(err, boom) || d != (slashing.Decision{}) {
		t.Errorf("block: %+v, %v; want a zero decision and the store error", d, err)
	}
	d, err = e.CheckAndRecordAttestation(ctx, slashing.AttestationRequest{PublicKey: slashingtest.Key(0), GenesisValidatorsRoot: slashingtest.GVR})
	if !errors.Is(err, boom) || d != (slashing.Decision{}) {
		t.Errorf("attestation: %+v, %v; want a zero decision and the store error", d, err)
	}
}

func TestCheckSchema(t *testing.T) {
	tests := []struct {
		stored  uint32
		wantErr error
		message string
	}{
		{slashing.SchemaVersion, nil, ""},
		{0, slashing.ErrSchemaTooOld, "consensus migrate"},
		{slashing.SchemaVersion + 1, slashing.ErrSchemaTooNew, "downgrade is not supported"},
	}
	for _, tt := range tests {
		err := slashing.CheckSchema(ctx, versionStore{Store: memstore.New(), version: tt.stored})
		if tt.wantErr == nil {
			if err != nil {
				t.Errorf("version %d: %v", tt.stored, err)
			}
			continue
		}
		var se *slashing.SchemaError
		if !errors.Is(err, tt.wantErr) || !errors.As(err, &se) || se.Stored != tt.stored {
			t.Errorf("version %d: %v, want %v", tt.stored, err, tt.wantErr)
			continue
		}
		if !strings.Contains(err.Error(), tt.message) {
			t.Errorf("version %d: message %q does not mention %q", tt.stored, err, tt.message)
		}
	}
}

func TestKeyIDString(t *testing.T) {
	id := slashing.KeyIDOf(slashingtest.Key(0))
	if s := id.String(); len(s) != 18 || !strings.HasPrefix(s, "0x") {
		t.Errorf("KeyID.String() = %q, want 0x and 16 hex digits", s)
	}
}

type pinCounter struct {
	slashing.Store
	pins int
}

func (p *pinCounter) PinGenesisValidatorsRoot(ctx context.Context, gvr slashing.Root) (slashing.Root, error) {
	p.pins++
	return p.Store.PinGenesisValidatorsRoot(ctx, gvr)
}

type failingStore struct {
	slashing.Store
	err error
}

func (f *failingStore) UpdateBlocks(context.Context, slashing.KeyID, func(slashing.BlockTx) error) error {
	return f.err
}

func (f *failingStore) UpdateAttestations(context.Context, slashing.KeyID, func(slashing.AttestationTx) error) error {
	return f.err
}

type versionStore struct {
	slashing.Store
	version uint32
}

func (v versionStore) SchemaVersion(context.Context) (uint32, error) { return v.version, nil }
