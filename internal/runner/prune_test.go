// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/server/auth"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/boltstore"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

// messageHook sends every log message to a channel.
type messageHook chan string

func (h messageHook) Levels() []logrus.Level { return logrus.AllLevels }

func (h messageHook) Fire(e *logrus.Entry) error {
	select {
	case h <- e.Message:
	default:
	}
	return nil
}

func hookedLogger() (*logrus.Logger, messageHook) {
	l := logrus.New()
	l.SetOutput(io.Discard)
	h := make(messageHook, 1024)
	l.AddHook(h)
	return l, h
}

// waitFor waits for a log message that starts with prefix.
func (h messageHook) waitFor(t *testing.T, prefix string) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case m := <-h:
			if strings.HasPrefix(m, prefix) {
				return
			}
		case <-deadline:
			t.Fatalf("no log message %q", prefix)
		}
	}
}

// seedHistory writes a validator with blocks at slots 0..n-1 and attestations (i, i) for i < n, a watermark at 0,
// and a high watermark, into a closed store.
func seedHistory(t *testing.T, path string, n int) slashing.KeyID {
	t.Helper()
	ctx := context.Background()
	s, err := boltstore.Open(path, boltstore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if err := s.RegisterValidators(ctx, [][]byte{slashingtest.Key(0)}); err != nil {
		t.Fatal(err)
	}
	id := slashing.KeyIDOf(slashingtest.Key(0))
	err = s.UpdateHistory(ctx, []slashing.KeyID{id}, func(_ slashing.KeyID, tx slashing.HistoryTx) error {
		for i := range uint64(n) {
			if err := tx.InsertBlock(slashing.SignedBlock{Slot: i, SigningRoot: slashingtest.RootPtr(i)}); err != nil {
				return err
			}
			if err := tx.InsertAttestation(slashing.SignedAttestation{SourceEpoch: i, TargetEpoch: i,
				SigningRoot: slashingtest.RootPtr(i)}); err != nil {
				return err
			}
		}
		if err := tx.RaiseSlotLowWatermark(0); err != nil {
			return err
		}
		return tx.RaiseEpochLowWatermarks(0, 0)
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PinGenesisValidatorsRoot(ctx, slashingtest.GVR); err != nil {
		t.Fatal(err)
	}
	if err := s.SetHighWatermark(ctx, slashing.HighWatermark{Epoch: slashingtest.U64(1200), Slot: slashingtest.U64(7200)}); err != nil {
		t.Fatal(err)
	}
	return id
}

// The signer prunes at startup, with the network's slots per epoch (6 on the end-to-end network), and serves the
// store's high watermark to the sign scope.
func TestRunPrunesAtStartupAndServesHighWatermark(t *testing.T) {
	cfg := baseConfig(t)
	cfg.Consensus.Pruning.EpochsToKeep = 2
	id := seedHistory(t, cfg.SlashingProtectionDB(), 20)
	log, hook := hookedLogger()
	r := startWithLog(t, cfg, log)
	hook.waitFor(t, "Slashing-protection pruning finished")
	r.waitReady(t)

	code, body := r.do(t, http.MethodGet, "/api/v1/consensus/highWatermark", r.sign)
	if code != 200 || string(body) != `{"epoch":"1200","slot":"7200"}` {
		t.Fatalf("highWatermark: %d %s", code, body)
	}
	conforms(t, "HighWatermark", body)
	if code, _ := r.do(t, http.MethodGet, "/api/v1/consensus/highWatermark", ""); code != 401 {
		t.Fatalf("highWatermark without a token: %d", code)
	}
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}

	s, err := boltstore.Open(cfg.SlashingProtectionDB(), boltstore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	var blocks, atts []uint64
	var low slashing.LowWatermark
	err = s.ViewHistory(context.Background(), func(v slashing.HistoryView) error {
		if low, err = v.LowWatermark(id); err != nil {
			return err
		}
		if err := v.Blocks(id, func(b slashing.SignedBlock) error { blocks = append(blocks, b.Slot); return nil }); err != nil {
			return err
		}
		return v.Attestations(id, func(a slashing.SignedAttestation) error { atts = append(atts, a.TargetEpoch); return nil })
	})
	if err != nil {
		t.Fatal(err)
	}
	// Two epochs: attestations 18 and 19, and 2 × 6 = 12 slots of blocks, 8 to 19.
	if len(atts) != 2 || atts[0] != 18 || len(blocks) != 12 || blocks[0] != 8 || *low.Slot != 8 || *low.TargetEpoch != 18 {
		t.Fatalf("after pruning: blocks %v, attestations %v, low %+v", blocks, atts, low)
	}
}

func TestRunHighWatermarkProtectionDisabled(t *testing.T) {
	cfg := baseConfig(t)
	cfg.Consensus.SlashingProtectionEnabled = false
	cfg.HTTP.AuthMode = auth.ModeNone
	r := start(t, cfg)
	code, body := r.do(t, http.MethodGet, "/api/v1/consensus/highWatermark", "")
	if code != 404 || !strings.Contains(string(body), `"reason":"PROTECTION_DISABLED"`) {
		t.Fatalf("highWatermark with protection disabled: %d %s", code, body)
	}
	conforms(t, "ErrorResponse", body)
}

// The pruner runs again at each interval, and stops with the signer.
func TestPrunerRunsAtEveryInterval(t *testing.T) {
	cfg := baseConfig(t)
	path := cfg.SlashingProtectionDB()
	seedHistory(t, path, 4)
	s, err := boltstore.Open(path, boltstore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	log, hook := hookedLogger()
	cfg.Consensus.Pruning.Interval = 20 * time.Millisecond
	p := startPruner(s, cfg.Consensus.Pruning, 6, false, log)
	for range 3 {
		hook.waitFor(t, "Slashing-protection pruning finished")
	}
	p.stop()
	p.stop() // a second stop is harmless
	var none *pruner
	none.stop()
}
