// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/boltstore"
	"github.com/rgeraldes24/go-remotesigner/internal/vectors"
)

// e2eForkInfo is the fork_info of the end-to-end network bound to the
// interop GVR.
func e2eForkInfo(t *testing.T) string {
	t.Helper()
	c := goldenCase(t, "minimal", "AGGREGATION_SLOT", "typical")
	return `{"fork":{"previous_version":"` + c.Network.GenesisForkVersion + `","current_version":"` +
		c.Network.GenesisForkVersion + `","epoch":"0"},"genesis_validators_root":"` + c.Network.GVR + `"}`
}

// nowSlot is the current slot of baseConfig's network (genesis 1760000000,
// 10 s slots).
func nowSlot() uint64 { return uint64(time.Now().Unix()-1_760_000_000) / 10 }

func revealPath(pubkey string) string { return "/api/v1/consensus/randao_reveal/" + pubkey }

func revealReq(slot uint64, commitment, forkInfo string) []byte {
	return []byte(`{"slot":"` + strconv.FormatUint(slot, 10) + `","randao_commitment":"` + commitment +
		`","fork_info":` + forkInfo + `}`)
}

// The signer reveals end to end: a first use, a new layer and a retry, the
// health check reports the layers left, the admin reset needs the admin
// token and makes the next reveal a first use, and the metrics count it all.
func TestRunRandao(t *testing.T) {
	cfg := baseConfig(t)
	cfg.Metrics = config.Metrics{Enabled: true, Host: "127.0.0.1", HostAllowlist: []string{"localhost", "127.0.0.1"}}
	cfg.Consensus.Randao.FullScanMinInterval = time.Millisecond
	writeInteropKeys(t, cfg.KeyConfigPath)
	r := start(t, cfg)
	r.waitReady(t)
	k := vectors.Keys(t)[0]
	fi := e2eForkInfo(t)
	s := nowSlot()

	code, body := r.post(t, revealPath(k.Pubkey), r.sign, revealReq(s, k.RandaoCommitment, fi))
	if code != 200 || string(body) != `{"randao_reveal":"`+k.RandaoFirstReveal+`"}` {
		t.Fatalf("first use: %d %s", code, body)
	}
	conforms(t, "RandaoRevealResponse", body)
	code, body = r.post(t, revealPath(k.Pubkey), r.sign, revealReq(s+1, k.RandaoFirstReveal, fi))
	if code != 200 {
		t.Fatalf("new layer: %d %s", code, body)
	}
	var next struct {
		Reveal string `json:"randao_reveal"`
	}
	_ = json.Unmarshal(body, &next)
	if code, body := r.post(t, revealPath(k.Pubkey), r.sign, revealReq(s+1, k.RandaoFirstReveal, fi)); code != 200 ||
		!strings.Contains(string(body), next.Reveal) {
		t.Fatalf("retry: %d %s", code, body)
	}
	code, body = r.post(t, revealPath(k.Pubkey), r.sign, revealReq(s+1, next.Reveal, fi))
	if code != 412 || !strings.Contains(string(body), `"reason":"RANDAO_SLOT_NOT_INCREASING"`) {
		t.Fatalf("second new layer in one slot: %d %s", code, body)
	}
	conforms(t, "ErrorResponse", body)

	code, body = r.do(t, http.MethodGet, "/healthcheck", r.sign)
	if code != 200 || !strings.Contains(string(body),
		`{"id":"keys-check/randao","status":"UP","data":{"keys-without-seed":0,"min-layers-remaining":1048574}}`) {
		t.Fatalf("healthcheck: %d %s", code, body)
	}
	conforms(t, "HealthCheck", body)

	reset := "/api/v1/consensus/randao_state/" + k.Pubkey
	if code, _ := r.do(t, http.MethodDelete, reset, r.sign); code != 403 {
		t.Fatalf("sign token on the reset: %d", code)
	}
	if code, _ := r.do(t, http.MethodDelete, reset, ""); code != 401 {
		t.Fatalf("no token on the reset: %d", code)
	}
	code, body = r.do(t, http.MethodDelete, reset, r.admin)
	if code != 200 || string(body) != `{"code":200,"message":"randao state cleared"}` {
		t.Fatalf("reset: %d %s", code, body)
	}
	conforms(t, "StatusMessage", body)
	if code, body := r.post(t, revealPath(k.Pubkey), r.sign, revealReq(s+1, next.Reveal, fi)); code != 200 {
		t.Fatalf("first use after the reset: %d %s", code, body)
	}

	code, text := r.scrape(t, "")
	if code != 200 {
		t.Fatalf("scrape: %d", code)
	}
	for _, want := range []string{
		`consensus_randao_reveals_total{result="first_use"} 2`,
		`consensus_randao_reveals_total{result="new_layer"} 1`,
		`consensus_randao_reveals_total{result="re_reveal"} 1`,
		`consensus_randao_reveals_total{result="refused"} 1`,
		`consensus_randao_reveals_total{result="gap_advanced"} 0`,
		`consensus_randao_reveals_total{result="error"} 0`,
		`consensus_randao_new_layer_rate_limited_total 0`,
		`consensus_randao_slow_path_scans_total 2`,
		`consensus_randao_min_layers_remaining 1.048573e+06`,
		`consensus_randao_reveal_duration_seconds_count{path="scan"}`,
		`http_request_duration_seconds_count{code="200",route="/api/v1/consensus/randao_reveal/{identifier}"} 4`,
		`http_request_duration_seconds_count{code="200",route="/api/v1/consensus/randao_state/{identifier}"} 1`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("scrape lacks %s", want)
		}
	}
}

// With protection disabled (loopback only) the frontier rule runs in
// memory, and the reset is 404 PROTECTION_DISABLED.
func TestRunRandaoProtectionDisabled(t *testing.T) {
	cfg := baseConfig(t)
	cfg.Consensus.SlashingProtectionEnabled = false
	writeInteropKeys(t, cfg.KeyConfigPath)
	r := start(t, cfg)
	r.waitReady(t)
	k := vectors.Keys(t)[1]
	fi := e2eForkInfo(t)
	s := nowSlot()
	if code, body := r.post(t, revealPath(k.Pubkey), r.sign, revealReq(s, k.RandaoCommitment, fi)); code != 200 ||
		!strings.Contains(string(body), k.RandaoFirstReveal) {
		t.Fatalf("first use: %d %s", code, body)
	}
	code, body := r.post(t, revealPath(k.Pubkey), r.sign, revealReq(s, k.RandaoFirstReveal, fi))
	if code != 412 || !strings.Contains(string(body), "RANDAO_SLOT_NOT_INCREASING") {
		t.Fatalf("the in-memory frontier is not enforced: %d %s", code, body)
	}
	code, body = r.do(t, http.MethodDelete, "/api/v1/consensus/randao_state/"+k.Pubkey, r.admin)
	if code != 404 || !strings.Contains(string(body), `"reason":"PROTECTION_DISABLED"`) {
		t.Fatalf("reset: %d %s", code, body)
	}
}

// writeSchemaVersion rewrites meta/schema_version of the store at path.
func writeSchemaVersion(t *testing.T, path string, v uint32) {
	t.Helper()
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("meta")).Put([]byte("schema_version"), binary.BigEndian.AppendUint32(nil, v))
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRunStoreMigrationAndRandaoRefusals(t *testing.T) {
	t.Run("older store names consensus migrate", func(t *testing.T) {
		cfg := baseConfig(t)
		s, err := boltstore.Open(cfg.SlashingProtectionDB(), boltstore.Options{})
		if err != nil {
			t.Fatal(err)
		}
		_ = s.Close()
		writeSchemaVersion(t, cfg.SlashingProtectionDB(), 0)
		err = Run(context.Background(), cfg, quiet(), nil)
		if !errors.Is(err, slashing.ErrSchemaTooOld) || !strings.Contains(err.Error(), "consensus migrate") {
			t.Fatalf("Run = %v", err)
		}
	})
	t.Run("migrate flag on a newer store", func(t *testing.T) {
		cfg := baseConfig(t)
		cfg.Consensus.SlashingProtectionDBMigrate = true
		writeNewerSchema(t, cfg.SlashingProtectionDB())
		err := Run(context.Background(), cfg, quiet(), nil)
		if !errors.Is(err, slashing.ErrSchemaTooNew) || !strings.Contains(err.Error(), "--slashing-protection-db-migrate") {
			t.Fatalf("Run = %v", err)
		}
	})
	t.Run("migrate flag on a current store and on none", func(t *testing.T) {
		cfg := baseConfig(t)
		cfg.Consensus.SlashingProtectionDBMigrate = true
		cfg.Consensus.SlashingProtectionDBPath = cfg.DataPath + "/elsewhere/sp.db"
		r := start(t, cfg) // no file yet: Open creates it current
		r.waitReady(t)
		if err := r.stop(); err != nil {
			t.Fatal(err)
		}
		r = start(t, cfg) // a current file: nothing to migrate
		r.waitReady(t)
		if _, err := os.Stat(cfg.Consensus.SlashingProtectionDBPath + ".v1.bak"); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("a current store was backed up")
		}
	})
	t.Run("RANDAO protection required", func(t *testing.T) {
		cfg := baseConfig(t)
		cfg.Consensus.SlashingProtectionEnabled = false
		cfg.Consensus.Randao.ProtectionRequired = true
		if err := Run(context.Background(), cfg, quiet(), nil); !errors.Is(err, config.ErrRandaoProtectionRequired) {
			t.Fatalf("Run = %v", err)
		}
	})
}
