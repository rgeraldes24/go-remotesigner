// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/signingroot"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/pgstore"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/pgstore/pgtest"
	"github.com/rgeraldes24/go-remotesigner/internal/vectors"
)

// usePostgres points cfg at a fresh migrated database, through proxy when it is set.
func usePostgres(t *testing.T, cfg *config.Config, db *pgtest.DB, proxy func(target string) string) {
	t.Helper()
	u, err := url.Parse(db.URL)
	if err != nil {
		t.Fatal(err)
	}
	if proxy != nil {
		u.Host = proxy(u.Host)
	}
	cfg.Consensus.Postgres = config.Postgres{URL: u.String(), PasswordFile: db.PasswordFile(t),
		HealthCheckTimeout: 300 * time.Millisecond, HealthCheckInterval: 100 * time.Millisecond}
}

func migratedDB(t *testing.T) *pgtest.DB {
	t.Helper()
	db := pgtest.New(t)
	if _, err := pgstore.Migrate(context.Background(), pgstore.Config{URL: db.URL, Password: db.Password}); err != nil {
		t.Fatal(err)
	}
	return db
}

// waitHealth polls the slashing-protection-db-health-check until it reports want.
func (r *running) waitHealth(t *testing.T, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, body := r.do(t, http.MethodGet, "/healthcheck", r.sign)
		if strings.Contains(string(body), `{"id":"slashing-protection-db-health-check","status":"`+want+`"}`) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("health check never %s: %s", want, body)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The signer runs on the Postgres store: capabilities say so, it signs and refuses a double vote, reveals, resets a
// frontier online and reports the database's health. A stalled database fails a signing request in at most 5 s
// with 500 STORE_UNAVAILABLE and turns the health check DOWN; once it answers again the signer recovers.
func TestRunPostgres(t *testing.T) {
	db := migratedDB(t)
	cfg := baseConfig(t)
	var proxy *pgtest.StallProxy
	usePostgres(t, cfg, db, func(target string) string {
		proxy = pgtest.NewStallProxy(t, target)
		return proxy.Addr()
	})
	writeInteropKeys(t, cfg.KeyConfigPath)
	log, hook := hookedLogger()
	r := startWithLog(t, cfg, log)
	r.waitReady(t)
	hook.waitFor(t, "Slashing-protection pruning scheduled: at every interval")

	code, body := r.do(t, http.MethodGet, "/api/v1/consensus/capabilities", r.sign)
	var caps struct {
		SlashingProtection string `json:"slashing_protection"`
	}
	if err := json.Unmarshal(body, &caps); code != 200 || err != nil || caps.SlashingProtection != "postgres" {
		t.Fatalf("capabilities: %d %s", code, body)
	}
	conforms(t, "Capabilities", body)

	att := goldenCase(t, "minimal", signingroot.Attestation, "typical")
	if code, body := r.post(t, signPath(att), r.sign, att.RequestJSON); code != 200 {
		t.Fatalf("attestation: %d %s", code, body)
	}
	var v map[string]any
	if err := json.Unmarshal(att.RequestJSON, &v); err != nil {
		t.Fatal(err)
	}
	delete(v, "signing_root")
	v["attestation"].(map[string]any)["beacon_block_root"] = "0x" + strings.Repeat("ee", 32)
	double, _ := json.Marshal(v)
	if code, body := r.post(t, signPath(att), r.sign, double); code != 412 ||
		!strings.Contains(string(body), `"reason":"SLASHING_DOUBLE_VOTE"`) {
		t.Fatalf("double vote: %d %s", code, body)
	}

	k := vectors.Keys(t)[0]
	fi := e2eForkInfo(t)
	if code, body := r.post(t, revealPath(k.Pubkey), r.sign, revealReq(nowSlot(), k.RandaoCommitment, fi)); code != 200 ||
		string(body) != `{"randao_reveal":"`+k.RandaoFirstReveal+`"}` {
		t.Fatalf("first use: %d %s", code, body)
	}
	if code, body := r.do(t, http.MethodDelete, "/api/v1/consensus/randao_state/"+k.Pubkey, r.admin); code != 200 {
		t.Fatalf("reset: %d %s", code, body)
	}
	if code, body := r.do(t, http.MethodGet, "/api/v1/consensus/highWatermark", r.sign); code != 200 || string(body) != `{}` {
		t.Fatalf("highWatermark: %d %s", code, body)
	}
	r.waitHealth(t, "UP")

	proxy.Stall()
	blk := goldenCase(t, "minimal", signingroot.BlockV2, "typical")
	began := time.Now()
	code, body = r.post(t, signPath(blk), r.sign, blk.RequestJSON)
	took := time.Since(began)
	if code != 500 || !strings.Contains(string(body), `"reason":"STORE_UNAVAILABLE"`) {
		t.Fatalf("block with the database stalled: %d %s", code, body)
	}
	if took > 5*time.Second {
		t.Fatalf("block with the database stalled answered after %v, want at most 5 s", took)
	}
	t.Logf("a stalled database failed the request after %v", took.Round(10*time.Millisecond))
	conforms(t, "ErrorResponse", body)
	r.waitHealth(t, "DOWN")

	proxy.Resume()
	r.waitHealth(t, "UP")
	deadline := time.Now().Add(10 * time.Second)
	for {
		code, body = r.post(t, signPath(blk), r.sign, blk.RequestJSON)
		if code == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("block after the database resumed: %d %s", code, body)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
}

// A database without the schema refuses to start, naming consensus migrate, unless --slashing-protection-db-migrate
// creates it; a newer schema always refuses.
func TestRunPostgresSchemaRefusals(t *testing.T) {
	db := pgtest.New(t)
	cfg := baseConfig(t)
	usePostgres(t, cfg, db, nil)
	err := Run(context.Background(), cfg, quiet(), nil)
	if !errors.Is(err, slashing.ErrSchemaTooOld) || !strings.Contains(err.Error(), "consensus migrate") {
		t.Fatalf("Run on an empty database: %v", err)
	}

	cfg.Consensus.SlashingProtectionDBMigrate = true
	r := start(t, cfg)
	r.waitReady(t)
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}

	db.Exec(t, `UPDATE database_version SET version = version + 1`)
	err = Run(context.Background(), cfg, quiet(), nil)
	if !errors.Is(err, slashing.ErrSchemaTooNew) || !strings.Contains(err.Error(), "downgrade is not supported") {
		t.Fatalf("Run on a newer schema: %v", err)
	}
}

// The password comes from its file or PGPASSFILE only: PGPASSWORD refuses to start, and so does an unreadable
// password file.
func TestRunPostgresPasswordSources(t *testing.T) {
	db := migratedDB(t)
	cfg := baseConfig(t)
	usePostgres(t, cfg, db, nil)
	t.Run("PGPASSWORD", func(t *testing.T) {
		t.Setenv("PGPASSWORD", db.Password)
		if err := Run(context.Background(), cfg, quiet(), nil); !errors.Is(err, pgstore.ErrPasswordInEnv) {
			t.Fatalf("Run with PGPASSWORD: %v", err)
		}
	})
	t.Run("unreadable file", func(t *testing.T) {
		c := *cfg
		c.Consensus.Postgres.PasswordFile = c.DataPath + "/missing"
		if err := Run(context.Background(), &c, quiet(), nil); err == nil ||
			!strings.Contains(err.Error(), "--slashing-protection-db-password-file") {
			t.Fatalf("Run with a missing password file: %v", err)
		}
	})
	t.Run("PGPASSFILE", func(t *testing.T) {
		u, _ := url.Parse(db.URL)
		pass := pgtest.WritePasswordFile(t, strings.Join([]string{u.Hostname(), u.Port(), db.Name, db.User, db.Password}, ":"))
		t.Setenv("PGPASSFILE", pass)
		c := *cfg
		c.Consensus.Postgres.PasswordFile = ""
		r := start(t, &c)
		r.waitReady(t)
		if err := r.stop(); err != nil {
			t.Fatal(err)
		}
	})
}
