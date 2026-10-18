// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package pgstore_test

import (
	"context"
	"errors"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/interchange"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/pgstore"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/pgstore/pgtest"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

const rolesDoc = "../../../docs/operations/postgres.md"

// docSQL returns the statements of the SQL block that follows the marker <!-- postgres-roles:<name> --> in the
// operations page, with the page's names replaced by the test's.
func docSQL(t *testing.T, name string, names map[string]string) []string {
	t.Helper()
	page, err := os.ReadFile(rolesDoc)
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile("(?s)<!-- postgres-roles:" + name + " -->\n```sql\n(.*?)```").FindSubmatch(page)
	if m == nil {
		t.Fatalf("%s: no SQL block marked postgres-roles:%s", rolesDoc, name)
	}
	sql := string(m[1])
	// The longest name first: the database and the signers' role are both called remotesigner.
	sql = regexp.MustCompile(`\bremotesigner_owner\b`).ReplaceAllString(sql, names["owner"])
	sql = regexp.MustCompile(`\bDATABASE remotesigner\b`).ReplaceAllString(sql, "DATABASE "+names["database"])
	sql = regexp.MustCompile(`\bremotesigner\b`).ReplaceAllString(sql, names["signer"])
	var out []string
	for stmt := range strings.SplitSeq(sql, ";") {
		if stmt = strings.TrimSpace(stmt); stmt != "" {
			out = append(out, stmt)
		}
	}
	return out
}

// execAll runs each statement on its own (CREATE DATABASE cannot run in a transaction block).
func execAll(t *testing.T, dsn string, stmts []string) {
	t.Helper()
	for _, s := range stmts {
		pgtest.Exec(t, dsn, s)
	}
}

// The least-privilege setup of docs/operations/postgres.md, run as written: the owner creates the schema with
// Migrate, and the signers' role, which can change no schema object, signs, imports, prunes, exports, sets the high
// watermark, moves and resets a RANDAO frontier and disables a key.
func TestPostgresLeastPrivilegeRoles(t *testing.T) {
	pgtest.Skip(t)
	suffix := pgtest.Random(t, 6)
	names := map[string]string{"owner": "rs_owner_" + suffix, "signer": "rs_signer_" + suffix,
		"database": "rs_roles_" + suffix}
	t.Cleanup(func() {
		pgtest.ExecServer(t, `DROP DATABASE IF EXISTS `+names["database"]+` WITH (FORCE)`)
		pgtest.ExecServer(t, `DROP ROLE IF EXISTS `+names["owner"])
		pgtest.ExecServer(t, `DROP ROLE IF EXISTS `+names["signer"])
	})
	execAll(t, os.Getenv(pgtest.Env), docSQL(t, "server", names))
	ownerPW, signerPW := pgtest.Random(t, 16), pgtest.Random(t, 16)
	pgtest.ExecServer(t, `ALTER ROLE `+names["owner"]+` PASSWORD '`+ownerPW+`'`)
	pgtest.ExecServer(t, `ALTER ROLE `+names["signer"]+` PASSWORD '`+signerPW+`'`)

	admin, err := url.Parse(os.Getenv(pgtest.Env))
	if err != nil {
		t.Fatal(err)
	}
	as := func(role, password string) (string, pgstore.Config) {
		u := *admin
		u.Path = "/" + names["database"]
		u.User = url.UserPassword(role, password)
		withPW := u.String()
		u.User = url.User(role)
		return withPW, pgstore.Config{URL: u.String(), Password: password}
	}
	adminDSN, _ := as(admin.User.Username(), func() string { p, _ := admin.User.Password(); return p }())
	execAll(t, adminDSN, docSQL(t, "database", names))

	ownerDSN, ownerCfg := as(names["owner"], ownerPW)
	m, err := pgstore.Migrate(bg, ownerCfg)
	if err != nil || m.From != 0 || m.To != slashing.SchemaVersion {
		t.Fatalf("Migrate as the owner: %+v, %v", m, err)
	}
	execAll(t, ownerDSN, docSQL(t, "grants", names))

	signerDSN, signerCfg := as(names["signer"], signerPW)
	for _, stmt := range []string{
		`CREATE TABLE extra (id INTEGER)`,
		`DROP TABLE signed_blocks`,
		`ALTER TABLE validators ADD COLUMN extra INTEGER`,
		`UPDATE database_version SET version = 2`,
		`DELETE FROM validators`,
		`TRUNCATE signed_attestations`,
		`CREATE FUNCTION f() RETURNS INTEGER AS 'SELECT 1' LANGUAGE sql`,
	} {
		if err := tryExec(signerDSN, stmt); !denied(err) {
			t.Errorf("the signers' role ran %q: %v", stmt, err)
		}
	}

	s := open(t, signerCfg)
	e := slashing.NewEngine(s)
	keys := [][]byte{slashingtest.Key(0), slashingtest.Key(1)}
	must(t, e.RegisterValidators(bg, keys))
	d, err := e.CheckAndRecordBlock(bg, slashing.BlockRequest{PublicKey: keys[0], GenesisValidatorsRoot: slashingtest.GVR,
		Slot: 100, SigningRoot: slashingtest.RootOf(1)})
	if err != nil || !d.Allowed {
		t.Fatalf("block: %+v, %v", d, err)
	}
	d, err = e.CheckAndRecordAttestation(bg, slashing.AttestationRequest{PublicKey: keys[0],
		GenesisValidatorsRoot: slashingtest.GVR, SourceEpoch: 9, TargetEpoch: 10, SigningRoot: slashingtest.RootOf(2)})
	if err != nil || !d.Allowed {
		t.Fatalf("attestation: %+v, %v", d, err)
	}
	doc := interchangeDoc([]int{1, 2},
		map[int][]slashing.SignedBlock{1: {{Slot: 50, SigningRoot: importedRoot(3)}}, 2: {{Slot: 60, SigningRoot: importedRoot(4)}}},
		map[int][]slashing.SignedAttestation{1: {{SourceEpoch: 4, TargetEpoch: 5, SigningRoot: importedRoot(5)}}})
	res, err := interchange.Import(bg, s, strings.NewReader(doc), interchange.ImportOptions{Batch: 1})
	if err != nil || len(res.Failed()) > 0 {
		t.Fatalf("import: %+v, %v", res, err)
	}
	if _, err := slashing.Prune(bg, s, slashing.PruneConfig{EpochsToKeep: 1, SlotsPerEpoch: 1}); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if _, err := slashing.RepairLowWatermarks(bg, s, 101, 11); err != nil {
		t.Fatalf("watermark repair: %v", err)
	}
	must(t, s.SetHighWatermark(bg, slashing.HighWatermark{Epoch: slashingtest.U64(1000), Slot: slashingtest.U64(10000)}))
	must(t, s.SetHighWatermark(bg, slashing.HighWatermark{}))
	if _, err := interchange.Export(bg, s, io.Discard, interchange.ExportOptions{}); err != nil {
		t.Fatalf("export: %v", err)
	}
	next := slashing.RandaoState{Index: 9, Reveal: slashingtest.RootOf(9), LastSlot: 100}
	if ok, err := s.CompareAndSwapRandaoState(bg, key(0), nil, next); err != nil || !ok {
		t.Fatalf("first frontier: %v, %v", ok, err)
	}
	if ok, err := s.CompareAndSwapRandaoState(bg, key(0), &next, slashing.RandaoState{Index: 8, LastSlot: 101}); err != nil || !ok {
		t.Fatalf("frontier move: %v, %v", ok, err)
	}
	must(t, s.DeleteRandaoState(bg, key(0)))
	must(t, s.SetValidatorEnabled(bg, key(1), false))
	if st, err := s.ValidatorStatus(bg, key(1)); err != nil || st.Enabled {
		t.Fatalf("status after disabling: %+v, %v", st, err)
	}
}

func tryExec(dsn, sql string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(context.Background()) }()
	_, err = conn.Exec(ctx, sql)
	return err
}

// denied reports a refusal for want of privilege (42501) or ownership (42501 too, "must be owner").
func denied(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "42501"
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
