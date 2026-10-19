// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/urfave/cli/v2"

	"github.com/rgeraldes24/go-remotesigner/cmd/remotesigner/flags"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/pgstore"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/pgstore/pgtest"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

// A store command's Postgres store holds one connection and bounds each call by pgstore.CommandTimeout, not by the
// signing bound: an online import writes a validator's whole history in one call.
func TestStoreCommandPostgresProfile(t *testing.T) {
	var got storeTarget
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{Name: flags.SlashingProtectionDBURL},
			&cli.StringFlag{Name: flags.SlashingProtectionDBUser},
		},
		Action: func(c *cli.Context) error {
			var err error
			got, err = targetOf(c, true)
			return err
		},
	}
	if err := app.Run([]string{binaryName, "--slashing-protection-db-url=postgres://signer@db.internal/signer",
		"--slashing-protection-db-username=ops"}); err != nil {
		t.Fatal(err)
	}
	if !got.postgres() {
		t.Fatalf("target %v, want the Postgres database", got)
	}
	if c := got.pg; c.MaxConns != 1 || c.MinConns != 0 || c.Timeout != pgstore.CommandTimeout || c.User != "ops" ||
		c.URL != "postgres://signer@db.internal/signer" {
		t.Errorf("store command's Postgres configuration %+v: want 1 connection, none kept open, %v per call, user ops",
			*c, pgstore.CommandTimeout)
	}
}

// An online import of a validator that already signs, with a history of more than 10,000 attestations, writes it
// all and leaves the key enabled. At two or three round trips per attestation such a history takes longer to write
// than the signing profile's 4.5 s per call, which used to fail the element and disable a key that every replica
// was serving.
func TestPostgresImportLongHistoryOnline(t *testing.T) {
	db := pgtest.New(t)
	store := []string{"--slashing-protection-db-url=" + db.URL, "--slashing-protection-db-password-file=" + db.PasswordFile(t)}
	if code, stdout, stderr := runCLI(t, append([]string{"consensus", "migrate"}, store...)...); code != exitOK {
		t.Fatalf("consensus migrate: exit %d %s %s", code, stdout, stderr)
	}

	// The key signs before the import, so the import reads its stored history too.
	ctx := context.Background()
	gvr := slashingtest.GVR
	s, err := pgstore.Open(ctx, pgstore.Config{URL: db.URL, Password: db.Password, GenesisValidatorsRoot: &gvr})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	e := slashing.NewEngine(s)
	if err := e.RegisterValidators(ctx, [][]byte{slashingtest.Key(0)}); err != nil {
		t.Fatal(err)
	}
	if d, err := e.CheckAndRecordAttestation(ctx, slashing.AttestationRequest{PublicKey: slashingtest.Key(0),
		GenesisValidatorsRoot: gvr, SourceEpoch: 0, TargetEpoch: 1, SigningRoot: slashingtest.RootOf(1)}); err != nil ||
		!d.Allowed {
		t.Fatalf("sign before the import: %+v %v", d, err)
	}

	const n = 10_500
	atts := make([]string, n)
	for i := range atts {
		target := uint64(i) + 2
		atts[i] = fmt.Sprintf(`{"source_epoch":"%d","target_epoch":"%d","signing_root":"%s"}`, target-1, target,
			rootHex(target))
	}
	file := interchangeFile(t, gvrHex, entry(0, ``, strings.Join(atts, ",")))
	code, stdout, stderr := runCLI(t, append([]string{"consensus", "import", "--from=" + file}, store...)...)
	if code != exitOK || !strings.Contains(stdout, "imported 1 of 1 validator(s)") ||
		!strings.Contains(stdout, fmt.Sprintf("0 block(s) and %d attestation(s) written", n)) {
		t.Fatalf("online import of %d attestations: exit %d\nstdout %s\nstderr %s", n, code, stdout, stderr)
	}
	if st := statusOf(t, s, 0); !st.Registered || !st.Enabled {
		t.Fatalf("the key after the import: %+v, want registered and enabled", st)
	}
	var rows int
	if err := db.Connect(t).QueryRow(ctx, `SELECT count(*) FROM signed_attestations`).Scan(&rows); err != nil || rows != n+1 {
		t.Fatalf("%d attestations stored (%v), want %d", rows, err, n+1)
	}
}
