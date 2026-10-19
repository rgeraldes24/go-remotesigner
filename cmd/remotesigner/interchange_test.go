// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/urfave/cli/v2"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/boltstore"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/interchange"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

var gvrHex = "0x" + hex.EncodeToString(slashingtest.GVR[:])

func pkHex(i int) string { return "0x" + hex.EncodeToString(slashingtest.Key(i)) }

func rootHex(n uint64) string {
	r := slashingtest.RootOf(n)
	return "0x" + hex.EncodeToString(r[:])
}

// interchangeFile writes an interchange document with the given data elements and returns its path.
func interchangeFile(t *testing.T, gvr string, entries ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "interchange.json")
	doc := `{"metadata":{"interchange_format_version":"5","genesis_validators_root":"` + gvr + `"},"data":[` +
		strings.Join(entries, ",") + `]}`
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func entry(key int, blocks, atts string) string {
	return `{"pubkey":"` + pkHex(key) + `","signed_blocks":[` + blocks + `],"signed_attestations":[` + atts + `]}`
}

// openTestStore opens the store at path for a check and closes it when the test ends.
func openTestStore(t *testing.T, path string) *boltstore.Store {
	t.Helper()
	s, err := boltstore.Open(path, boltstore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func statusOf(t *testing.T, s slashing.Store, key int) slashing.ValidatorStatus {
	t.Helper()
	st, err := s.ValidatorStatus(context.Background(), slashing.KeyIDOf(slashingtest.Key(key)))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func lowOf(t *testing.T, s slashing.Store, key int) slashing.LowWatermark {
	t.Helper()
	var low slashing.LowWatermark
	err := s.ViewHistory(context.Background(), func(v slashing.HistoryView) error {
		var err error
		low, err = v.LowWatermark(slashing.KeyIDOf(slashingtest.Key(key)))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return low
}

func closeStore(t *testing.T, s *boltstore.Store) {
	t.Helper()
	if err := s.Close(); err != nil && !errors.Is(err, boltstore.ErrClosed) {
		t.Fatal(err)
	}
}

func TestImportCommand(t *testing.T) {
	data := t.TempDir()
	db := filepath.Join(data, "slashing-protection.db")
	good := entry(0, `{"slot":"10","signing_root":"`+rootHex(1)+`"}`, `{"source_epoch":"1","target_epoch":"2"}`)
	// Key 1's attestation has a bad epoch: that element fails, and the others still import.
	bad := entry(1, ``, `{"source_epoch":"01","target_epoch":"2"}`)
	file := interchangeFile(t, gvrHex, good, bad, entry(2, `{"slot":"3"}`, ``))

	code, stdout, stderr := runCLI(t, "--data-path="+data, "consensus", "import", "--from="+file)
	if code != exitStartup || !strings.Contains(stdout, "imported 2 of 3 validator(s)") ||
		!strings.Contains(stderr, "data[1]") || !strings.Contains(stderr, "the key is disabled") ||
		!strings.Contains(stderr, "1 validator(s) failed to import") {
		t.Fatalf("import with a failing element: exit %d\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	s := openTestStore(t, db)
	if st := statusOf(t, s, 1); !st.Registered || st.Enabled {
		t.Fatalf("the failed key is %+v, want registered and disabled", st)
	}
	for _, k := range []int{0, 2} {
		if st := statusOf(t, s, k); !st.Enabled {
			t.Fatalf("key %d is %+v, want enabled", k, st)
		}
	}
	if low := lowOf(t, s, 0); *low.Slot != 10 || *low.SourceEpoch != 1 || *low.TargetEpoch != 2 {
		t.Fatalf("key 0 low watermark %+v", low)
	}

	// While a signer holds the store, import is refused.
	code, _, stderr = runCLI(t, "--data-path="+data, "consensus", "import", "--from="+file)
	if code != exitStartup || !strings.Contains(stderr, "stop the signer") {
		t.Fatalf("import into a held store: exit %d %s", code, stderr)
	}
	closeStore(t, s)

	// A clean file for key 1 imports, and its key is enabled again.
	fixed := interchangeFile(t, gvrHex, entry(1, ``, `{"source_epoch":"1","target_epoch":"2"}`))
	if code, stdout, stderr := runCLI(t, "--data-path="+data, "consensus", "import", "--from="+fixed); code != exitOK ||
		!strings.Contains(stdout, "imported 1 of 1 validator(s)") {
		t.Fatalf("clean import: exit %d %s %s", code, stdout, stderr)
	}
	s = openTestStore(t, db)
	if st := statusOf(t, s, 1); !st.Enabled {
		t.Fatalf("key 1 after a clean import: %+v", st)
	}
	closeStore(t, s)

	// A history that is already slashable imports, with a warning: (2, 5) surrounds (3, 4).
	slashable := interchangeFile(t, gvrHex, entry(3, ``, `{"source_epoch":"2","target_epoch":"5"},{"source_epoch":"3","target_epoch":"4"}`))
	if code, stdout, stderr := runCLI(t, "--data-path="+data, "consensus", "import", "--from="+slashable); code != exitOK ||
		!strings.Contains(stdout, "imported 1 of 1 validator(s)") ||
		!strings.Contains(stderr, "data[0] (key "+slashing.KeyIDOf(slashingtest.Key(3)).String()+"): 2 imported attestation(s)") ||
		!strings.Contains(stderr, "already slashable") {
		t.Fatalf("slashable import: exit %d %s %s", code, stdout, stderr)
	}
}

func TestImportCommandRefusals(t *testing.T) {
	data := t.TempDir()
	db := filepath.Join(data, "slashing-protection.db")
	truncated := filepath.Join(t.TempDir(), "truncated.json")
	if err := os.WriteFile(truncated, []byte(`{"metadata":{"interchange_format_version":"5","genesis_validators_root":"`+
		gvrHex+`"},"data":[`+entry(0, ``, ``)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
		code int
		want string
	}{
		{"missing --from", []string{"import"}, exitUsage, "--from is required"},
		{"unknown argument", []string{"import", "--from=x", "extra"}, exitUsage, "unexpected argument"},
		{"missing file", []string{"import", "--from=" + filepath.Join(data, "none.json")}, exitStartup, "no such file"},
		{"truncated file", []string{"import", "--from=" + truncated}, exitStartup, "nothing was imported"},
		{"other network", []string{"--network=e2e", "--network-genesis-validators-root=0x" + strings.Repeat("11", 32),
			"import", "--from=" + interchangeFile(t, gvrHex, entry(0, ``, ``))}, exitStartup, "genesis validators root"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"--data-path=" + data, "consensus"}, tc.args...)
			code, _, stderr := runCLI(t, args...)
			if code != tc.code || !strings.Contains(stderr, tc.want) {
				t.Fatalf("exit %d %q, want %d and %q", code, stderr, tc.code, tc.want)
			}
		})
	}
	// None of the refusals left a validator behind.
	if _, err := os.Stat(db); err == nil {
		s := openTestStore(t, db)
		if st := statusOf(t, s, 0); st.Registered {
			t.Fatalf("a refused import registered key 0: %+v", st)
		}
	}
}

func TestExportCommand(t *testing.T) {
	data := t.TempDir()
	db := filepath.Join(data, "slashing-protection.db")
	out := filepath.Join(t.TempDir(), "export.json")

	// A store that was never bound to a network cannot name one, unless the network does.
	closeStore(t, openTestStore(t, db))
	code, _, stderr := runCLI(t, "--data-path="+data, "consensus", "export", "--to="+out)
	if code != exitStartup || !strings.Contains(stderr, "--network") {
		t.Fatalf("export of an unbound store: exit %d %s", code, stderr)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("a failed export left a file")
	}
	code, stdout, stderr := runCLI(t, "--data-path="+data, "consensus", "--network=e2e",
		"--network-genesis-validators-root="+gvrHex, "export", "--to="+out)
	if code != exitOK || !strings.Contains(stdout, "exported 0 validator(s)") {
		t.Fatalf("empty export with the network's root: exit %d %s %s", code, stdout, stderr)
	}
	wantEmpty := "{\n  \"metadata\": {\n    \"interchange_format_version\": \"5\",\n    \"genesis_validators_root\": \"" +
		gvrHex + "\"\n  },\n  \"data\": []\n}\n"
	if got, _ := os.ReadFile(out); string(got) != wantEmpty {
		t.Fatalf("empty export:\n%s\nwant\n%s", got, wantEmpty)
	}

	// After an import the store names its own network; --keys selects validators by key or identifier.
	file := interchangeFile(t, gvrHex, entry(0, `{"slot":"10"}`, ``), entry(1, `{"slot":"11"}`, ``))
	if code, _, stderr := runCLI(t, "--data-path="+data, "consensus", "import", "--from="+file); code != exitOK {
		t.Fatalf("import: exit %d %s", code, stderr)
	}
	id1 := slashing.KeyIDOf(slashingtest.Key(1))
	code, stdout, stderr = runCLI(t, "--data-path="+data, "consensus", "export", "--to="+out,
		"--keys=0x"+hex.EncodeToString(id1[:])+","+pkHex(5))
	if code != exitOK || !strings.Contains(stdout, "exported 1 validator(s), 1 block(s)") ||
		!strings.Contains(stderr, "no history for key "+slashing.KeyIDOf(slashingtest.Key(5)).String()) {
		t.Fatalf("filtered export: exit %d %s %s", code, stdout, stderr)
	}
	got, _ := os.ReadFile(out)
	if !strings.Contains(string(got), pkHex(1)) || strings.Contains(string(got), pkHex(0)) {
		t.Fatalf("filtered export holds the wrong keys")
	}

	for args, want := range map[string]string{
		"export":                  "--to is required",
		"export --to=x --keys=0x": "--keys",
	} {
		code, _, stderr := runCLI(t, append([]string{"--data-path=" + data, "consensus"}, strings.Fields(args)...)...)
		if code != exitUsage || !strings.Contains(stderr, want) {
			t.Errorf("%s: exit %d %q", args, code, stderr)
		}
	}
	if code, _, stderr := runCLI(t, "--data-path="+t.TempDir(), "consensus", "export", "--to="+out); code != exitUsage ||
		!strings.Contains(stderr, "no slashing-protection store") {
		t.Fatalf("export without a store: exit %d %s", code, stderr)
	}
}

// seedWatermarks writes keys 0 and 1 with the given low watermarks into a store bound to the test network.
func seedWatermarks(t *testing.T, db string, lows ...slashing.LowWatermark) {
	t.Helper()
	ctx := context.Background()
	s := openTestStore(t, db)
	if _, err := s.PinGenesisValidatorsRoot(ctx, slashingtest.GVR); err != nil {
		t.Fatal(err)
	}
	for i, low := range lows {
		if err := s.RegisterValidators(ctx, [][]byte{slashingtest.Key(i)}); err != nil {
			t.Fatal(err)
		}
		err := s.UpdateHistory(ctx, []slashing.KeyID{slashing.KeyIDOf(slashingtest.Key(i))},
			func(_ slashing.KeyID, tx slashing.HistoryTx) error {
				if err := tx.RaiseSlotLowWatermark(*low.Slot); err != nil {
					return err
				}
				return tx.RaiseEpochLowWatermarks(*low.SourceEpoch, *low.TargetEpoch)
			})
		if err != nil {
			t.Fatal(err)
		}
	}
	closeStore(t, s)
}

func lw(slot, source, target uint64) slashing.LowWatermark {
	return slashing.LowWatermark{Slot: &slot, SourceEpoch: &source, TargetEpoch: &target}
}

func TestWatermarkRepairCommand(t *testing.T) {
	data := t.TempDir()
	db := filepath.Join(data, "slashing-protection.db")
	seedWatermarks(t, db, lw(10, 2, 3), lw(40, 5, 6))
	run := func(args ...string) (int, string, string) {
		return runCLI(t, append([]string{"--data-path=" + data, "consensus", "watermark-repair"}, args...)...)
	}

	// Both values are required: a missing one is a usage error (Web3Signer throws a NullPointerException).
	for _, args := range [][]string{{"--epoch=10"}, {"--slot=100"}, {}} {
		if code, _, stderr := run(args...); code != exitUsage || !strings.Contains(stderr, "--epoch and --slot are both required") {
			t.Fatalf("%v: exit %d %q", args, code, stderr)
		}
	}
	// Lowering any validator's watermark is refused, and nothing changes.
	code, _, stderr := run("--epoch=10", "--slot=20")
	if code != exitStartup || !strings.Contains(stderr, "watermark-repair refused") ||
		!strings.Contains(stderr, "lower the low watermark of 1 validator(s)") {
		t.Fatalf("lowering repair: exit %d %q", code, stderr)
	}
	s := openTestStore(t, db)
	if low := lowOf(t, s, 0); !reflect.DeepEqual(low, lw(10, 2, 3)) {
		t.Fatalf("key 0 after a refused repair: %+v", low)
	}
	closeStore(t, s)

	code, stdout, stderr := run("--epoch=10", "--slot=64")
	if code != exitOK || !strings.Contains(stdout, "raised the low watermarks of 2 validator(s)") {
		t.Fatalf("repair: exit %d %s %s", code, stdout, stderr)
	}
	s = openTestStore(t, db)
	for k := range 2 {
		if low := lowOf(t, s, k); !reflect.DeepEqual(low, lw(64, 10, 10)) {
			t.Fatalf("key %d after the repair: %+v", k, low)
		}
	}
	closeStore(t, s)

	// The keys have no records at or above the repaired watermarks: an export writes them as records of their own.
	out := filepath.Join(t.TempDir(), "export.json")
	code, stdout, stderr = runCLI(t, "--data-path="+data, "consensus", "export", "--to="+out)
	if code != exitOK || !strings.Contains(stdout, "exported 2 validator(s), 2 block(s) and 2 attestation(s)") ||
		!strings.Contains(stderr, "4 of the records stand for a low watermark") {
		t.Fatalf("export after the repair: exit %d %s %s", code, stdout, stderr)
	}
	if got, _ := os.ReadFile(out); strings.Count(string(got), `{"slot": "64"}`) != 2 ||
		strings.Count(string(got), `{"source_epoch": "10", "target_epoch": "10"}`) != 2 {
		t.Fatalf("export after the repair:\n%s", got)
	}

	// The repair stays below the high watermark.
	if code, _, stderr := runCLI(t, "--data-path="+data, "consensus", "set-high-watermark", "--epoch=20",
		"--slot=128"); code != exitOK {
		t.Fatalf("set-high-watermark: exit %d %s", code, stderr)
	}
	if code, _, stderr := run("--epoch=21", "--slot=100"); code != exitStartup || !strings.Contains(stderr, "high watermark") {
		t.Fatalf("repair above the high watermark: exit %d %q", code, stderr)
	}
}

func TestSetHighWatermarkCommand(t *testing.T) {
	data := t.TempDir()
	db := filepath.Join(data, "slashing-protection.db")
	run := func(args ...string) (int, string, string) {
		return runCLI(t, append([]string{"--data-path=" + data, "consensus", "set-high-watermark"}, args...)...)
	}
	for _, args := range [][]string{{"--epoch=1"}, {"--slot=1"}, {}, {"--remove", "--epoch=1"}} {
		if code, _, stderr := run(args...); code != exitUsage || !strings.Contains(stderr, "usage error") {
			t.Fatalf("%v: exit %d %q", args, code, stderr)
		}
	}

	// A store not bound to a network has no metadata to fence (Web3Signer's update silently changes nothing).
	closeStore(t, openTestStore(t, db))
	if code, _, stderr := run("--epoch=100", "--slot=12800"); code != exitStartup || !strings.Contains(stderr, "not bound to a network") {
		t.Fatalf("unbound store: exit %d %q", code, stderr)
	}
	// Naming the network binds the store, as the signer's startup would.
	if code, _, stderr := runCLI(t, "--data-path="+data, "consensus", "--network=e2e", "--network-genesis-validators-root="+gvrHex,
		"set-high-watermark", "--epoch=100", "--slot=12800"); code != exitOK {
		t.Fatalf("unbound store with --network: exit %d %q", code, stderr)
	}
	s := openTestStore(t, db)
	if gvr, ok, err := s.GenesisValidatorsRoot(context.Background()); err != nil || !ok || gvr != slashingtest.GVR {
		t.Fatalf("store root %x %v %v", gvr, ok, err)
	}
	closeStore(t, s)
	if err := os.Remove(db); err != nil {
		t.Fatal(err)
	}

	seedWatermarks(t, db, lw(640, 4, 5))
	if code, _, stderr := run("--epoch=5", "--slot=12800"); code != exitStartup || !strings.Contains(stderr, "above every validator's") {
		t.Fatalf("high watermark at a low watermark: exit %d %q", code, stderr)
	}
	code, stdout, stderr := run("--epoch=100", "--slot=12800")
	if code != exitOK || !strings.Contains(stdout, "set to epoch 100 and slot 12800") {
		t.Fatalf("set: exit %d %s %s", code, stdout, stderr)
	}
	s = openTestStore(t, db)
	h, err := s.HighWatermark(context.Background())
	if err != nil || *h.Epoch != 100 || *h.Slot != 12800 {
		t.Fatalf("high watermark %+v %v", h, err)
	}
	closeStore(t, s)
	if code, stdout, _ := run("--remove"); code != exitOK || !strings.Contains(stdout, "removed") {
		t.Fatalf("remove: exit %d %s", code, stdout)
	}
	s = openTestStore(t, db)
	if h, err := s.HighWatermark(context.Background()); err != nil || h.IsSet() {
		t.Fatalf("high watermark after --remove: %+v %v", h, err)
	}
	closeStore(t, s)
}

// An import that stopped with an error after elements were read reports them before it exits: which keys are
// disabled, and which could not be.
func TestFinishImport(t *testing.T) {
	stopped := errors.New("import x into y: disk full")
	key := func(i int) []byte { return slashingtest.Key(i) }
	res := interchange.ImportResult{Validators: []interchange.ValidatorResult{
		{Index: 0, PublicKey: key(0), Blocks: interchange.Counts{Imported: 2}},
		{Index: 1, PublicKey: key(1), Err: errors.New("not imported: disk full"), Disabled: true},
		{Index: 2, PublicKey: key(2), Err: errors.New("not imported: disk full; disabling the key also failed: disk full")},
	}}
	for _, tc := range []struct {
		name               string
		res                interchange.ImportResult
		err                error
		code               int
		exit, out, errText []string
	}{
		{name: "nothing read", err: stopped, code: exitStartup, exit: []string{stopped.Error()}},
		{name: "stopped after some elements", res: res, err: stopped, code: exitStartup,
			exit: []string{"disk full; the import stopped after 3 element(s): run it again", "2 validator(s) failed to import",
				"1 of their keys could not be disabled"},
			out: []string{"imported 1 of 3 validator(s) into db: 2 block(s)"},
			errText: []string{"data[1] (key " + slashing.KeyIDOf(key(1)).String() + "): not imported: disk full; the key is disabled",
				"data[2] (key " + slashing.KeyIDOf(key(2)).String() + "): not imported", "the key could not be disabled either"}},
		{name: "complete", res: interchange.ImportResult{Validators: res.Validators[:1]}, code: exitOK,
			out: []string{"imported 1 of 1 validator(s)"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr strings.Builder
			err := finishImport(&stdout, &stderr, "db", tc.res, tc.err)
			code, msg := exitOK, ""
			if err != nil {
				var ec cli.ExitCoder
				if !errors.As(err, &ec) {
					t.Fatalf("not an exit: %v", err)
				}
				code, msg = ec.ExitCode(), err.Error()
			}
			if code != tc.code {
				t.Fatalf("exit %d %q, want %d", code, msg, tc.code)
			}
			for _, want := range tc.exit {
				if !strings.Contains(msg, want) {
					t.Errorf("exit message %q lacks %q", msg, want)
				}
			}
			for _, want := range tc.out {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("stdout %q lacks %q", stdout.String(), want)
				}
			}
			for _, want := range tc.errText {
				if !strings.Contains(stderr.String(), want) {
					t.Errorf("stderr %q lacks %q", stderr.String(), want)
				}
			}
		})
	}
}

// The offline way to enable a disabled key again (docs/operations/reload.md
// section 5.1): export the key's own history and import that file. A key
// without history is left out of the export, and an element with empty
// lists enables it instead.
func TestEnableAgainByExportAndImport(t *testing.T) {
	data := t.TempDir()
	db := filepath.Join(data, "slashing-protection.db")
	file := interchangeFile(t, gvrHex, entry(0, `{"slot":"10","signing_root":"`+rootHex(1)+`"}`,
		`{"source_epoch":"1","target_epoch":"2","signing_root":"`+rootHex(2)+`"}`), entry(5, ``, ``))
	if code, stdout, stderr := runCLI(t, "--data-path="+data, "consensus", "import", "--from="+file); code != exitOK {
		t.Fatalf("import: exit %d %s %s", code, stdout, stderr)
	}
	for _, k := range []int{0, 5} {
		if code, _, stderr := runCLI(t, "--data-path="+data, "consensus", "disable-validator", "--key="+pkHex(k)); code != exitOK {
			t.Fatalf("disable key %d: exit %d %s", k, code, stderr)
		}
	}
	enabled := func(k int) bool {
		t.Helper()
		s := openTestStore(t, db)
		defer closeStore(t, s)
		return statusOf(t, s, k).Enabled
	}
	if enabled(0) || enabled(5) {
		t.Fatal("disable-validator left a key enabled")
	}

	own := filepath.Join(t.TempDir(), "key.json")
	code, _, stderr := runCLI(t, "--data-path="+data, "consensus", "export", "--keys="+pkHex(0)+","+pkHex(5), "--to="+own)
	if code != exitOK || !strings.Contains(stderr, "no history for key") {
		t.Fatalf("export: exit %d, stderr %q; want key 5 noted as without history", code, stderr)
	}
	if code, stdout, stderr := runCLI(t, "--data-path="+data, "consensus", "import", "--from="+own); code != exitOK ||
		!strings.Contains(stdout, "imported 1 of 1 validator(s)") || !strings.Contains(stdout, "already covered") {
		t.Fatalf("import of the key's own history: exit %d %s %s", code, stdout, stderr)
	}
	if !enabled(0) || enabled(5) {
		t.Fatalf("after importing key 0's own history: key 0 enabled %v, key 5 enabled %v", enabled(0), enabled(5))
	}

	empty := interchangeFile(t, gvrHex, entry(5, ``, ``))
	if code, stdout, stderr := runCLI(t, "--data-path="+data, "consensus", "import", "--from="+empty); code != exitOK {
		t.Fatalf("import of an empty element: exit %d %s %s", code, stdout, stderr)
	}
	if !enabled(5) {
		t.Fatal("an empty element did not enable key 5")
	}
}
