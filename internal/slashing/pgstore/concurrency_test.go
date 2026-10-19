// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package pgstore_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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

// instances opens n stores on one database, each with its own pool: n signer processes sharing it.
func instances(t *testing.T, db *pgtest.DB, n int) []*pgstore.Store {
	t.Helper()
	out := make([]*pgstore.Store, n)
	for i := range out {
		out[i] = open(t, config(db))
	}
	return out
}

// deadlocks reads the number of deadlocks Postgres detected in the database. Backends report their statistics when
// they exit, so the stores must be closed first.
func deadlocks(t *testing.T, db *pgtest.DB) int64 {
	t.Helper()
	conn := db.Connect(t)
	var n int64
	if err := conn.QueryRow(bg, `SELECT deadlocks FROM pg_stat_database WHERE datname = $1`, db.Name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// importedRoot marks a root written by an import; the engines sign slashingtest.RootOf roots, whose first byte is
// 0xa5.
func importedRoot(n uint64) *slashing.Root {
	r := slashingtest.RootOf(n)
	r[0] = 0x1b
	return &r
}

// interchangeDoc is an EIP-3076 document with one element per key.
func interchangeDoc(keys []int, blocks map[int][]slashing.SignedBlock, atts map[int][]slashing.SignedAttestation) string {
	var b strings.Builder
	fmt.Fprintf(&b, `{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x%s"},"data":[`,
		hex.EncodeToString(slashingtest.GVR[:]))
	for i, k := range keys {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"pubkey":"0x%s","signed_blocks":[`, hex.EncodeToString(slashingtest.Key(k)))
		for j, blk := range blocks[k] {
			if j > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `{"slot":"%d","signing_root":"0x%s"}`, blk.Slot, hex.EncodeToString(blk.SigningRoot[:]))
		}
		b.WriteString(`],"signed_attestations":[`)
		for j, a := range atts[k] {
			if j > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `{"source_epoch":"%d","target_epoch":"%d","signing_root":"0x%s"}`, a.SourceEpoch,
				a.TargetEpoch, hex.EncodeToString(a.SigningRoot[:]))
		}
		b.WriteString(`]}`)
	}
	b.WriteString(`]}`)
	return b.String()
}

type signed struct {
	key            int
	block          bool
	slot           uint64
	source, target uint64
}

// Two signer instances on one database sign blocks and attestations for the same keys while imports, pruning
// runs and enable flips run against them through both. Afterwards:
//   - no two messages either instance allowed for a key conflict;
//   - no record an instance signed conflicts with a record written before it (the record ids give the order);
//   - no low watermark ever moved down;
//   - Postgres detected no deadlock, and no call failed.
func TestPostgresTwoInstancesSignImportPrune(t *testing.T) {
	db := migrated(t)
	stores := instances(t, db, 2)
	const keys = 4
	engines := make([]*slashing.Engine, len(stores))
	for i, s := range stores {
		engines[i] = slashing.NewEngine(s)
		all := make([][]byte, keys)
		for k := range all {
			all[k] = slashingtest.Key(k)
		}
		if err := engines[i].RegisterValidators(bg, all); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(bg, 3*time.Second)
	defer cancel()
	// The chain moves on: one epoch (and slot) every 20 ms, so that pruning keeps deleting while messages are
	// signed and imported around the head.
	began := time.Now()
	head := func() uint64 { return 100 + uint64(time.Since(began)/(20*time.Millisecond)) }

	var (
		mu       sync.Mutex
		allowed  []signed
		failures []error
		roots    atomic.Uint64
		wg       sync.WaitGroup
	)
	fail := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		failures = append(failures, err)
	}
	for w := range 8 {
		wg.Go(func() {
			r := rand.New(rand.NewPCG(uint64(w), 1))
			for ctx.Err() == nil {
				e := engines[r.IntN(len(engines))]
				k := r.IntN(keys)
				var (
					d   slashing.Decision
					err error
					rec = signed{key: k}
				)
				n := roots.Add(1)
				if r.IntN(3) == 0 {
					rec.block, rec.slot = true, head()+uint64(r.IntN(6))
					d, err = e.CheckAndRecordBlock(bg, slashing.BlockRequest{PublicKey: slashingtest.Key(k),
						GenesisValidatorsRoot: slashingtest.GVR, Slot: rec.slot, SigningRoot: slashingtest.RootOf(n)})
				} else {
					rec.target = head() + uint64(r.IntN(6))
					rec.source = rec.target - 1 - uint64(r.IntN(6))
					d, err = e.CheckAndRecordAttestation(bg, slashing.AttestationRequest{PublicKey: slashingtest.Key(k),
						GenesisValidatorsRoot: slashingtest.GVR, SourceEpoch: rec.source, TargetEpoch: rec.target,
						SigningRoot: slashingtest.RootOf(n)})
				}
				if err != nil {
					fail(fmt.Errorf("sign: %w", err))
					continue
				}
				if d.Allowed && !d.Repeat {
					mu.Lock()
					allowed = append(allowed, rec)
					mu.Unlock()
				}
			}
		})
	}
	// Imports of histories that overlap what the instances sign, one to all four keys per file and per batch.
	wg.Go(func() {
		r := rand.New(rand.NewPCG(99, 2))
		for ctx.Err() == nil {
			ks := r.Perm(keys)[:1+r.IntN(keys)]
			blocks, atts := map[int][]slashing.SignedBlock{}, map[int][]slashing.SignedAttestation{}
			for _, k := range ks {
				// Three distinct slots and targets per element.
				h := head()
				for _, v := range r.Perm(20)[:3] {
					blocks[k] = append(blocks[k], slashing.SignedBlock{Slot: h - 10 + uint64(v),
						SigningRoot: importedRoot(roots.Add(1))})
				}
				for _, v := range r.Perm(20)[:3] {
					target := h - 10 + uint64(v)
					atts[k] = append(atts[k], slashing.SignedAttestation{SourceEpoch: target - 1, TargetEpoch: target,
						SigningRoot: importedRoot(roots.Add(1))})
				}
			}
			s := stores[r.IntN(len(stores))]
			res, err := interchange.Import(bg, s, strings.NewReader(interchangeDoc(ks, blocks, atts)),
				interchange.ImportOptions{Batch: 1 + r.IntN(keys)})
			if err == nil && len(res.Failed()) > 0 {
				err = res.Failed()[0].Err
			}
			if err != nil {
				fail(fmt.Errorf("import: %w", err))
			}
		}
	})
	wg.Go(func() {
		r := rand.New(rand.NewPCG(7, 3))
		for ctx.Err() == nil {
			_, err := slashing.Prune(bg, stores[r.IntN(len(stores))],
				slashing.PruneConfig{EpochsToKeep: 60, SlotsPerEpoch: 1, Batch: 1 + r.IntN(3)})
			if err != nil {
				fail(fmt.Errorf("prune: %w", err))
			}
		}
	})
	wg.Go(func() {
		r := rand.New(rand.NewPCG(5, 4))
		for ctx.Err() == nil {
			id := key(r.IntN(keys))
			for _, enabled := range []bool{false, true} {
				if err := stores[r.IntN(len(stores))].SetValidatorEnabled(bg, id, enabled); err != nil {
					fail(fmt.Errorf("set enabled: %w", err))
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	lowered := watchWatermarks(t, ctx, db, &wg)
	conflicts := watchConflicts(t, ctx, db, &wg)
	wg.Wait()

	for _, err := range failures {
		t.Error(err)
	}
	if err := lowered(); err != nil {
		t.Error(err)
	}
	checkAllowed(t, allowed)
	conn := db.Connect(t)
	if err := conflicts(conn); err != nil {
		t.Error(err)
	}
	var signedBlocks, signedAtts int
	if err := conn.QueryRow(bg, `SELECT (SELECT count(*) FROM signed_blocks WHERE get_byte(signing_root, 0) = 165),
		(SELECT count(*) FROM signed_attestations WHERE get_byte(signing_root, 0) = 165)`).Scan(&signedBlocks, &signedAtts); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d messages allowed; %d signed blocks and %d signed attestations left after pruning", len(allowed),
		signedBlocks, signedAtts)
	if len(allowed) == 0 {
		t.Fatal("no message was allowed: the stress did not run")
	}
	for _, s := range stores {
		_ = s.Close()
	}
	if n := deadlocks(t, db); n != 0 {
		t.Errorf("Postgres detected %d deadlocks", n)
	}
}

// checkAllowed fails when two allowed messages for one key conflict: two blocks at one slot, two attestations at
// one target, or two attestations of which one surrounds the other.
func checkAllowed(t *testing.T, allowed []signed) {
	t.Helper()
	blocks := map[[2]uint64]bool{}
	atts := map[int][]signed{}
	for _, a := range allowed {
		if a.block {
			k := [2]uint64{uint64(a.key), a.slot}
			if blocks[k] {
				t.Errorf("key %d: two blocks allowed at slot %d", a.key, a.slot)
			}
			blocks[k] = true
			continue
		}
		for _, b := range atts[a.key] {
			if a.target == b.target || (a.source < b.source && a.target > b.target) ||
				(a.source > b.source && a.target < b.target) {
				t.Errorf("key %d: allowed (%d, %d) and (%d, %d)", a.key, a.source, a.target, b.source, b.target)
			}
		}
		atts[a.key] = append(atts[a.key], a)
	}
}

// conflictQuery counts the attestations an instance signed that surround or are surrounded by a record written
// before them: their record ids give the order, since a record's id is drawn inside the transaction that holds the
// validator's lock. Signed roots start with 0xa5 (slashingtest.RootOf), imported ones with 0x1b.
const conflictQuery = `SELECT count(*) FROM signed_attestations x JOIN signed_attestations y
	ON x.validator_id = y.validator_id AND y.id < x.id
	WHERE get_byte(x.signing_root, 0) = 165 AND (
		(y.source_epoch < x.source_epoch AND y.target_epoch > x.target_epoch) OR
		(y.source_epoch > x.source_epoch AND y.target_epoch < x.target_epoch))`

// watchConflicts runs conflictQuery every 20 ms until ctx ends, before pruning removes the records it checks; the
// returned function runs it once more on conn and reports any conflict seen.
func watchConflicts(t *testing.T, ctx context.Context, db *pgtest.DB, wg *sync.WaitGroup) func(*pgx.Conn) error {
	conn := db.Connect(t)
	var (
		worst  int
		checks int
		bad    error
	)
	count := func(c *pgx.Conn) {
		var n int
		if err := c.QueryRow(bg, conflictQuery).Scan(&n); err != nil {
			bad = err
			return
		}
		worst, checks = max(worst, n), checks+1
	}
	wg.Go(func() {
		for ctx.Err() == nil && bad == nil {
			count(conn)
			time.Sleep(20 * time.Millisecond)
		}
	})
	return func(c *pgx.Conn) error {
		count(c)
		if bad == nil && worst > 0 {
			bad = fmt.Errorf("up to %d signed attestations surrounded or were surrounded by a record written before "+
				"them (%d checks)", worst, checks)
		}
		return bad
	}
}

// watchWatermarks samples every low watermark until ctx ends; the returned function reports a watermark that moved
// down.
func watchWatermarks(t *testing.T, ctx context.Context, db *pgtest.DB, wg *sync.WaitGroup) func() error {
	conn := db.Connect(t)
	var bad error
	wg.Go(func() {
		last := map[int32][3]int64{}
		for ctx.Err() == nil {
			seen := maps.Clone(last)
			rows, err := conn.Query(bg, `SELECT validator_id, coalesce(slot, -1), coalesce(source_epoch, -1),
				coalesce(target_epoch, -1) FROM low_watermarks`)
			if err != nil {
				bad = err
				return
			}
			var (
				vid int32
				w   [3]int64
			)
			_, err = pgx.ForEachRow(rows, []any{&vid, &w[0], &w[1], &w[2]}, func() error {
				prev, ok := seen[vid]
				for i, v := range w {
					if ok && v < prev[i] {
						return fmt.Errorf("validator %d: low watermark %v moved down to %v", vid, prev, w)
					}
				}
				last[vid] = w
				return nil
			})
			if err != nil {
				bad = err
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
	})
	return func() error { return bad }
}

// History transactions over the same validators in opposite orders, disabling, single-kind transactions and RANDAO
// writes, from two instances at once: the fixed lock order means Postgres never detects a deadlock.
func TestPostgresLockOrderNoDeadlock(t *testing.T) {
	db := migrated(t)
	stores := instances(t, db, 2)
	const keys = 6
	register(t, stores[0], keys)
	ids := make([]slashing.KeyID, keys)
	for i := range ids {
		ids[i] = key(i)
	}
	ctx, cancel := context.WithTimeout(bg, 2*time.Second)
	defer cancel()
	var (
		wg    sync.WaitGroup
		calls atomic.Int64
		errs  = make(chan error, 64)
	)
	run := func(w int, op func(r *rand.Rand, s *pgstore.Store) error) {
		wg.Go(func() {
			r := rand.New(rand.NewPCG(uint64(w), 9))
			for ctx.Err() == nil {
				if err := op(r, stores[r.IntN(len(stores))]); err != nil {
					select {
					case errs <- err:
					default:
					}
					return
				}
				calls.Add(1)
			}
		})
	}
	for w := range 4 {
		run(w, func(r *rand.Rand, s *pgstore.Store) error {
			order := make([]slashing.KeyID, 0, keys)
			for _, i := range r.Perm(keys)[:2+r.IntN(keys-1)] {
				order = append(order, ids[i])
			}
			return s.UpdateHistory(bg, order, func(id slashing.KeyID, tx slashing.HistoryTx) error {
				_, _, err := tx.LastBlock()
				return err
			})
		})
	}
	for w := range 3 {
		run(10+w, func(r *rand.Rand, s *pgstore.Store) error {
			return s.SetValidatorEnabled(bg, ids[r.IntN(keys)], true)
		})
	}
	for w := range 3 {
		run(20+w, func(r *rand.Rand, s *pgstore.Store) error {
			return s.UpdateBlocks(bg, ids[r.IntN(keys)], func(tx slashing.BlockTx) error {
				_, err := tx.Enabled()
				return err
			})
		})
		run(30+w, func(r *rand.Rand, s *pgstore.Store) error {
			return s.UpdateAttestations(bg, ids[r.IntN(keys)], func(tx slashing.AttestationTx) error {
				_, err := tx.Enabled()
				return err
			})
		})
		run(40+w, func(r *rand.Rand, s *pgstore.Store) error {
			id := ids[r.IntN(keys)]
			st, ok, err := s.RandaoState(bg, id)
			if err != nil {
				return err
			}
			var old *slashing.RandaoState
			if ok {
				old = &st
			}
			_, err = s.CompareAndSwapRandaoState(bg, id, old, slashing.RandaoState{Index: st.Index + 1, LastSlot: st.LastSlot + 1})
			return err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	t.Logf("%d calls", calls.Load())
	for _, s := range stores {
		_ = s.Close()
	}
	if n := deadlocks(t, db); n != 0 {
		t.Errorf("Postgres detected %d deadlocks", n)
	}
}

// validatorID is the database id of a registered key.
func validatorID(t *testing.T, db *pgtest.DB, id slashing.KeyID) int32 {
	t.Helper()
	var vid int32
	if err := db.Connect(t).QueryRow(bg, `SELECT id FROM validators WHERE pubkey_hash = $1`, id[:]).Scan(&vid); err != nil {
		t.Fatal(err)
	}
	return vid
}

// holdLock takes the advisory lock (typ, vid) in a transaction on a session of its own, which the caller ends.
func holdLock(t *testing.T, db *pgtest.DB, typ int, vid int32) pgx.Tx {
	t.Helper()
	tx, err := db.Connect(t).Begin(bg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(bg, fmt.Sprintf(`SELECT pg_advisory_xact_lock(%d, $1)`, typ), vid); err != nil {
		t.Fatal(err)
	}
	return tx
}

// advisoryLock is a pg_advisory_xact_lock(type, validator id).
type advisoryLock [2]int64

// heldWhileWaiting waits until a session waits for the advisory lock (typ, vid), and returns the advisory locks that
// session holds meanwhile, ordered by type and validator id.
func heldWhileWaiting(t *testing.T, watch *pgx.Conn, typ int, vid int32) []advisoryLock {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var pid int32
		err := watch.QueryRow(bg, `SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND NOT granted
			AND classid = $1 AND objid = $2 AND objsubid = 2`, typ, vid).Scan(&pid)
		if errors.Is(err, pgx.ErrNoRows) {
			if time.Now().After(deadline) {
				t.Fatalf("no session waited for the advisory lock (%d, %d)", typ, vid)
			}
			time.Sleep(5 * time.Millisecond)
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		rows, err := watch.Query(bg, `SELECT classid::bigint, objid::bigint FROM pg_locks
			WHERE pid = $1 AND locktype = 'advisory' AND granted ORDER BY classid, objid`, pid)
		if err != nil {
			t.Fatal(err)
		}
		held, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (advisoryLock, error) {
			var l advisoryLock
			return l, r.Scan(&l[0], &l[1])
		})
		if err != nil {
			t.Fatal(err)
		}
		return held
	}
}

// The advisory locks are taken in one order everywhere, BLOCK(0), ATTESTATION(1), RANDAO(2): while another session
// holds one of a validator's locks, the waiting store holds exactly the locks that come before it. Disabling a key
// takes its block and then its attestation lock; a history transaction (import, pruning, the watermark repair)
// takes both locks of each validator in turn, in KeyID order whatever order the call names them in; a RANDAO frontier
// write or reset takes the RANDAO lock alone, and a write reads the row only once it holds the lock, so it sees what
// the lock's previous holder wrote.
func TestPostgresLockOrder(t *testing.T) {
	db := migrated(t)
	s := open(t, config(db))
	register(t, s, 2)
	watch := db.Connect(t)
	ids := []slashing.KeyID{key(0), key(1)}
	slices.SortFunc(ids, func(a, b slashing.KeyID) int { return bytes.Compare(a[:], b[:]) })
	a, b := validatorID(t, db, ids[0]), validatorID(t, db, ids[1])
	history := func() error {
		return s.UpdateHistory(bg, []slashing.KeyID{ids[1], ids[0]}, func(slashing.KeyID, slashing.HistoryTx) error {
			return nil
		})
	}
	sorted := func(ls ...advisoryLock) []advisoryLock {
		slices.SortFunc(ls, func(x, y advisoryLock) int { return slices.Compare(x[:], y[:]) })
		return ls
	}
	for _, tc := range []struct {
		name string
		typ  int   // the lock another session holds
		vid  int32 // of this validator
		want []advisoryLock
		call func() error
	}{
		{"disable", lockTypeAttestation, a, sorted(advisoryLock{0, int64(a)}), func() error {
			return s.SetValidatorEnabled(bg, ids[0], false)
		}},
		{"history, first validator's attestation lock", lockTypeAttestation, a, sorted(advisoryLock{0, int64(a)}), history},
		{"history, second validator's block lock", lockTypeBlock, b,
			sorted(advisoryLock{0, int64(a)}, advisoryLock{1, int64(a)}), history},
		{"history, second validator's attestation lock", lockTypeAttestation, b,
			sorted(advisoryLock{0, int64(a)}, advisoryLock{1, int64(a)}, advisoryLock{0, int64(b)}), history},
		{"RANDAO reset", lockTypeRandao, a, nil, func() error { return s.DeleteRandaoState(bg, ids[0]) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := holdLock(t, db, tc.typ, tc.vid)
			done := make(chan error, 1)
			go func() { done <- tc.call() }()
			got := heldWhileWaiting(t, watch, tc.typ, tc.vid)
			must(t, tx.Rollback(bg))
			must(t, <-done)
			if !slices.Equal(got, tc.want) {
				t.Errorf("waiting for (%d, %d) while holding %v, want %v", tc.typ, tc.vid, got, tc.want)
			}
		})
	}

	t.Run("RANDAO write", func(t *testing.T) {
		tx := holdLock(t, db, lockTypeRandao, a)
		type result struct {
			swapped bool
			err     error
		}
		done := make(chan result, 1)
		go func() {
			ok, err := s.CompareAndSwapRandaoState(bg, ids[0], nil, slashing.RandaoState{Index: 9, LastSlot: 9})
			done <- result{ok, err}
		}()
		if got := heldWhileWaiting(t, watch, lockTypeRandao, a); len(got) != 0 {
			t.Errorf("waiting for the RANDAO lock while holding %v, want none", got)
		}
		// The lock's holder stores a frontier while the store waits.
		if _, err := tx.Exec(bg, `INSERT INTO randao_reveal_state (validator_id, deepest_index, deepest_reveal,
			last_new_slot) VALUES ($1, 5, $2, 5)`, a, make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
		must(t, tx.Commit(bg))
		if r := <-done; r.err != nil || r.swapped {
			t.Fatalf("first-use write over a frontier stored meanwhile: swapped %v, %v; want refused", r.swapped, r.err)
		}
		if st, ok, err := s.RandaoState(bg, ids[0]); err != nil || !ok || st.Index != 5 {
			t.Fatalf("frontier %+v, %v, %v; want the one stored under the lock", st, ok, err)
		}
	})
}

// The advisory lock types, as the store numbers them.
const (
	lockTypeBlock       = 0
	lockTypeAttestation = 1
	lockTypeRandao      = 2
)

// split is one store whose SetValidatorEnabled goes through a second instance: the store contract's serialisation
// test then checks that a disable on one replica waits for a transaction open on another.
type split struct {
	slashing.Store
	other slashing.Store
}

func (s split) SetValidatorEnabled(ctx context.Context, id slashing.KeyID, enabled bool) error {
	return s.other.SetValidatorEnabled(ctx, id, enabled)
}

func (s split) Close() error { return errors.Join(s.Store.Close(), s.other.Close()) }

func TestPostgresContractAcrossInstances(t *testing.T) {
	pgtest.Skip(t)
	slashingtest.RunStoreContract(t, func(t *testing.T) slashing.Store {
		db := migrated(t)
		a, err := pgstore.Open(bg, config(db))
		if err != nil {
			t.Fatal(err)
		}
		b, err := pgstore.Open(bg, config(db))
		if err != nil {
			t.Fatal(err)
		}
		return split{Store: a, other: b}
	})
}

// A transaction that fails with 40P01 or 40001 runs again; any other error ends it.
func TestPostgresRetry(t *testing.T) {
	s := open(t, config(migrated(t)))
	register(t, s, 2)
	for i, code := range []string{"40P01", "40001"} {
		calls := 0
		err := s.UpdateHistory(bg, []slashing.KeyID{key(0), key(1)}, func(id slashing.KeyID, tx slashing.HistoryTx) error {
			calls++
			if calls == 1 {
				return fmt.Errorf("insert: %w", &pgconn.PgError{Code: code})
			}
			return tx.InsertBlock(slashing.SignedBlock{Slot: uint64(10*i + calls)})
		})
		if err != nil || calls != 3 {
			t.Errorf("%s: %v after %d calls, want success after 3 (one failed, then both ids)", code, err, calls)
		}
	}
	calls := 0
	errOther := errors.New("other")
	err := s.UpdateBlocks(bg, key(0), func(slashing.BlockTx) error { calls++; return errOther })
	if !errors.Is(err, errOther) || calls != 1 {
		t.Errorf("a plain error: %v after %d calls", err, calls)
	}
	calls = 0
	err = s.UpdateBlocks(bg, key(0), func(slashing.BlockTx) error {
		calls++
		return &pgconn.PgError{Code: "40P01"}
	})
	if !pgstore.Retryable(err) || calls != 5 {
		t.Errorf("a deadlock every time: %v after %d calls, want it returned after 5", err, calls)
	}
}

// A real deadlock: another session holds a validator's attestation lock while the store holds its block lock and
// waits for it, and then asks for the block lock. Postgres aborts one of the two; either way the store's history
// transaction succeeds, retried when it was the victim.
func TestPostgresDeadlockRetried(t *testing.T) {
	db := migrated(t)
	s := open(t, config(db))
	register(t, s, 1)
	conn := db.Connect(t)
	var vid int32
	id := key(0)
	if err := conn.QueryRow(bg, `SELECT id FROM validators WHERE pubkey_hash = $1`, id[:]).Scan(&vid); err != nil {
		t.Fatal(err)
	}
	tx, err := conn.Begin(bg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(bg, `SELECT pg_advisory_xact_lock(1, $1)`, vid); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	done := make(chan error, 1)
	go func() {
		done <- s.UpdateHistory(bg, []slashing.KeyID{key(0)}, func(_ slashing.KeyID, tx slashing.HistoryTx) error {
			calls.Add(1)
			return tx.InsertBlock(slashing.SignedBlock{Slot: 1})
		})
	}()
	// Wait until the store holds the block lock and waits for the attestation lock.
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting bool
		if err := conn.QueryRow(bg, `SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND NOT granted
			AND classid = 1 AND objid = $1)`, vid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the store never waited for the attestation lock")
		}
		time.Sleep(5 * time.Millisecond)
	}
	_, lockErr := tx.Exec(bg, `SELECT pg_advisory_xact_lock(0, $1)`, vid)
	_ = tx.Rollback(bg)
	if err := <-done; err != nil {
		t.Fatalf("UpdateHistory: %v", err)
	}
	// The store's function runs once either way: a victim store was aborted while it waited for the lock.
	var pe *pgconn.PgError
	switch {
	case calls.Load() != 1:
		t.Fatalf("the store's function ran %d times", calls.Load())
	case lockErr == nil:
		t.Log("the store was the deadlock victim and ran the transaction again")
	case errors.As(lockErr, &pe) && pe.Code == "40P01":
		t.Log("the other session was the deadlock victim")
	default:
		t.Fatalf("other session: %v", lockErr)
	}
}

// lockWaiters counts the sessions of the database that wait for a lock.
func lockWaiters(t *testing.T, conn *pgx.Conn) int {
	t.Helper()
	var n int
	if err := conn.QueryRow(bg, `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()
		AND wait_event_type = 'Lock'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// SetHighWatermark is a fence across instances: it waits for a check-and-record that read the old high watermark,
// and a check-and-record that starts while it waits queues behind it and reads the new one.
func TestPostgresSetHighWatermarkFence(t *testing.T) {
	db := migrated(t)
	ss := instances(t, db, 3)
	if _, err := ss[0].PinGenesisValidatorsRoot(bg, slashingtest.GVR); err != nil {
		t.Fatal(err)
	}
	register(t, ss[0], 2)
	watch := db.Connect(t)
	// waitFor waits until n sessions wait for a lock, failing when stop delivers first.
	waitFor := func(n int, stop <-chan slashing.HighWatermark) {
		t.Helper()
		for deadline := time.Now().Add(time.Second); lockWaiters(t, watch) < n; time.Sleep(2 * time.Millisecond) {
			select {
			case h := <-stop:
				t.Fatalf("a check-and-record that started while SetHighWatermark waited read %+v before it", h)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatalf("%d sessions wait for a lock, want %d", lockWaiters(t, watch), n)
			}
		}
	}

	read, release, held := make(chan slashing.HighWatermark, 1), make(chan struct{}), make(chan error, 1)
	releaseOnce := sync.OnceFunc(func() { close(release) })
	defer releaseOnce()
	go func() {
		held <- ss[1].UpdateAttestations(bg, key(0), func(tx slashing.AttestationTx) error {
			h, err := tx.HighWatermark()
			read <- h
			<-release
			return err
		})
	}()
	if h := <-read; h.IsSet() {
		t.Fatalf("high watermark %+v before it is set", h)
	}
	set := make(chan error, 1)
	go func() {
		set <- ss[0].SetHighWatermark(bg, slashing.HighWatermark{Epoch: slashingtest.U64(1000),
			Slot: slashingtest.U64(10000)})
	}()
	waitFor(1, nil)
	later := make(chan slashing.HighWatermark, 1)
	go func() {
		_ = ss[2].UpdateAttestations(bg, key(1), func(tx slashing.AttestationTx) error {
			h, err := tx.HighWatermark()
			later <- h
			return err
		})
	}()
	waitFor(2, later)
	select {
	case err := <-set:
		t.Fatalf("SetHighWatermark returned while a check-and-record that read the old one was open: %v", err)
	case h := <-later:
		t.Fatalf("a check-and-record that started while SetHighWatermark waited read %+v before it", h)
	case <-time.After(100 * time.Millisecond):
	}
	releaseOnce()
	if err := <-held; err != nil {
		t.Fatalf("the open check-and-record: %v", err)
	}
	if err := <-set; err != nil {
		t.Fatalf("SetHighWatermark: %v", err)
	}
	if h := <-later; h.Epoch == nil || *h.Epoch != 1000 || h.Slot == nil || *h.Slot != 10000 {
		t.Fatalf("the check-and-record that queued behind SetHighWatermark read %+v, want epoch 1000 and slot 10000", h)
	}
}

// SetHighWatermark under saturated signing: check-and-records that never pause keep the metadata row share-locked
// by overlapping transactions, so a FOR UPDATE on the row alone never got its turn and ran out its call bound. The
// table lock it takes first queues new check-and-records behind it, so every call returns, and no check-and-record
// fails meanwhile.
func TestPostgresSetHighWatermarkUnderLoad(t *testing.T) {
	db := migrated(t)
	stores := instances(t, db, 2)
	const keys, workers = 64, 32
	all := make([][]byte, keys)
	for k := range all {
		all[k] = slashingtest.Key(k)
	}
	engines := make([]*slashing.Engine, len(stores))
	for i, s := range stores {
		engines[i] = slashing.NewEngine(s)
		if err := engines[i].RegisterValidators(bg, all); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := stores[0].PinGenesisValidatorsRoot(bg, slashingtest.GVR); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	var (
		wg       sync.WaitGroup
		signs    atomic.Int64
		mu       sync.Mutex
		failures []error
	)
	// Worker w alone signs for keys w and w+workers, one epoch further each time, with no pause.
	for w := range workers {
		wg.Go(func() {
			e := engines[w%len(engines)]
			for epoch := uint64(1); ctx.Err() == nil; epoch++ {
				k := w + workers*int(epoch%2)
				_, err := e.CheckAndRecordAttestation(bg, slashing.AttestationRequest{PublicKey: all[k],
					GenesisValidatorsRoot: slashingtest.GVR, SourceEpoch: epoch - 1, TargetEpoch: epoch,
					SigningRoot: slashingtest.RootOf(epoch)})
				if err != nil {
					mu.Lock()
					failures = append(failures, err)
					mu.Unlock()
					return
				}
				signs.Add(1)
			}
		})
	}
	time.Sleep(300 * time.Millisecond)
	began := time.Now()
	fence := slashing.HighWatermark{Epoch: slashingtest.U64(1 << 40), Slot: slashingtest.U64(1 << 40)}
	for i, h := range []slashing.HighWatermark{fence, {}, fence, {}} {
		start := time.Now()
		if err := stores[i%2].SetHighWatermark(bg, h); err != nil {
			t.Errorf("SetHighWatermark %d under load: %v after %v", i, err, time.Since(start))
		}
	}
	took := time.Since(began)
	before := signs.Load()
	time.Sleep(100 * time.Millisecond)
	cancel()
	wg.Wait()
	t.Logf("4 SetHighWatermark calls in %v; %d check-and-records in all, still signing afterwards: %v", took,
		signs.Load(), signs.Load() > before)
	if len(failures) > 0 {
		t.Fatalf("%d check-and-records failed, the first: %v", len(failures), failures[0])
	}
}
