// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package execution

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/theQRL/go-qrl/core/types"
)

// readAudit returns the entries of an audit log.
func readAudit(t *testing.T, path string) []AuditEntry {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out []AuditEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e AuditEntry
		dec := json.NewDecoder(strings.NewReader(sc.Text()))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil {
			t.Fatalf("line %q: %v", sc.Text(), err)
		}
		if _, err := time.Parse(time.RFC3339Nano, e.Time); err != nil {
			t.Fatalf("time %q: %v", e.Time, err)
		}
		out = append(out, e)
	}
	return out
}

// auditFixture is a sendFixture with an audit log.
func auditFixture(t *testing.T) (*fixture, *fakeGQRL, string) {
	t.Helper()
	f, g := sendFixture(t, 1)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := OpenAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	f.txs.audit = a
	return f, g, path
}

// The audit log is JSON Lines, mode 0600, appended to: each signed
// transaction (before it leaves the signer), the node's answer to each
// sent one, and each refusal (the chain ID, the fee cap, an unknown
// account and a type other than 0x2 here; the policy's in
// TestPolicyThroughTheEndpoint), with hash, from, to, nonce, value, fee
// (gas × maxFeePerGas) and chain ID: docs/operations/execution.md,
// section 10.
func TestAuditLog(t *testing.T) {
	f, g, path := auditFixture(t)
	_, addr := f.key(0)
	r := decodeOne(t, f.post(call(1, MethodSignTransaction, fullTx(addr)), nil).Body.Bytes())
	var res signTransactionResult
	if r.Error != nil || json.Unmarshal(r.Result, &res) != nil {
		t.Fatalf("%+v", r.Error)
	}
	refusals := 1
	g.set(func(g *fakeGQRL) {
		g.onSend = func(*types.Transaction) *Error {
			if refusals > 0 {
				refusals--
				return &Error{Code: -32000, Message: "nonce too low: next nonce 1, tx nonce 0"}
			}
			return nil
		}
	})
	if _, r := f.sendTx(t, 2, fullTx(addr, "nonce", "")); r.Error != nil {
		t.Fatalf("%+v", r.Error)
	}
	_, _ = f.sendTx(t, 3, fullTx(addr, "chainId", "0x1"))                                   // wrong chain
	_, _ = f.sendTx(t, 4, fullTx(addr, "gas", "0x1000000", "maxFeePerGas", "0xe8d4a51000")) // fee cap
	_, _ = f.sendTx(t, 5, fullTx(recipient))                                                // unknown account
	// A type other than 0x2 is -32602, as gqrl refuses it, and a refusal the
	// log records, for both methods.
	if code, r := f.sendTx(t, 6, fullTx(addr, "type", "0x1")); code != http.StatusBadRequest || r.Error == nil ||
		r.Error.Code != ErrInvalidParams.Code {
		t.Fatalf("type 0x1: %d %+v", code, r.Error)
	}
	if r := decodeOne(t, f.post(call(7, MethodSignTransaction, fullTx(addr, "type", "0x0")), nil).Body.Bytes()); r.Error == nil ||
		r.Error.Code != ErrInvalidParams.Code {
		t.Fatalf("type 0x0: %+v", r.Error)
	}

	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v (%v)", fi.Mode(), err)
	}
	entries := readAudit(t, path)
	var got []string
	for _, e := range entries {
		got = append(got, e.Method+" "+e.Outcome)
	}
	want := []string{
		"qrl_signTransaction signed",
		"qrl_sendTransaction signed", "qrl_sendTransaction node-refused",
		"qrl_sendTransaction signed", "qrl_sendTransaction sent",
		"qrl_sendTransaction refused", "qrl_sendTransaction refused", "qrl_sendTransaction refused",
		"qrl_sendTransaction refused", "qrl_signTransaction refused",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("entries:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	signed := entries[0]
	if signed.Hash != res.Tx.Hash().Hex() || !strings.EqualFold(signed.From, addr) || !strings.EqualFold(signed.To, recipient) ||
		signed.Nonce != "0x0" || signed.Value != "0xde0b6b3a7640000" || signed.Fee != "0xeebe0b40ed208" ||
		signed.ChainID != "0x539" || signed.Reason != "" {
		t.Fatalf("signed entry %+v", signed)
	}
	if e := entries[2]; e.Reason != "nonce too low: next nonce 1, tx nonce 0" || e.Hash == "" || e.Hash == entries[4].Hash {
		t.Fatalf("node-refused entry %+v", e)
	}
	if entries[3].Hash != entries[4].Hash || entries[4].Nonce != "0x0" {
		t.Fatalf("sent entry %+v", entries[4])
	}
	for i, reason := range map[int]string{5: "not --chain-id 1337", 6: "above the cap", 7: ErrUnknownAccount.Message,
		8: typeRefusal, 9: typeRefusal} {
		if e := entries[i]; !strings.Contains(e.Reason, reason) || e.Hash != "" || e.From == "" {
			t.Errorf("refusal %d: %+v, want %q", i, e, reason)
		}
	}
}

// A signature leaves the signer only once its audit entry is written: with
// the log unwritable, nothing is returned or sent.
func TestAuditLogFailsClosed(t *testing.T) {
	f, g, _ := auditFixture(t)
	_, addr := f.key(0)
	_ = f.txs.audit.Close()
	for _, method := range []string{MethodSignTransaction, MethodSendTransaction} {
		r := decodeOne(t, f.post(call(1, method, fullTx(addr)), nil).Body.Bytes())
		if r.Error == nil || r.Error.Code != ErrInternal.Code || r.Result != nil {
			t.Fatalf("%s: %+v %s", method, r.Error, r.Result)
		}
	}
	if g.callsOf(MethodSendRawTransaction) != nil {
		t.Fatal("a transaction was sent without its audit entry")
	}
}

// Reopen continues in a new file at the path, for log rotation.
func TestAuditLogReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	a, err := OpenAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	if err := a.Write(AuditEntry{Method: "m", Outcome: AuditRefused, Reason: "one"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := a.Reopen(); err != nil {
		t.Fatal(err)
	}
	if err := a.Write(AuditEntry{Method: "m", Outcome: AuditRefused, Reason: "two"}); err != nil {
		t.Fatal(err)
	}
	if old, cur := readAudit(t, path+".1"), readAudit(t, path); len(old) != 1 || old[0].Reason != "one" ||
		len(cur) != 1 || cur[0].Reason != "two" {
		t.Fatalf("old %+v, current %+v", old, cur)
	}
	// An existing file is appended to, never truncated.
	b, err := OpenAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Write(AuditEntry{Method: "m", Outcome: AuditRefused, Reason: "three"}); err != nil {
		t.Fatal(err)
	}
	_ = b.Close()
	if cur := readAudit(t, path); len(cur) != 2 {
		t.Fatalf("after reopening: %+v", cur)
	}
	if _, err := OpenAuditLog(filepath.Join(dir, "missing", "audit.jsonl")); err == nil {
		t.Fatal("a log in a missing directory opened")
	}
}
