// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package execution

import (
	"encoding/hex"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/theQRL/go-qrl/core/types"
)

func addrOf(b byte) Address {
	var a Address
	a[0] = b
	return a
}

// qOf is an address in Q form, lower case.
func qOf(a Address) string { return "Q" + hex.EncodeToString(a[:]) }

// The policy file's syntax: unknown keys, bad addresses, an account named
// twice (in two spellings), negative or oversized limits, amounts that are
// not decimal Planck, a key or list entry without a value (YAML's null,
// which would lift the limit), a second document and a file that lets no
// account sign are refused.
func TestParsePolicyRefusals(t *testing.T) {
	a := qOf(addrOf(1))
	section := "accounts:\n  " + a + ":\n"
	for _, tt := range []struct{ name, yaml, want string }{
		{"recipients without a value", section + "    allowed-recipients:\n    max-value: 1\n", "line 3: allowed-recipients has no value"},
		{"recipients commented out", section + "    allowed-recipients:\n#      - " + recipient + "\n", "allowed-recipients has no value"},
		{"empty recipient entry", section + "    allowed-recipients:\n      -\n      - " + recipient + "\n", "line 4: a list entry has no value"},
		{"max-value without a value", section + "    max-value:\n", "max-value has no value"},
		{"max-fee null", section + "    max-fee: null\n", "max-fee has no value"},
		{"contract-creation null", section + "    contract-creation: ~\n", "contract-creation has no value"},
		{"max-data-bytes without a value", section + "    max-data-bytes:\n", "max-data-bytes has no value"},
		{"rate tilde", section + "    max-transactions-per-hour: ~\n", "max-transactions-per-hour has no value"},
		{"all limits empty", section + "    allowed-recipients:\n#      - Q11\n    max-value:\n    max-transactions-per-hour:\n    max-data-bytes:\n", "has no value"},
		{"account without a section", section, a + " has no value"},
		{"default without a value", "default:\n" + section + "    max-value: 1\n", "default has no value"},
		{"accounts without a value", "default: {}\naccounts:\n", "accounts has no value"},
		{"null document", "~\n", "the document is empty"},
		{"second document", "accounts:\n  " + a + ":\n    allowed-recipients: []\n---\ndefault: {}\n", "more than one YAML document"},
		{"trailing document marker", "default: {}\n---\n", "more than one YAML document"},
		{"bad second document", "default: {}\n---\n[\n", "invalid policy"},
		{"unknown key", "accounts:\n  " + a + ":\n    max-gas: 1\n", "max-gas"},
		{"unknown top key", "account: {}\n", "account"},
		{"bad account", "accounts:\n  Q12: {}\n", "not Q followed by 128 hex characters"},
		{"lower-case q", "accounts:\n  q" + a[1:] + ": {}\n", "not Q followed"},
		{"bad recipient", "accounts:\n  " + a + ":\n    allowed-recipients: [Qzz]\n", "allowed-recipients"},
		{"named twice", "accounts:\n  " + qOf(addrOf(0xab)) + ": {}\n  Q" + strings.ToUpper(qOf(addrOf(0xab))[1:]) + ": {}\n", "named twice"},
		{"negative data", "accounts:\n  " + a + ":\n    max-data-bytes: -1\n", "max-data-bytes"},
		{"rate too high", "accounts:\n  " + a + ":\n    max-transactions-per-hour: 100001\n", "max-transactions-per-hour"},
		{"hex amount", "accounts:\n  " + a + ":\n    max-value: 0x10\n", "decimal amount of Planck"},
		{"negative amount", "accounts:\n  " + a + ":\n    max-fee: -5\n", "decimal amount of Planck"},
		{"fractional amount", "accounts:\n  " + a + ":\n    max-fee: 1.5\n", "decimal amount of Planck"},
		{"amount over 256 bits", "accounts:\n  " + a + ":\n    max-value: " + new(big.Int).Lsh(big.NewInt(1), 256).String() + "\n", "256-bit"},
		{"nothing", "accounts: {}\n", "no account could sign"},
		{"empty", "", "invalid policy"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParsePolicy([]byte(tt.yaml)); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err %v, want %q", err, tt.want)
			}
		})
	}
}

// Each rule of an account's policy, the defaults of a policy file (fee
// cap 1 quanta, no contract creation), the default section for accounts
// the file does not name, and the refusal of other accounts.
func TestPolicyRules(t *testing.T) {
	a1, a2, a3, to1, to2 := addrOf(1), addrOf(2), addrOf(3), addrOf(9), addrOf(10)
	p, err := ParsePolicy([]byte(`
accounts:
  ` + qOf(a1) + `:
    allowed-recipients: [` + qOf(to1) + `]
    max-value: 1_000
    max-fee: 21000000
    max-data-bytes: 4
  ` + qOf(a2) + `:
    contract-creation: true
`))
	if err != nil {
		t.Fatal(err)
	}
	fee := func(v int64) *big.Int { return big.NewInt(v) }
	for _, tt := range []struct {
		name    string
		from    Address
		to      *Address
		value   int64
		data    int
		fee     *big.Int
		refusal string
	}{
		{"within the policy", a1, &to1, 1000, 4, fee(21_000_000), ""},
		{"recipient not allowed", a1, &to2, 1, 0, fee(1), "recipient is not in this account's allowed-recipients"},
		{"creation off by default", a1, nil, 0, 1, fee(1), "contract creation is not allowed"},
		{"value above", a1, &to1, 1001, 0, fee(1), "value 1001 Planck is above this account's max-value of 1000"},
		{"data above", a1, &to1, 0, 5, fee(1), "input of 5 bytes is above this account's max-data-bytes of 4"},
		{"fee above", a1, &to1, 0, 0, fee(21_000_001), "above the cap of 21000000 Planck"},
		{"creation on", a2, nil, 1 << 40, 100_000, fee(1), ""},
		{"default fee cap", a2, &to2, 0, 0, new(big.Int).Add(DefaultMaxFee, big.NewInt(1)), "above the cap of 1000000000000000000 Planck"},
		{"default fee cap reached", a2, &to2, 0, 0, DefaultMaxFee, ""},
		{"account not named", a3, &to1, 0, 0, fee(1), "no policy for this account"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := p.Check(tt.from, tt.to, big.NewInt(tt.value), tt.data, tt.fee)
			switch {
			case tt.refusal == "" && r != nil:
				t.Fatalf("refused: %s", r.reason)
			case tt.refusal != "" && (r == nil || !strings.Contains(r.reason, tt.refusal)):
				t.Fatalf("%v, want %q", r, tt.refusal)
			}
		})
	}
	// An empty list allows no recipient; a leading document marker is one document.
	none, err := ParsePolicy([]byte("---\naccounts:\n  " + qOf(a1) + ":\n    allowed-recipients: []\n  " + qOf(a2) + ": {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if r := none.Check(a1, &to1, big.NewInt(0), 0, fee(1)); r == nil || !strings.Contains(r.reason, "allowed-recipients") {
		t.Fatalf("allowed-recipients: []: %v", r)
	}
	if r := none.Check(a2, &to1, new(big.Int).Lsh(big.NewInt(1), 100), 1<<20, fee(1)); r != nil {
		t.Fatalf("an empty section: %s", r.reason)
	}
	withDefault, err := ParsePolicy([]byte("default:\n  max-value: 5\n  contract-creation: true\naccounts:\n  " + qOf(a1) + ":\n    max-value: 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if r := withDefault.Check(a3, &to1, big.NewInt(5), 0, fee(1)); r != nil {
		t.Fatalf("default section: %s", r.reason)
	}
	if r := withDefault.Check(a3, &to1, big.NewInt(6), 0, fee(1)); r == nil {
		t.Fatal("default section's max-value not applied")
	}
	if r := withDefault.Check(a1, &to1, big.NewInt(2), 0, fee(1)); r == nil {
		t.Fatal("the account's own section does not override the default")
	}
	open := OpenPolicy()
	if r := open.Check(a3, nil, new(big.Int).Lsh(big.NewInt(1), 255), 1<<20, DefaultMaxFee); r != nil || open.FromFile() {
		t.Fatalf("open policy: %v", r)
	}
	if r := open.Check(a3, nil, big.NewInt(0), 1, new(big.Int).Add(DefaultMaxFee, big.NewInt(1))); r == nil {
		t.Fatal("the open policy has no fee cap")
	}
}

// max-transactions-per-hour counts over a sliding hour.
func TestPolicyRate(t *testing.T) {
	a := addrOf(1)
	p, err := ParsePolicy([]byte("accounts:\n  " + qOf(a) + ":\n    max-transactions-per-hour: 2\n  " + qOf(addrOf(2)) + ":\n    max-transactions-per-hour: 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Unix(1_700_000_000, 0)
	if p.Reserve(a, t0) != nil || p.Reserve(a, t0.Add(30*time.Minute)) != nil {
		t.Fatal("refused within the limit")
	}
	if r := p.Reserve(a, t0.Add(59*time.Minute)); r == nil || !strings.Contains(r.reason, "signed 2 transactions in the last hour") {
		t.Fatalf("third in the hour: %v", r)
	}
	if r := p.Reserve(a, t0.Add(time.Hour)); r != nil {
		t.Fatalf("an hour after the first: %v", r)
	}
	if r := p.Reserve(a, t0.Add(time.Hour+time.Minute)); r == nil {
		t.Fatal("the second and third are still within the hour")
	}
	if r := p.Reserve(addrOf(2), t0); r == nil {
		t.Fatal("max-transactions-per-hour: 0 allowed one")
	}
	if r := OpenPolicy().Reserve(a, t0); r != nil {
		t.Fatal("the open policy has a rate")
	}
}

// LoadPolicy reads the file and refuses one over 1 MiB.
func TestLoadPolicy(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(p, []byte("default: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if pol, err := LoadPolicy(p); err != nil || !pol.FromFile() {
		t.Fatalf("%v", err)
	}
	big := filepath.Join(dir, "big.yaml")
	if err := os.WriteFile(big, []byte("# "+strings.Repeat("x", maxPolicyFile)+"\ndefault: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPolicy(big); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("%v", err)
	}
	if _, err := LoadPolicy(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("a missing file loaded")
	}
}

// Through the endpoint: a policy refusal is -32003 "Transaction rejected"
// with the reason, for both transaction methods, and written to the audit
// log (G4 S27), and the hourly count is charged once per
// qrl_sendTransaction however often it retries.
func TestPolicyThroughTheEndpoint(t *testing.T) {
	f, g, path := auditFixture(t)
	_, addr := f.key(0)
	from := f.accounts.List()[0].Address
	pol, err := ParsePolicy([]byte("accounts:\n  " + qOf(from) + ":\n    allowed-recipients: [" + recipient + "]\n    max-value: 10\n    max-transactions-per-hour: 2\n"))
	if err != nil {
		t.Fatal(err)
	}
	f.txs.policy = pol
	for _, method := range []string{MethodSignTransaction, MethodSendTransaction} {
		w := f.post(call(1, method, fullTx(addr, "value", "0xb")), nil)
		r := decodeOne(t, w.Body.Bytes())
		if w.Code != http.StatusOK || r.Error == nil || r.Error.Code != -32003 || r.Error.Message != "Transaction rejected" ||
			r.Error.Data != "value 11 Planck is above this account's max-value of 10" {
			t.Fatalf("%s: %d %s", method, w.Code, w.Body)
		}
		w = f.post(call(1, method, fullTx(addr, "to", "Q"+strings.Repeat("22", 64), "value", "0x1")), nil)
		if r := decodeOne(t, w.Body.Bytes()); r.Error == nil || r.Error.Code != -32003 {
			t.Fatalf("%s other recipient: %s", method, w.Body)
		}
	}
	refusals := 3
	g.set(func(g *fakeGQRL) {
		g.onSend = func(*types.Transaction) *Error {
			if refusals > 0 {
				refusals--
				return &Error{Code: -32000, Message: "already known"}
			}
			return nil
		}
	})
	if code, r := f.sendTx(t, 1, fullTx(addr, "value", "0x1", "nonce", "")); code != http.StatusOK || r.Error != nil ||
		len(g.callsOf(MethodSendRawTransaction)) != 4 {
		t.Fatalf("%d %+v", code, r.Error)
	}
	if r := decodeOne(t, f.post(call(2, MethodSignTransaction, fullTx(addr, "value", "0x1", "nonce", "0x1")), nil).Body.Bytes()); r.Error != nil {
		t.Fatalf("second in the hour: %+v", r.Error)
	}
	r := decodeOne(t, f.post(call(3, MethodSignTransaction, fullTx(addr, "value", "0x1", "nonce", "0x2")), nil).Body.Bytes())
	if r.Error == nil || r.Error.Code != -32003 || !strings.Contains(r.Error.Data.(string), "max-transactions-per-hour") {
		t.Fatalf("third in the hour: %+v", r.Error)
	}
	var refused []string
	for _, e := range readAudit(t, path) {
		if e.Outcome == AuditRefused {
			refused = append(refused, e.Method+": "+e.Reason)
		}
	}
	want := []string{
		MethodSignTransaction + ": value 11 Planck is above this account's max-value of 10",
		MethodSignTransaction + ": the recipient is not in this account's allowed-recipients",
		MethodSendTransaction + ": value 11 Planck is above this account's max-value of 10",
		MethodSendTransaction + ": the recipient is not in this account's allowed-recipients",
		MethodSignTransaction + ": this account has signed 2 transactions in the last hour, its max-transactions-per-hour",
	}
	if !slices.Equal(refused, want) {
		t.Fatalf("audited refusals:\n%s\nwant:\n%s", strings.Join(refused, "\n"), strings.Join(want, "\n"))
	}
}
