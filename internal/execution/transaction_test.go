// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package execution

import (
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/theQRL/go-qrl/common"
	"github.com/theQRL/go-qrl/common/hexutil"
	"github.com/theQRL/go-qrl/core/types"
	"github.com/theQRL/go-qrl/crypto/pqcrypto"
	"github.com/theQRL/go-qrl/crypto/pqcrypto/wallet"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
)

// The wallet adapter is go-qrl's pqcrypto/wallet.Wallet over the loaded
// key: its address, descriptor 01 00 00 and public key are the key's, its
// signatures verify with go-qrl, and it never gives out the seed.
func TestKeyWallet(t *testing.T) {
	f := newFixture(t, 1, nil)
	key, addr := f.key(0)
	var w wallet.Wallet = keyWallet{key: key}
	if _, err := w.GetSeed(); !errors.Is(err, errSeedNotExported) {
		t.Fatalf("GetSeed: %v", err)
	}
	if got := common.Address(w.GetAddress()).Hex(); got != addr {
		t.Fatalf("address %s, want %s", got, addr)
	}
	if d := w.GetDescriptor(); d != [3]byte{1, 0, 0} {
		t.Fatalf("descriptor %x", d)
	}
	pk := key.PublicKey()
	if !slices.Equal(w.GetPK(), pk[:]) {
		t.Fatal("public key differs")
	}
	digest := make([]byte, 32)
	sig, err := pqcrypto.Sign(digest, w)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := pqcrypto.MLDSA87VerifySignature(sig, digest, w.GetPK(), w.GetDescriptor()); err != nil || !ok {
		t.Fatalf("go-qrl does not verify the signature: %v", err)
	}
	other, err := keyWallet{key: key, mode: mldsa87.Hedged}.Sign(digest)
	if err != nil || slices.Equal(other, sig) {
		t.Fatalf("two hedged signatures are equal (%v)", err)
	}
	d1, _ := keyWallet{key: key, mode: mldsa87.Deterministic}.Sign(digest)
	d2, _ := keyWallet{key: key, mode: mldsa87.Deterministic}.Sign(digest)
	if !slices.Equal(d1, d2) {
		t.Fatal("deterministic signatures differ")
	}
	key.Zeroize()
	if _, err := w.Sign(digest); !errors.Is(err, mldsa87.ErrZeroized) {
		t.Fatalf("zeroized key: %v", err)
	}
}

// signRequest renders a qrl_signTransaction or qrl_sendTransaction call.
func signRequest(method string, tx map[string]any) string { return call(1, method, tx) }

// fullTx is a complete transfer from account addr.
func fullTx(addr string, members ...string) map[string]any {
	m := txObject("from", addr, "to", recipient, "gas", "0x5208", "maxFeePerGas", "0x2e90edd001",
		"maxPriorityFeePerGas", "0x3b9aca00", "value", "0xde0b6b3a7640000", "nonce", "0x0", "chainId", "0x539")
	for k, v := range txObject(members...) {
		if v == "" {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	return m
}

// qrl_signTransaction returns gqrl's {raw, tx}: the encoded type-0x2
// transaction and its JSON with descriptor, empty extraParams, signature
// and public key; go-qrl recovers the sender from it. The node is never
// asked.
func TestSignTransaction(t *testing.T) {
	f := newFixture(t, 1, defaultAllow)
	key, addr := f.key(0)
	w := f.post(signRequest(MethodSignTransaction, fullTx(addr, "input", "0xc0ffee")), nil)
	r := decodeOne(t, w.Body.Bytes())
	if w.Code != http.StatusOK || r.Error != nil {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var res struct {
		Raw hexutil.Bytes              `json:"raw"`
		Tx  map[string]json.RawMessage `json:"tx"`
	}
	if err := json.Unmarshal(r.Result, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Raw) == 0 || res.Raw[0] != types.DynamicFeeTxType {
		t.Fatalf("raw %x…", res.Raw[:min(len(res.Raw), 4)])
	}
	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(res.Raw); err != nil {
		t.Fatal(err)
	}
	from, err := types.Sender(types.NewZondSigner(big.NewInt(testChainID)), tx)
	if err != nil || from.Hex() != addr {
		t.Fatalf("sender %s (%v), want %s", from.Hex(), err, addr)
	}
	pk := key.PublicKey()
	if tx.Nonce() != 0 || tx.Gas() != 21000 || !strings.EqualFold(tx.To().Hex(), recipient) ||
		tx.Value().String() != "1000000000000000000" ||
		hexutil.Encode(tx.Data()) != "0xc0ffee" || !slices.Equal(tx.RawPublicKeyValue(), pk[:]) ||
		hexutil.Encode(tx.Descriptor()) != "0x010000" || len(tx.ExtraParams()) != 0 {
		t.Fatalf("transaction %+v", tx)
	}
	for member, want := range map[string]string{
		"type": `"0x2"`, "chainId": `"0x539"`, "descriptor": `"0x010000"`, "extraParams": `"0x"`,
		"hash": `"` + tx.Hash().Hex() + `"`,
	} {
		if got := string(res.Tx[member]); got != want {
			t.Errorf("tx.%s = %s, want %s", member, got, want)
		}
	}
	for _, member := range []string{"signature", "publicKey", "nonce", "gas", "maxFeePerGas", "maxPriorityFeePerGas",
		"value", "input", "accessList", "to"} {
		if _, ok := res.Tx[member]; !ok {
			t.Errorf("tx has no %s", member)
		}
	}
	if n := len(f.node.received()); n != 0 {
		t.Fatalf("qrl_signTransaction asked the node %d times", n)
	}
}

// qrl_signTransaction has gqrl's required members and refusals; each is
// -32602 with gqrl's own words, and none reaches the node.
func TestSignTransactionParams(t *testing.T) {
	f := newFixture(t, 1, defaultAllow)
	_, addr := f.key(0)
	tests := []struct {
		name string
		body string
		data string
	}{
		{"no params", call(1, MethodSignTransaction), "takes [transaction]"},
		{"two params", call(1, MethodSignTransaction, fullTx(addr), fullTx(addr)), "takes [transaction]"},
		{"not an object", call(1, MethodSignTransaction, "0x00"), "must be a JSON object"},
		{"no from", signRequest(MethodSignTransaction, fullTx(addr, "from", "")), "from is required"},
		{"lower-case q", signRequest(MethodSignTransaction, fullTx("q"+addr[1:])), "from"},
		{"no gas", signRequest(MethodSignTransaction, fullTx(addr, "gas", "")), "gas not specified"},
		{"no fee cap", signRequest(MethodSignTransaction, fullTx(addr, "maxFeePerGas", "")), "missing maxFeePerGas/maxPriorityFeePerGas"},
		{"no tip", signRequest(MethodSignTransaction, fullTx(addr, "maxPriorityFeePerGas", "")), "missing maxFeePerGas/maxPriorityFeePerGas"},
		{"no nonce", signRequest(MethodSignTransaction, fullTx(addr, "nonce", "")), "nonce not specified"},
		{"leading zero", signRequest(MethodSignTransaction, fullTx(addr, "nonce", "0x01")), "nonce"},
		{"decimal value", signRequest(MethodSignTransaction, fullTx(addr, "value", "1")), "value"},
		{"data and input differ", signRequest(MethodSignTransaction, fullTx(addr, "data", "0x01", "input", "0x02")), `both "data" and "input"`},
		{"creation without data", signRequest(MethodSignTransaction, fullTx(addr, "to", "")), "contract creation without any data"},
		{"fee cap below tip", signRequest(MethodSignTransaction, fullTx(addr, "maxFeePerGas", "0x1")), "below maxPriorityFeePerGas"},
		{"legacy type", signRequest(MethodSignTransaction, fullTx(addr, "type", "0x0")), "type 0x2"},
		{"access-list type", signRequest(MethodSignTransaction, fullTx(addr, "type", "0x1")), "type 0x2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := f.post(tt.body, nil)
			r := decodeOne(t, w.Body.Bytes())
			if w.Code != http.StatusBadRequest || r.Error == nil || r.Error.Code != ErrInvalidParams.Code {
				t.Fatalf("%d %s, want -32602", w.Code, w.Body)
			}
			if data, _ := r.Error.Data.(string); !strings.Contains(data, tt.data) {
				t.Fatalf("data %q, want %q", data, tt.data)
			}
		})
	}
	for _, typ := range []any{"0x2", "0x02", 2} {
		tx := fullTx(addr)
		tx["type"] = typ
		if r := decodeOne(t, f.post(signRequest(MethodSignTransaction, tx), nil).Body.Bytes()); r.Error != nil {
			t.Errorf("type %v: %+v", typ, r.Error)
		}
	}
	// Defaults: no value is 0, no chainId is --chain-id, no access list is empty.
	r := decodeOne(t, f.post(signRequest(MethodSignTransaction, fullTx(addr, "value", "", "chainId", "")), nil).Body.Bytes())
	var res signTransactionResult
	if r.Error != nil || json.Unmarshal(r.Result, &res) != nil || res.Tx.Value().Sign() != 0 ||
		res.Tx.ChainId().Int64() != testChainID || len(res.Tx.AccessList()) != 0 {
		t.Fatalf("defaults: %+v %s", r.Error, r.Result)
	}
	if n := len(f.node.received()); n != 0 {
		t.Fatalf("the node was asked %d times", n)
	}
}

// An address that is not loaded is -32000, as for qrl_sign.
func TestSignTransactionUnknownAccount(t *testing.T) {
	f := newFixture(t, 1, defaultAllow)
	r := decodeOne(t, f.post(signRequest(MethodSignTransaction, fullTx(recipient)), nil).Body.Bytes())
	if r.Error == nil || r.Error.Code != ErrUnknownAccount.Code || r.Error.Message != ErrUnknownAccount.Message {
		t.Fatalf("%+v", r.Error)
	}
}

// A chainId other than --chain-id is refused (-32003), and so is every
// transaction while the node's chain ID differs from it.
func TestSignTransactionChainID(t *testing.T) {
	g, nd := newFakeGQRL(t)
	f := newFixtureWith(t, 1, defaultAllow, downstreamOf(t, nd.Server), nd)
	_, addr := f.key(0)
	r := decodeOne(t, f.post(signRequest(MethodSignTransaction, fullTx(addr, "chainId", "0x1")), nil).Body.Bytes())
	if r.Error == nil || r.Error.Code != ErrTxRejected.Code || !strings.Contains(r.Error.Data.(string), "not --chain-id 1337") {
		t.Fatalf("wrong chainId: %+v", r.Error)
	}
	f.txs.chain.check(t.Context())
	if r := decodeOne(t, f.post(signRequest(MethodSignTransaction, fullTx(addr)), nil).Body.Bytes()); r.Error != nil {
		t.Fatalf("matching node: %+v", r.Error)
	}
	g.set(func(g *fakeGQRL) { g.chainID = big.NewInt(1) })
	f.txs.chain.check(t.Context())
	for _, method := range []string{MethodSignTransaction, MethodSendTransaction} {
		r = decodeOne(t, f.post(signRequest(method, fullTx(addr)), nil).Body.Bytes())
		if r.Error == nil || r.Error.Code != ErrTxRejected.Code ||
			!strings.Contains(r.Error.Data.(string), "the downstream node's chain ID is 1, not --chain-id 1337") {
			t.Fatalf("%s with a node on another chain: %+v", method, r.Error)
		}
	}
	// qrl_sign signs no transaction and is not affected.
	if r := decodeOne(t, f.post(call(1, MethodSign, addr, "0x00"), nil).Body.Bytes()); r.Error != nil {
		t.Fatalf("qrl_sign: %+v", r.Error)
	}
	g.set(func(g *fakeGQRL) { g.chainID = big.NewInt(testChainID) })
	f.txs.chain.check(t.Context())
	if r := decodeOne(t, f.post(signRequest(MethodSignTransaction, fullTx(addr)), nil).Body.Bytes()); r.Error != nil {
		t.Fatalf("after the node came back: %+v", r.Error)
	}
	if g.callsOf(MethodSendRawTransaction) != nil {
		t.Fatal("a refused transaction was sent")
	}
}

// Without a policy file the fee cap, gas × maxFeePerGas, is 1 quanta: equal
// is signed, one Planck more is refused.
func TestSignTransactionFeeCap(t *testing.T) {
	f := newFixture(t, 1, defaultAllow)
	_, addr := f.key(0)
	// 21,000 × 47,619,047,619,047 = 999,999,999,999,987,000; 21,000 × 47,619,047,619,048 = 1,000,000,000,000,008,000.
	for _, tt := range []struct {
		gas, feeCap string
		ok          bool
	}{
		{"0x5208", hexutil.EncodeBig(big.NewInt(47_619_047_619_047)), true},
		{"0x5208", hexutil.EncodeBig(big.NewInt(47_619_047_619_048)), false},
		{"0x1", "0xde0b6b3a7640000", true}, // 1 × 10^18
		{"0x1", "0xde0b6b3a7640001", false},
	} {
		r := decodeOne(t, f.post(signRequest(MethodSignTransaction, fullTx(addr, "gas", tt.gas, "maxFeePerGas", tt.feeCap)), nil).Body.Bytes())
		switch {
		case tt.ok && r.Error != nil:
			t.Errorf("gas %s fee cap %s: %+v", tt.gas, tt.feeCap, r.Error)
		case !tt.ok && (r.Error == nil || r.Error.Code != ErrTxRejected.Code || !strings.Contains(r.Error.Data.(string), "above the cap of 1000000000000000000 Planck")):
			t.Errorf("gas %s fee cap %s: %+v, want the fee cap refusal", tt.gas, tt.feeCap, r.Error)
		}
	}
}
