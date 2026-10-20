// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha512"
	"fmt"
	"math/big"
	"strconv"

	"github.com/theQRL/go-qrl/accounts"
	"github.com/theQRL/go-qrl/common"
	"github.com/theQRL/go-qrl/core/types"
	walletcommon "github.com/theQRL/go-qrllib/wallet/common"
	"github.com/theQRL/go-qrllib/wallet/common/descriptor"
	walletmldsa87 "github.com/theQRL/go-qrllib/wallet/ml_dsa_87"
)

// txAccounts is how many execution accounts the transaction vectors use.
const txAccounts = 2

// txAccountTag derives the accounts' seeds: seed i is the first 48 bytes
// of SHA-512(tag ‖ decimal i).
const txAccountTag = "go-remotesigner transaction vector account "

// txAccount is an execution account of the transaction vectors: a go-qrl
// wallet built from its extended seed.
type txAccount struct {
	extended []byte // descriptor 01 00 00, then the 48-byte seed
	wallet   *walletmldsa87.Wallet
}

func newTxAccount(i int) (*txAccount, error) {
	sum := sha512.Sum512([]byte(txAccountTag + strconv.Itoa(i)))
	var seed walletcommon.Seed
	copy(seed[:], sum[:len(seed)])
	w, err := walletmldsa87.NewWalletFromSeed(seed)
	if err != nil {
		return nil, err
	}
	ext, err := w.GetExtendedSeed()
	if err != nil {
		return nil, err
	}
	return &txAccount{extended: ext[:], wallet: w}, nil
}

// deterministicWallet is go-qrl's wallet over a txAccount that signs in
// ML-DSA-87's deterministic mode, so that a signed transaction and its
// hash are reproducible. The signer signs hedged in production; its golden
// test switches to the same deterministic mode.
type deterministicWallet struct{ a *txAccount }

func (w deterministicWallet) GetSeed() (walletcommon.ExtendedSeed, error) {
	return w.a.wallet.GetExtendedSeed()
}

func (w deterministicWallet) GetAddress() [common.AddressLength]uint8 { return w.a.wallet.GetAddress() }

func (w deterministicWallet) GetDescriptor() descriptor.Descriptor {
	return w.a.wallet.GetDescriptor().ToDescriptor()
}

func (w deterministicWallet) GetPK() []byte {
	pk := w.a.wallet.GetPK()
	return pk[:]
}

func (w deterministicWallet) Sign(message []uint8) ([]byte, error) {
	sig, err := w.a.wallet.SignDeterministic(message)
	return sig[:], err
}

// txCase is one transaction of the vectors.
type txCase struct {
	name    string
	account int
	tx      types.DynamicFeeTx
}

func bigPow(base, exp int64) *big.Int {
	return new(big.Int).Exp(big.NewInt(base), big.NewInt(exp), nil)
}

func txAddr(fill byte) *common.Address {
	var a common.Address
	for i := range a {
		a[i] = fill + byte(i)
	}
	return &a
}

func txCases() []txCase {
	max256 := new(big.Int).Sub(bigPow(2, 256), big.NewInt(1))
	quanta := bigPow(10, 18)
	return []txCase{
		{name: "transfer", account: 0, tx: types.DynamicFeeTx{
			ChainID: big.NewInt(1337), Nonce: 0, GasTipCap: big.NewInt(1_000_000_000),
			GasFeeCap: big.NewInt(200_000_000_001), Gas: 21_000, To: txAddr(0x11), Value: quanta,
		}},
		{name: "transfer_with_input", account: 0, tx: types.DynamicFeeTx{
			ChainID: big.NewInt(1337), Nonce: 7, GasTipCap: big.NewInt(2), GasFeeCap: big.NewInt(3), Gas: 60_000,
			To: txAddr(0xa0), Value: big.NewInt(1), Data: []byte("go-remotesigner"),
		}},
		{name: "contract_creation", account: 1, tx: types.DynamicFeeTx{
			ChainID: big.NewInt(1337), Nonce: 1, GasTipCap: big.NewInt(1_000_000_000),
			GasFeeCap: big.NewInt(20_000_000_000), Gas: 300_000,
			Data: []byte{0x60, 0x80, 0x60, 0x40, 0x52, 0x34, 0x80, 0x15, 0x60, 0x0f, 0x57, 0x5f, 0x80, 0xfd, 0x5b, 0x50},
		}},
		{name: "access_list", account: 1, tx: types.DynamicFeeTx{
			ChainID: big.NewInt(1), Nonce: 42, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(1_000_000_007),
			Gas: 100_000, To: txAddr(0x30), Value: big.NewInt(0), Data: []byte{0xde, 0xad, 0xbe, 0xef},
			AccessList: types.AccessList{
				{Address: *txAddr(0x30), StorageKeys: []common.Hash{{1}, {2, 3}}},
				{Address: *txAddr(0x70), StorageKeys: []common.Hash{}},
			},
		}},
		{name: "limits", account: 0, tx: types.DynamicFeeTx{
			ChainID: big.NewInt(1<<62 + 1), Nonce: 1<<64 - 2, GasTipCap: max256, GasFeeCap: max256,
			Gas: 1<<64 - 1, To: txAddr(0xff), Value: max256,
		}},
	}
}

// txRequest is the transaction object of a qrl_signTransaction request for
// tx from from, with gqrl's member names and encodings.
func txRequest(from common.Address, tx *types.DynamicFeeTx) obj {
	r := obj{}.set("from", from.Hex())
	if tx.To != nil {
		r = r.set("to", tx.To.Hex())
	}
	r = r.set("gas", hexUint(tx.Gas)).
		set("maxFeePerGas", hexBig(tx.GasFeeCap)).
		set("maxPriorityFeePerGas", hexBig(tx.GasTipCap))
	if tx.Value != nil {
		r = r.set("value", hexBig(tx.Value))
	}
	r = r.set("nonce", hexUint(tx.Nonce))
	if len(tx.Data) > 0 {
		r = r.set("input", hx(tx.Data))
	}
	if tx.AccessList != nil {
		list := []obj{}
		for _, t := range tx.AccessList {
			keys := []string{}
			for _, k := range t.StorageKeys {
				keys = append(keys, hx(k[:]))
			}
			list = append(list, obj{}.set("address", t.Address.Hex()).set("storageKeys", keys))
		}
		r = r.set("accessList", list)
	}
	return r.set("chainId", hexBig(tx.ChainID))
}

func hexUint(v uint64) string  { return "0x" + strconv.FormatUint(v, 16) }
func hexBig(v *big.Int) string { return "0x" + v.Text(16) }

// genTransactions writes transactions/signing.json: execution-mode
// transactions signed with go-qrl's own types.SignTx, at the go-qrl
// commit qrysm pins, as the oracle of the signer's qrl_signTransaction.
func genTransactions(g *generator) error {
	accounts := make([]*txAccount, txAccounts)
	var accountRecs []obj
	for i := range accounts {
		a, err := newTxAccount(i)
		if err != nil {
			return err
		}
		accounts[i] = a
		addr := a.wallet.GetAddress()
		pk := a.wallet.GetPK()
		accountRecs = append(accountRecs, obj{}.
			set("index", i).
			set("extended_seed", hx(a.extended)).
			set("address", common.Address(addr).Hex()).
			set("public_key", hx(pk[:])))
	}
	var recs []obj
	for _, c := range txCases() {
		a := accounts[c.account]
		data := c.tx
		if data.AccessList == nil {
			data.AccessList = types.AccessList{}
		}
		if data.Value == nil {
			data.Value = new(big.Int)
		}
		tx := types.NewTx(&data)
		if tx.Type() != types.DynamicFeeTxType {
			return fmt.Errorf("%s: type %d", c.name, tx.Type())
		}
		signer := types.NewZondSigner(c.tx.ChainID)
		w := deterministicWallet{a}
		desc := w.GetDescriptor()
		hash := signer.Hash(tx, desc[:], []byte{})
		signed, err := types.SignTx(tx, signer, w)
		if err != nil {
			return fmt.Errorf("%s: %w", c.name, err)
		}
		from, err := types.Sender(signer, signed)
		if err != nil || from != common.Address(a.wallet.GetAddress()) {
			return fmt.Errorf("%s: the signed transaction does not verify: %v", c.name, err)
		}
		raw, err := signed.MarshalBinary()
		if err != nil {
			return fmt.Errorf("%s: %w", c.name, err)
		}
		recs = append(recs, obj{}.
			set("name", c.name).
			set("account", c.account).
			set("request", txRequest(from, &c.tx)).
			set("signing_hash", hx(hash[:])).
			set("deterministic", obj{}.
				set("raw", hx(raw)).
				set("hash", signed.Hash().Hex())))
	}
	return writeJSON(g.vectors, "transactions/signing.json", obj{}.
		set("description", g.description("Execution-mode transactions (type 0x2, dynamic fee) signed by go-qrl's "+
			"types.SignTx with types.NewZondSigner(chainId) at the go-qrl commit qrysm pins. Account i's "+
			"extended seed is 01 00 00 followed by the first 48 bytes of SHA-512(\""+txAccountTag+"\" ‖ decimal i). "+
			"request is the qrl_signTransaction transaction object; signing_hash is ZondSigner.Hash with the "+
			"descriptor 01 00 00 and empty extraParams, which the signature covers. deterministic holds the "+
			"encoded signed transaction (raw) and its hash when the account signs in ML-DSA-87's deterministic "+
			"mode; the signer signs hedged, so only its signing hash matches these in production. "+
			"These are test keys: never use them on a live network.")).
		set("generator", g.info).
		set("accounts", accountRecs).
		set("cases", recs))
}

// textCase is one message of the text-hash vectors.
type textCase struct {
	name string
	data []byte
}

// byteRun is n bytes counting up from 0, wrapping at 251.
func byteRun(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

func textCases() []textCase {
	return []textCase{
		{"empty", []byte{}},
		{"hello_joe", []byte("Hello Joe")}, // the value go-qrl's own accounts test expects
		{"zero_byte", []byte{0}},
		{"nine_bytes", byteRun(9)},
		{"ten_bytes", byteRun(10)}, // the length takes two digits
		{"hash_sized", byteRun(32)},
		{"prefixed", append([]byte("\x19QRL Signed Message:\n32"), byteRun(32)...)},
		{"utf8", []byte("go-remotesigner \u00e9\u2713")},
		{"not_utf8", []byte{0xff, 0xfe, 0x80, 0x00, 0xc3}},
		{"hundred_bytes", byteRun(100)},
		{"thousand_bytes", byteRun(1000)},
	}
}

// genTextHash writes transactions/text_hash.json: go-qrl's
// accounts.TextHash of messages, at the go-qrl commit qrysm pins, as the
// oracle of the message qrl_sign signs.
func genTextHash(g *generator) error {
	var recs []obj
	for _, c := range textCases() {
		h := accounts.TextHash(c.data)
		if len(h) != 32 {
			return fmt.Errorf("%s: a text hash of %d bytes", c.name, len(h))
		}
		recs = append(recs, obj{}.
			set("name", c.name).
			set("data", hx(c.data)).
			set("text_hash", hx(h)))
	}
	return writeJSON(g.vectors, "transactions/text_hash.json", obj{}.
		set("description", g.description("The message qrl_sign signs: go-qrl's accounts.TextHash, at the go-qrl "+
			"commit qrysm pins, of each data, which is Keccak-256 of \"\\x19QRL Signed Message:\\n\", the data's "+
			"length in decimal, and the data.")).
		set("generator", g.info).
		set("cases", recs))
}
