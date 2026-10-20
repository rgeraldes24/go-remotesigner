// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package execution

import (
	"bytes"
	"encoding/json"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/theQRL/go-qrl/common/hexutil"
	"github.com/theQRL/go-qrl/core/types"
	walletmldsa87 "github.com/theQRL/go-qrllib/wallet/ml_dsa_87"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/signer/provider"
)

// txVectors is testdata/vectors/transactions/signing.json, written by
// tools/vectorgen with go-qrl's own types.SignTx at the go-qrl commit
// qrysm pins (cyyber/go-qrl), which the signer's go-qrl must agree with.
type txVectors struct {
	Accounts []struct {
		Index        int           `json:"index"`
		ExtendedSeed hexutil.Bytes `json:"extended_seed"`
		Address      string        `json:"address"`
		PublicKey    hexutil.Bytes `json:"public_key"`
	} `json:"accounts"`
	Cases []struct {
		Name          string          `json:"name"`
		Account       int             `json:"account"`
		Request       json.RawMessage `json:"request"`
		SigningHash   string          `json:"signing_hash"`
		Deterministic struct {
			Raw  hexutil.Bytes `json:"raw"`
			Hash string        `json:"hash"`
		} `json:"deterministic"`
	} `json:"cases"`
}

func readTxVectors(t *testing.T) txVectors {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "transactions", "signing.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v txVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Accounts) == 0 || len(v.Cases) == 0 {
		t.Fatal("no vectors")
	}
	return v
}

// unlimited lets every account sign any transaction: the vectors go up to
// the 256-bit limits, far over any fee cap.
func unlimited() *Policy {
	return &Policy{fallback: &AccountPolicy{MaxFee: new(big.Int).Lsh(big.NewInt(1), 600), ContractCreation: true}}
}

// Every vector through qrl_signTransaction, on the vector's chain: the
// signer's transaction has the vector's signing hash, and in deterministic
// mode its raw encoding and hash equal the vector's byte for byte; hedged,
// the signing hash is the same and the signature still verifies.
func TestTransactionVectors(t *testing.T) {
	v := readTxVectors(t)
	keys := provider.New(quiet())
	t.Cleanup(keys.Close)
	var loaded []*mldsa87.Key
	for _, a := range v.Accounts {
		ext := [mldsa87.ExtendedSeedSize]byte(a.ExtendedSeed)
		k, err := mldsa87.FromExtendedSeed51(&ext)
		if err != nil {
			t.Fatal(err)
		}
		pk := k.PublicKey()
		if mldsa87.ChecksumAddress(pk.Address()) != a.Address || string(pk[:]) != string(a.PublicKey) {
			t.Fatalf("account %d: the key derives another address or public key", a.Index)
		}
		loaded = append(loaded, k)
	}
	if _, err := keys.Apply([]provider.Batch{{Source: "vectors", Keys: loaded}}, nil, nil); err != nil {
		t.Fatal(err)
	}
	accounts := NewAccounts(keys)
	accounts.Refresh()
	nd := newNode(t)
	f := newFixtureWith(t, 0, nil, downstreamOf(t, nd.Server), nd)

	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			var chain struct {
				ChainID *hexutil.Big `json:"chainId"`
			}
			if err := json.Unmarshal(c.Request, &chain); err != nil || chain.ChainID == nil {
				t.Fatalf("request chainId: %v", err)
			}
			txs := NewTransactions(TransactionsConfig{ChainID: chain.ChainID.ToInt(), Policy: unlimited()})
			h := newHandler(accounts, f.handler.allow, f.handler.proxy, txs, quiet())
			body := `{"jsonrpc":"2.0","id":1,"method":"qrl_signTransaction","params":[` + string(c.Request) + `]}`

			sign := func(mode mldsa87.Mode) *types.Transaction {
				txs.mode = mode
				f.handler = h
				r := decodeOne(t, f.post(body, nil).Body.Bytes())
				if r.Error != nil {
					t.Fatalf("%v: %+v", mode, r.Error)
				}
				var res struct {
					Raw hexutil.Bytes      `json:"raw"`
					Tx  *types.Transaction `json:"tx"`
				}
				if err := json.Unmarshal(r.Result, &res); err != nil {
					t.Fatal(err)
				}
				tx := new(types.Transaction)
				if err := tx.UnmarshalBinary(res.Raw); err != nil {
					t.Fatal(err)
				}
				if res.Tx.Hash() != tx.Hash() {
					t.Fatal("tx and raw differ")
				}
				signer := types.NewZondSigner(chain.ChainID.ToInt())
				if got := signer.Hash(tx, tx.Descriptor(), tx.ExtraParams()).Hex(); got != c.SigningHash {
					t.Fatalf("%v: signing hash %s, want %s", mode, got, c.SigningHash)
				}
				from, err := types.Sender(signer, tx)
				if err != nil || !strings.EqualFold(from.Hex(), v.Accounts[c.Account].Address) {
					t.Fatalf("%v: sender %s (%v)", mode, from.Hex(), err)
				}
				return tx
			}
			det := sign(mldsa87.Deterministic)
			raw, _ := det.MarshalBinary()
			if hexutil.Encode(raw) != hexutil.Encode(c.Deterministic.Raw) {
				t.Fatalf("raw differs from the vector")
			}
			if det.Hash().Hex() != c.Deterministic.Hash {
				t.Fatalf("hash %s, want %s", det.Hash().Hex(), c.Deterministic.Hash)
			}
			if hedged := sign(mldsa87.Hedged); hedged.Hash() == det.Hash() {
				t.Fatal("a hedged signature equals the deterministic one")
			}
		})
	}
}

// textHashVectors is testdata/vectors/transactions/text_hash.json, written
// by tools/vectorgen with go-qrl's own accounts.TextHash at the go-qrl
// commit qrysm pins (cyyber/go-qrl).
type textHashVectors struct {
	Cases []struct {
		Name     string        `json:"name"`
		Data     hexutil.Bytes `json:"data"`
		TextHash hexutil.Bytes `json:"text_hash"`
	} `json:"cases"`
}

// TextHash is go-qrl's accounts.TextHash on every text-hash vector, and
// qrl_sign of each vector's data signs that vector's text hash: the
// signature verifies with go-qrllib over it.
func TestTextHashVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "transactions", "text_hash.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v textHashVectors
	if err := json.Unmarshal(data, &v); err != nil || len(v.Cases) == 0 {
		t.Fatalf("text-hash vectors: %d cases (%v)", len(v.Cases), err)
	}
	f := newFixture(t, 1, defaultAllow)
	k, addr := f.key(0)
	pk := k.PublicKey()
	desc, err := walletmldsa87.NewMLDSA87Descriptor()
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if h := TextHash(c.Data); !bytes.Equal(h[:], c.TextHash) {
				t.Fatalf("TextHash(%x) = %x, want go-qrl's %x", c.Data, h, c.TextHash)
			}
			w := f.post(call(i+1, MethodSign, addr, hexutil.Encode(c.Data)), nil)
			r := decodeOne(t, w.Body.Bytes())
			var sig hexutil.Bytes
			if w.Code != http.StatusOK || r.Error != nil || json.Unmarshal(r.Result, &sig) != nil {
				t.Fatalf("qrl_sign: %d %.300s", w.Code, w.Body)
			}
			if !walletmldsa87.Verify(c.TextHash, sig, (*walletmldsa87.PK)(&pk), [3]byte(desc)) {
				t.Fatal("the qrl_sign signature does not verify over go-qrl's text hash")
			}
		})
	}
}
