// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package execution

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/theQRL/go-qrl/common/hexutil"
	"github.com/theQRL/go-qrl/core/types"

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
