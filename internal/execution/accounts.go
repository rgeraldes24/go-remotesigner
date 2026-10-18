// Copyright 2023 ConsenSys AG.
// Copyright 2026 The go-remotesigner Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//
// Modified by The go-remotesigner Authors, 2026: translated from Java to Go and adapted for QRL.
// Derived from Web3Signer
// signing/src/main/java/tech/pegasys/web3signer/signing/config/SecpArtifactSignerProviderAdapter.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

//go:build !noexecution

package execution

import (
	"bytes"
	"slices"
	"sync/atomic"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/signer/provider"
)

// Address is a 64-byte QRL account address.
type Address = [mldsa87.AddressSize]byte

// Account is a loaded account: its address and public key.
type Account struct {
	Address   Address
	PublicKey *mldsa87.PublicKey
}

// Accounts is the address-keyed view of the loaded keys. Refresh rebuilds
// it from the provider after every load, so lookups by address never hash
// a public key. The index is keyed by the address bytes: the text forms
// (QIP-55, lower or upper case after the "Q") all parse to the same key, and
// the "Q" itself is never case-folded.
type Accounts struct {
	keys  *provider.Provider
	index atomic.Pointer[accountIndex]
}

type accountIndex struct {
	byAddress map[Address]provider.ID
	sorted    []Account // by address bytes
}

// NewAccounts returns an empty view of keys; call Refresh after each load.
func NewAccounts(keys *provider.Provider) *Accounts {
	a := &Accounts{keys: keys}
	a.index.Store(&accountIndex{byAddress: map[Address]provider.ID{}})
	return a
}

// Refresh re-keys the provider's current keys by address.
func (a *Accounts) Refresh() {
	next := &accountIndex{byAddress: map[Address]provider.ID{}}
	for pk := range a.keys.PublicKeys() {
		addr := pk.Address()
		if _, dup := next.byAddress[addr]; dup {
			continue // one address per key pair: only a duplicate key can repeat it, and the provider has none
		}
		next.byAddress[addr] = pk.ID()
		next.sorted = append(next.sorted, Account{Address: addr, PublicKey: pk})
	}
	slices.SortFunc(next.sorted, func(x, y Account) int { return bytes.Compare(x.Address[:], y.Address[:]) })
	a.index.Store(next)
}

// Lookup returns the key of an address. A key the provider has evicted
// since the last Refresh is not found.
func (a *Accounts) Lookup(addr Address) (*mldsa87.Key, bool) {
	id, ok := a.index.Load().byAddress[addr]
	if !ok {
		return nil, false
	}
	return a.keys.Get(id)
}

// List returns the loaded accounts, sorted by address.
func (a *Accounts) List() []Account { return a.index.Load().sorted }
