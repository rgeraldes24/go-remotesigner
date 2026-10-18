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
// signing/src/test/java/tech/pegasys/web3signer/signing/config/SecpArtifactSignerProviderAdapterTest.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

//go:build !noexecution

package execution

import (
	"crypto/sha3"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystoretest"
	"github.com/rgeraldes24/go-remotesigner/internal/signer/provider"
)

// When_LoadIsCalled_Expect_SameNumberOfEntriesAsTheSignerProvided and
// When_LoadIsCalled_Expect_SignerMappedToEth1Address: after a refresh the
// view has one account per loaded key, each found by its address, the
// first 64 bytes of SHAKE-256 over the descriptor 01 00 00 and the public
// key (computed here with the standard library, not go-qrllib).
func TestW3SAccountsMapKeysToAddresses(t *testing.T) {
	keys := provider.New(quiet())
	defer keys.Close()
	var loaded []*mldsa87.Key
	for i := range 3 {
		k, err := mldsa87.FromExtendedSeed51(keystoretest.ExtendedSeed("accounts", i))
		if err != nil {
			t.Fatal(err)
		}
		loaded = append(loaded, k)
	}
	if _, err := keys.Apply([]provider.Batch{{Source: "a", Keys: loaded}}, nil, nil); err != nil {
		t.Fatal(err)
	}
	a := NewAccounts(keys)
	if len(a.List()) != 0 {
		t.Fatal("accounts before the first refresh")
	}
	a.Refresh()
	if len(a.List()) != keys.Len() {
		t.Fatalf("%d accounts for %d keys", len(a.List()), keys.Len())
	}
	for _, k := range loaded {
		pk := k.PublicKey()
		var want Address
		copy(want[:], sha3.SumSHAKE256(append([]byte{0x01, 0x00, 0x00}, pk[:]...), mldsa87.AddressSize))
		if pk.Address() != want {
			t.Fatalf("address %x, want SHAKE-256(01 00 00 ‖ pk)[:64] = %x", pk.Address(), want)
		}
		got, ok := a.Lookup(want)
		if !ok || got != k {
			t.Fatalf("the key of address %x was not found", want[:4])
		}
	}

	// A key a reload evicts is not found, even before the next refresh.
	gone := loaded[0].PublicKey()
	if _, err := keys.Apply([]provider.Batch{{Source: "a", Keys: []*mldsa87.Key{}}}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Lookup(gone.Address()); ok {
		t.Fatal("an evicted key was found")
	}
	a.Refresh()
	if len(a.List()) != 0 {
		t.Fatalf("%d accounts after every key was removed", len(a.List()))
	}
}
