// Copyright 2019 ConsenSys AG.
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
// core/src/integrationTest/java/tech/pegasys/web3signer/core/jsonrpcproxy/EthAccountsIntegrationTest.java,
// core/src/integrationTest/java/tech/pegasys/web3signer/core/jsonrpcproxy/EthSignIntegrationTest.java,
// core/src/test/java/tech/pegasys/web3signer/core/service/jsonrpc/EthSignResultProviderTest.java and
// core/src/test/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/RequestMapperTest.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

//go:build !noexecution

package execution

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
)

// ethAccountsRequestFromWeb3jRespondsWithNodesAddress: qrl_accounts
// answers with the loaded account, as JSON.
func TestW3SAccountsRespondsWithLoadedAddress(t *testing.T) {
	f := newFixture(t, 1, defaultAllow)
	_, addr := f.key(0)
	w := f.post(call(1, MethodAccounts), nil)
	if w.Header().Get("Content-Type") != "application/json" ||
		w.Body.String() != string(encodeResult([]byte("1"), []string{addr}, nil)) {
		t.Fatalf("%v %s", w.Header(), w.Body)
	}
}

// ethSignSignsMessageWhenAnUnlockedAccountIsPassed and
// returnsExpectedSignature: the signature is the account's over the
// prefixed message. ML-DSA signatures are hedged, so it is checked by
// verifying, not by comparing bytes.
func TestW3SSignSignsWithAnUnlockedAccount(t *testing.T) {
	f := newFixture(t, 1, defaultAllow)
	k, addr := f.key(0)
	for _, data := range []string{"0xdeadbeaf", "0x" + hex.EncodeToString([]byte("Lorem ipsum dolor sit amet"))} {
		w := f.post(call(1, MethodSign, addr, data), nil)
		r := decodeOne(t, w.Body.Bytes())
		var sigHex string
		if w.Header().Get("Content-Type") != "application/json" || json.Unmarshal(r.Result, &sigHex) != nil {
			t.Fatalf("%v %s", w.Header(), w.Body)
		}
		sig, _ := hex.DecodeString(strings.TrimPrefix(sigHex, "0x"))
		msg, _ := hex.DecodeString(strings.TrimPrefix(data, "0x"))
		digest := TextHash(msg)
		if len(sig) != mldsa87.SignatureSize || !k.Verify(digest[:], sig) {
			t.Fatalf("%s: the signature is not the account's over TextHash", data)
		}
	}
}

// ethSignExpectsFirstParameterToBeEth1Address and
// ethSignDoNotSignMessageWhenSignerAccountIsNotLoaded: a public key, or an
// address that is not loaded, is not an unlocked account.
func TestW3SSignRefusesUnknownAccounts(t *testing.T) {
	f := newFixture(t, 1, defaultAllow)
	k, _ := f.key(0)
	pk := k.PublicKey()
	other, err := mldsa87.FromExtendedSeed51(&[mldsa87.ExtendedSeedSize]byte{0x01})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Zeroize()
	otherPK := other.PublicKey()
	for name, tt := range map[string]struct {
		address string
		code    int
	}{
		// gqrl decodes the address before looking it up, so a public key is
		// invalid params rather than an unknown account.
		"public key":         {"0x" + hex.EncodeToString(pk[:]), ErrInvalidParams.Code},
		"address not loaded": {mldsa87.ChecksumAddress(otherPK.Address()), ErrUnknownAccount.Code},
	} {
		w := f.post(call(1, MethodSign, tt.address, "0x00"), nil)
		if r := decodeOne(t, w.Body.Bytes()); r.Error == nil || r.Error.Code != tt.code {
			t.Errorf("%s: %s, want error %d", name, w.Body, tt.code)
		}
	}
	w := f.post(call(1, MethodSign, mldsa87.ChecksumAddress(otherPK.Address()), "0x00"), nil)
	if w.Code != http.StatusOK || w.Body.String() != string(encodeResult([]byte("1"), nil, ErrUnknownAccount)) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// ifParamIsInvalidExceptionIsThrownWithInvalidParams.
func TestW3SSignInvalidParams(t *testing.T) {
	f := newFixture(t, 1, defaultAllow)
	for _, params := range []string{`[]`, `[2]`, `[1,2,3]`, `{}`, `null`} {
		w := f.post(`{"jsonrpc":"2.0","id":1,"method":"qrl_sign","params":`+params+`}`, nil)
		if r := decodeOne(t, w.Body.Bytes()); w.Code != http.StatusBadRequest || r.Error.Code != ErrInvalidParams.Code {
			t.Errorf("params %s: %d %s", params, w.Code, w.Body)
		}
	}
}

// RequestMapperTest: a method of the table gets its handler; any other
// method, the empty name included, is not local.
func TestW3SRequestMapper(t *testing.T) {
	f := newFixture(t, 0, defaultAllow)
	for _, m := range []string{MethodAccounts, MethodSign, MethodHealthStatus} {
		if f.handler.table[m] == nil {
			t.Errorf("%s has no handler", m)
		}
	}
	for _, m := range []string{"", "nothing", "eth_accounts", "eth_sign"} {
		if f.handler.table[m] != nil {
			t.Errorf("%q has a local handler", m)
		}
	}
}
