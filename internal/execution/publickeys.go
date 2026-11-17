// Copyright 2020 ConsenSys AG.
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
// core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/PublicKeysListHandler.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

//go:build !noexecution

package execution

import (
	"bufio"
	"encoding/hex"
	"net/http"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
)

// PublicKeysPath lists the loaded accounts with their public keys.
const PublicKeysPath = "/api/v1/execution/publicKeys"

// publicKeys serves GET /api/v1/execution/publicKeys: a JSON array of
// {"address", "public_key"} objects, sorted by address, with the address
// in QIP-55 form and the 2,592-byte public key in 0x hex. An ML-DSA
// signature from qrl_sign carries no public key and cannot be recovered
// from, so a verifier takes the key from here. The array is streamed one
// account at a time.
func publicKeys(accounts *Accounts) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if r.Method == http.MethodHead {
			return
		}
		bw := bufio.NewWriterSize(w, 64<<10)
		defer func() { _ = bw.Flush() }()
		var item [len(`,{"address":"","public_key":"0x"}`) + 1 + 2*mldsa87.AddressSize + 2*mldsa87.PublicKeySize]byte
		_ = bw.WriteByte('[')
		for i, a := range accounts.List() {
			b := append(item[:0], `,{"address":"`...)
			b = append(b, mldsa87.ChecksumAddress(a.Address)...)
			b = append(b, `","public_key":"0x`...)
			b = hex.AppendEncode(b, a.PublicKey[:])
			b = append(b, `"}`...)
			if i == 0 {
				b = b[1:]
			}
			if _, err := bw.Write(b); err != nil {
				return // the client went away
			}
		}
		_ = bw.WriteByte(']')
	})
}
