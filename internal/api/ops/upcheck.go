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
// core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/UpcheckHandler.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

// Package ops holds the operational handlers: /upcheck, /healthcheck and
// /reload.
package ops

import (
	"net/http"
)

const textPlain = "text/plain; charset=utf-8"

// Upcheck serves GET /upcheck: "OK" once ready, and 503 "LOADING" until the
// first key load and the store open have finished. The signer listens before
// its keys are loaded, so orchestrators can tell "starting" from "down".
func Upcheck(ready func() bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", textPlain)
		if !ready() {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("LOADING"))
			return
		}
		_, _ = w.Write([]byte("OK"))
	})
}
