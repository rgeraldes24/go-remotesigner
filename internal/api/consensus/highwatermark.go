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
// core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/HighWatermarkHandler.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package consensus

import (
	"context"
	"net/http"
	"strconv"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
	"github.com/rgeraldes24/go-remotesigner/internal/server"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// HighWatermarkReader reads the global high watermark.
type HighWatermarkReader interface {
	HighWatermark(ctx context.Context) (slashing.HighWatermark, error)
}

// HighWatermark serves GET /api/v1/consensus/highWatermark (sign scope): the global high watermark as
// {"epoch":"…","slot":"…"}, or {} when none is set. Web3Signer registers the route only with slashing protection;
// here it answers 404 PROTECTION_DISABLED while protection is disabled (docs/contract.md section 5).
type HighWatermark struct {
	// Store is nil when slashing protection is disabled.
	Store HighWatermarkReader
	Log   logrus.FieldLogger
}

// ServeHTTP writes the high watermark.
func (h *HighWatermark) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Store == nil {
		server.WriteError(w, h.Log, r, apierr.New(apierr.ProtectionDisabled, "slashing protection is disabled"))
		return
	}
	hw, err := h.Store.HighWatermark(r.Context())
	if err != nil {
		server.WriteError(w, h.Log, r, apierr.New(apierr.StoreUnavailable, "read the high watermark: "+err.Error()))
		return
	}
	data := []byte("{")
	if hw.Epoch != nil {
		data = strconv.AppendUint(append(data, `"epoch":"`...), *hw.Epoch, 10)
		data = append(data, '"')
	}
	if hw.Slot != nil {
		if hw.Epoch != nil {
			data = append(data, ',')
		}
		data = strconv.AppendUint(append(data, `"slot":"`...), *hw.Slot, 10)
		data = append(data, '"')
	}
	data = append(data, '}')
	w.Header().Set("Content-Type", server.ContentTypeJSON)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
