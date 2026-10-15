// Copyright 2020 ConsenSys AG.
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
// core/src/main/java/tech/pegasys/web3signer/core/Runner.java and
// core/src/main/java/tech/pegasys/web3signer/core/config/HealthCheckNames.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package ops

import (
	"context"
	"net/http"
	"time"
)

// Check ids, as Web3Signer names them.
const (
	CheckDefault            = "default-check"
	CheckSlashingProtection = "slashing-protection-db-health-check"
	CheckConfigFilesLoading = "keys-check/config-files-loading"
)

// CheckTimeout bounds one check.
const CheckTimeout = 3 * time.Second

// Check is one named health check.
type Check struct {
	ID string
	// Run reports whether the check is up, with optional data. It must
	// honour ctx, which carries CheckTimeout.
	Run func(ctx context.Context) (up bool, data map[string]any)
}

type checkResult struct {
	ID     string         `json:"id"`
	Status string         `json:"status"`
	Data   map[string]any `json:"data,omitempty"`
}

type healthBody struct {
	Status  string        `json:"status"`
	Outcome string        `json:"outcome"`
	Checks  []checkResult `json:"checks,omitempty"`
}

// Healthcheck serves GET /healthcheck in Web3Signer's JSON shape: 200 and
// UP when every check is up, 503 and DOWN otherwise. The per-check detail is
// shown only to callers that detail approves (the sign scope); everyone
// else sees status and outcome only.
func Healthcheck(checks []Check, detail func(*http.Request) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allUp := true
		results := make([]checkResult, 0, len(checks))
		for _, c := range checks {
			ctx, cancel := context.WithTimeout(r.Context(), CheckTimeout)
			up, data := c.Run(ctx)
			cancel()
			allUp = allUp && up
			results = append(results, checkResult{ID: c.ID, Status: status(up), Data: data})
		}
		body := healthBody{Status: status(allUp), Outcome: status(allUp)}
		if detail(r) {
			body.Checks = results
		}
		code := http.StatusOK
		if !allUp {
			code = http.StatusServiceUnavailable
		}
		writeJSON(w, code, body)
	})
}

func status(up bool) string {
	if up {
		return "UP"
	}
	return "DOWN"
}
