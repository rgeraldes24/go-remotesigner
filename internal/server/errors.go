// Copyright 2026 ConsenSys AG.
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
// core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/JsonErrorHandler.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package server

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
)

// ContentTypeJSON is the Content-Type of every JSON response.
const ContentTypeJSON = "application/json; charset=utf-8"

// errorBody is the shape of every 4xx and 5xx response of the API
// (docs/contract.md section 11). Reason is omitted only for paths and
// methods outside the API, which have no catalogue reason.
type errorBody struct {
	Code    int           `json:"code"`
	Message string        `json:"message"`
	Reason  apierr.Reason `json:"reason,omitempty"`
}

// WriteError renders e as a JSON error response: its status, the reason's
// fixed message and the reason. The field path and detail are logged, never
// sent: they are for operators, and the response must carry no internals.
// 401 responses carry WWW-Authenticate: Bearer, and 503 responses
// Retry-After: 1. A refusal of the caller itself rather than of its request
// also closes the connection (ClosesConnection).
func WriteError(w http.ResponseWriter, log logrus.FieldLogger, r *http.Request, e *apierr.Error) {
	status := e.Status()
	logFailure(log, r, status, e)
	switch status {
	case http.StatusUnauthorized:
		w.Header().Set("WWW-Authenticate", "Bearer")
	case http.StatusServiceUnavailable:
		w.Header().Set("Retry-After", "1")
	}
	if ClosesConnection(e.Reason) {
		// HTTP/1.1 closes the connection after this response; HTTP/2 sends
		// GOAWAY and closes it once its open streams end.
		w.Header().Set("Connection", "close")
	}
	writeErrorBody(w, errorBody{Code: status, Message: e.Reason.Message(), Reason: e.Reason})
}

// ClosesConnection reports whether a refusal closes the connection it came
// on: 401 UNAUTHENTICATED (no credential, or one the route does not take),
// and 403 HOST_NOT_ALLOWED and ORIGIN_NOT_ALLOWED, which no client of the
// API sends. Kept open, such a connection would hold one of the listener's
// connection slots (--http-max-connections, or the metrics listener's cap)
// for the idle timeout, so a peer without a credential could hold them all
// by sending one refused request per connection now and then.
func ClosesConnection(r apierr.Reason) bool {
	switch r {
	case apierr.Unauthenticated, apierr.HostNotAllowed, apierr.OriginNotAllowed:
		return true
	}
	return false
}

// writePlainError renders a status that has no catalogue reason (an unknown
// path or method) in Web3Signer's {code, message} shape, with the status
// text as the message.
func writePlainError(w http.ResponseWriter, log logrus.FieldLogger, r *http.Request, status int) {
	logFailure(log, r, status, nil)
	writeErrorBody(w, errorBody{Code: status, Message: http.StatusText(status)})
}

func writeErrorBody(w http.ResponseWriter, b errorBody) {
	data, err := json.Marshal(b)
	if err != nil {
		// Unreachable: errorBody holds only an int and two strings.
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", ContentTypeJSON)
	h.Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(b.Code)
	_, _ = w.Write(data)
}

// logFailure records a refused or failed request: 5xx at ERROR, the rest at
// DEBUG. It logs the route pattern, never the path, which can hold a
// 5,186-character identifier.
func logFailure(log logrus.FieldLogger, r *http.Request, status int, e *apierr.Error) {
	if log == nil {
		return
	}
	fields := logrus.Fields{"method": r.Method, "route": routeOf(r), "status": status}
	if e != nil {
		fields["error"] = e.Error()
	}
	if status >= http.StatusInternalServerError {
		log.WithFields(fields).Error("Failed request")
	} else {
		log.WithFields(fields).Debug("Failed request")
	}
}

// routeOf returns the matched route pattern, or "-" before routing.
func routeOf(r *http.Request) string {
	if r.Pattern == "" {
		return "-"
	}
	return r.Pattern
}
