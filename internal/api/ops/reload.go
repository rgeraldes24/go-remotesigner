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
// core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/ReloadHandler.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package ops

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
	"github.com/rgeraldes24/go-remotesigner/internal/server"
)

// ReloadStatus is the state GET /reload reports.
type ReloadStatus string

// Reload states.
const (
	ReloadIdle                ReloadStatus = "idle"
	ReloadRunning             ReloadStatus = "running"
	ReloadCompleted           ReloadStatus = "completed"
	ReloadCompletedWithErrors ReloadStatus = "completed_with_errors"
	ReloadFailed              ReloadStatus = "failed"
)

// LoadFunc loads keys from every source. It returns the number of sources
// that failed while the others loaded, or an error when the load as a whole
// failed and nothing changed.
type LoadFunc func(ctx context.Context) (errorCount int, err error)

// Reloader runs key loads one at a time on a background goroutine: the
// initial load at startup and every POST /reload.
type Reloader struct {
	load LoadFunc
	log  logrus.FieldLogger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu        sync.Mutex
	running   bool
	closed    bool
	status    ReloadStatus
	lastTime  time.Time
	lastError string
}

// NewReloader returns an idle reloader.
func NewReloader(load LoadFunc, log logrus.FieldLogger) *Reloader {
	ctx, cancel := context.WithCancel(context.Background())
	return &Reloader{load: load, log: log, ctx: ctx, cancel: cancel, status: ReloadIdle}
}

// Start begins a load unless one is running, or the reloader is closed. It
// returns a channel closed when the load finishes, or nil if it did not
// start.
func (r *Reloader) Start() <-chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running || r.closed {
		return nil
	}
	r.running = true
	r.status = ReloadRunning
	r.lastTime = time.Now().UTC()
	r.lastError = ""
	done := make(chan struct{})
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer close(done)
		errs, err := r.load(r.ctx)
		r.finish(errs, err)
	}()
	return done
}

func (r *Reloader) finish(errs int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.running = false
	r.lastTime = time.Now().UTC()
	switch {
	case err != nil:
		r.status = ReloadFailed
		r.lastError = "reload failed; see the signer log"
		r.log.WithError(err).Error("Key reload failed")
	case errs > 0:
		r.status = ReloadCompletedWithErrors
		r.lastError = fmt.Sprintf("reload completed with %d key loading error(s)", errs)
		r.log.WithField("errors", errs).Warn("Key reload completed with errors")
	default:
		r.status = ReloadCompleted
		r.log.Info("Key reload completed")
	}
}

// Close cancels a running load and waits for it to stop. Later Start calls
// do nothing.
func (r *Reloader) Close() {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	r.cancel()
	r.wg.Wait()
}

type reloadStatusBody struct {
	Status            ReloadStatus `json:"status"`
	LastOperationTime string       `json:"lastOperationTime,omitempty"`
	LastError         string       `json:"lastError,omitempty"`
}

// StatusHandler serves GET /reload.
func (r *Reloader) StatusHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		r.mu.Lock()
		body := reloadStatusBody{Status: r.status, LastError: r.lastError}
		if !r.lastTime.IsZero() {
			body.LastOperationTime = r.lastTime.Format(time.RFC3339)
		}
		r.mu.Unlock()
		writeJSON(w, http.StatusOK, body)
	})
}

type statusMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// StartHandler serves POST /reload: 202 when a load starts, 409
// RELOAD_IN_PROGRESS while one runs (including the initial load).
func (r *Reloader) StartHandler(log logrus.FieldLogger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if r.Start() == nil {
			server.WriteError(w, log, req, apierr.New(apierr.ReloadInProgress, "a reload is running"))
			return
		}
		writeJSON(w, http.StatusAccepted, statusMessage{Code: http.StatusAccepted, Message: "reload started"})
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", server.ContentTypeJSON)
	w.WriteHeader(code)
	_, _ = w.Write(data)
}
