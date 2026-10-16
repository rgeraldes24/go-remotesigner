// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package consensus

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

type highWatermarkStore struct {
	hw  slashing.HighWatermark
	err error
}

func (s highWatermarkStore) HighWatermark(context.Context) (slashing.HighWatermark, error) {
	return s.hw, s.err
}

func TestHighWatermark(t *testing.T) {
	epoch, slot := uint64(1200), uint64(7200)
	for _, tc := range []struct {
		name  string
		store HighWatermarkReader
		code  int
		body  string
	}{
		{"set", highWatermarkStore{hw: slashing.HighWatermark{Epoch: &epoch, Slot: &slot}}, 200, `{"epoch":"1200","slot":"7200"}`},
		{"unset", highWatermarkStore{}, 200, `{}`},
		{"protection disabled", nil, 404, `"reason":"PROTECTION_DISABLED"`},
		{"store failure", highWatermarkStore{err: errors.New("disk")}, 500, `"reason":"STORE_UNAVAILABLE"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &HighWatermark{Store: tc.store, Log: logrus.New()}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/consensus/highWatermark", nil))
			body := rec.Body.String()
			if rec.Code != tc.code || !strings.Contains(body, tc.body) || (tc.code == 200 && body != tc.body) {
				t.Fatalf("%d %s, want %d %s", rec.Code, body, tc.code, tc.body)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Fatalf("Content-Type %q", ct)
			}
		})
	}
}
