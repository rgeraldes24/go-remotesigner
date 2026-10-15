// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package consensus

import (
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/policy"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/types"
	"github.com/rgeraldes24/go-remotesigner/internal/metrics"
	"github.com/rgeraldes24/go-remotesigner/internal/randao"
	"github.com/rgeraldes24/go-remotesigner/internal/server"
	"github.com/rgeraldes24/go-remotesigner/internal/signer"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// RandaoBodyLimit is the body limit of POST …/randao_reveal/{identifier};
// a valid body is about 300 bytes.
const RandaoBodyLimit = 4 << 10

// RandaoReveal serves POST /api/v1/consensus/randao_reveal/{identifier}
// (docs/contract.md section 14): identifier precheck and strict decode
// (400), fork_info (400, or the trust-on-first-use pin), key lookup (404,
// 503 KEY_QUARANTINED), a seed-holding key (422
// RANDAO_UNSUPPORTED_FOR_KEY), then the frontier rule of package randao,
// which commits the new frontier before the layer is returned.
type RandaoReveal struct {
	Policy  *policy.Policy
	Signer  *signer.Signer
	Reveals *randao.Service
	Pinner  GVRPinner
	Metrics *metrics.Metrics
	Log     logrus.FieldLogger
}

// ServeHTTP serves one reveal request.
func (h *RandaoReveal) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key, result, e := h.serve(r)
	if e != nil {
		if e.RetryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(int((e.RetryAfter+time.Second-1)/time.Second)))
		}
		server.WriteError(w, h.Log, r, e.Error)
		h.record(key, e.Status(), result, e.Error)
		return
	}
	data := []byte(`{"randao_reveal":"0x` + hex.EncodeToString(result.reveal[:]) + `"}`)
	w.Header().Set("Content-Type", server.ContentTypeJSON)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
	h.record(key, http.StatusOK, result, nil)
}

// revealResult is the released layer and its metrics class.
type revealResult struct {
	reveal [32]byte
	class  string
}

// revealError is a refusal with an optional Retry-After.
type revealError struct {
	*apierr.Error
	RetryAfter time.Duration
}

func (h *RandaoReveal) serve(r *http.Request) (key string, res revealResult, e *revealError) {
	fail := func(ae *apierr.Error) *revealError { return &revealError{Error: ae} }
	id, ae := ParseIdentifier(r.PathValue("identifier"))
	if ae != nil {
		return "", res, fail(ae)
	}
	key = shortKeyID(id)
	body, ae := server.ReadBody(r)
	if ae != nil {
		return key, res, fail(ae)
	}
	req, err := types.DecodeRandaoRevealRequest(body)
	if err != nil {
		return key, res, fail(asAPIError(err))
	}
	gvr, pin, err := h.Policy.CheckForkInfo(&req.ForkInfo)
	if err != nil {
		return key, res, fail(asAPIError(err))
	}
	k, err := h.Signer.Lookup(id)
	switch {
	case errors.Is(err, signer.ErrUnknownKey):
		return key, res, fail(apierr.New(apierr.UnknownKey, "no loaded key has this identifier"))
	case errors.Is(err, signer.ErrQuarantined):
		return key, res, fail(apierr.New(apierr.KeyQuarantined, "key quarantined after a signature fault"))
	case err != nil:
		return key, res, fail(apierr.New(apierr.Internal, "lookup: "+err.Error()))
	}
	pk := k.PublicKey()
	key = pk.LogID()
	holder, ok := k.(randao.SeedHolder)
	if !ok {
		return key, res, fail(apierr.New(apierr.RandaoUnsupportedForKey, "key holds no 48-byte seed"))
	}
	if pin {
		if ae := pinGVR(r.Context(), h.Pinner, h.Policy, gvr, h.Log); ae != nil {
			return key, res, fail(ae)
		}
	}
	out := h.Reveals.Reveal(r.Context(), randao.Request{
		ID: slashing.KeyID(id), Key: holder, Slot: req.Slot, Commitment: req.RandaoCommitment, LogID: key,
	})
	res.class = out.Result
	if out.Err != nil {
		return key, res, &revealError{Error: out.Err, RetryAfter: out.RetryAfter}
	}
	res.reveal = out.Reveal
	return key, res, nil
}

// record counts the request and logs it with the short key, never the
// commitment or the reveal. Refusals are logged at WARN.
func (h *RandaoReveal) record(key string, status int, res revealResult, e *apierr.Error) {
	if res.class == "" {
		res.class = resultOfStatus(status)
	}
	if res.class != "" {
		h.Metrics.RandaoReveals.WithLabelValues(res.class).Inc()
	}
	f := logrus.Fields{"key": key, "status": status}
	if res.class != "" {
		f["result"] = res.class
	}
	if e != nil {
		f["reason"] = e.Reason
	}
	l := h.Log.WithFields(f)
	switch {
	case status == http.StatusPreconditionFailed, status == http.StatusUnprocessableEntity,
		status == http.StatusTooManyRequests:
		l.Warn("RANDAO reveal refused")
	case status < 500:
		l.Debug("RANDAO reveal")
	}
}

// resultOfStatus maps the status of a request the frontier rule did not
// classify to the result label: refused for 412, 422 and 429, error for
// 5xx, and nothing for the rest (400, 404), which the counter leaves out.
func resultOfStatus(status int) string {
	switch {
	case status == http.StatusPreconditionFailed, status == http.StatusUnprocessableEntity,
		status == http.StatusTooManyRequests:
		return metrics.RandaoRefused
	case status >= 500:
		return metrics.RandaoError
	default:
		return ""
	}
}

// RandaoReset serves DELETE /api/v1/consensus/randao_state/{identifier}
// (admin): it clears a registered key's frontier, so that its next reveal
// is a first use under the new-layer conditions. The route answers 404
// PROTECTION_DISABLED while slashing protection is disabled, since the
// frontier then lives in memory only.
type RandaoReset struct {
	// Reveals is nil when slashing protection is disabled.
	Reveals *randao.Service
	Log     logrus.FieldLogger
}

// ServeHTTP clears one frontier.
func (h *RandaoReset) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id, ae := ParseIdentifier(r.PathValue("identifier"))
	if ae != nil {
		server.WriteError(w, h.Log, r, ae)
		return
	}
	if h.Reveals == nil {
		server.WriteError(w, h.Log, r, apierr.New(apierr.ProtectionDisabled, "slashing protection is disabled"))
		return
	}
	err := h.Reveals.Reset(r.Context(), slashing.KeyID(id))
	switch {
	case errors.Is(err, randao.ErrNotRegistered):
		server.WriteError(w, h.Log, r, apierr.New(apierr.UnknownKey, "key is not registered in slashing protection"))
		return
	case err != nil:
		server.WriteError(w, h.Log, r, apierr.New(apierr.StoreUnavailable, "reset randao state: "+err.Error()))
		return
	}
	h.Log.WithField("key-id", shortKeyID(id)).Warn("RANDAO state reset by the admin API: the key's next reveal is a first use")
	data := []byte(`{"code":200,"message":"randao state cleared"}`)
	w.Header().Set("Content-Type", server.ContentTypeJSON)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
