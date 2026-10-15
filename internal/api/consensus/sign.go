// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package consensus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/policy"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/signingroot"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/types"
	"github.com/rgeraldes24/go-remotesigner/internal/metrics"
	"github.com/rgeraldes24/go-remotesigner/internal/server"
	"github.com/rgeraldes24/go-remotesigner/internal/signer"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// SignBodyLimit is the body limit of POST …/sign/{identifier}: the largest
// valid body, a 128-signature contribution, is 1,195,027 bytes.
const SignBodyLimit = 2 << 20

// GVRPinner pins a trust-on-first-use genesis validators root in the
// slashing-protection store; the stores implement it.
type GVRPinner interface {
	PinGenesisValidatorsRoot(ctx context.Context, gvr slashing.Root) (slashing.Root, error)
}

// Sign serves POST /api/v1/consensus/sign/{identifier}. It runs steps 2 to
// 13 of the validation pipeline (docs/contract.md section 7) after the
// server's middleware has run step 1:
//
//   - identifier precheck and strict decode (400);
//   - type policy, invariants, signing-root recompute, fork_info and clock
//     bound (policy.Check: 403, 400, 412);
//   - key lookup (404, 503 KEY_QUARANTINED);
//   - the trust-on-first-use GVR pin, when one is pending;
//   - slashing check-and-record for blocks and attestations (412), committed
//     before anything is signed;
//   - sign in the type's mode, verify before release (500 SIGNATURE_FAULT
//     and quarantine), respond.
//
// A refused request never reaches the key. The response cache of step 9
// is not part of this release, so a repeated hedged request is signed
// again (a repeat of a recorded block or attestation is allowed by
// slashing protection without a new record).
type Sign struct {
	Policy *policy.Policy
	Signer *signer.Signer
	// Protector applies slashing protection to blocks and attestations. It
	// is nil when protection is disabled, which startup allows only when
	// every listener is loopback; they are then signed unchecked.
	Protector slashing.Protector
	// Pinner pins a pending GVR before the first accepted request is signed.
	Pinner  GVRPinner
	Metrics *metrics.Metrics
	Log     logrus.FieldLogger
}

// signResponse is the JSON success body.
type signResponse struct {
	Signature string `json:"signature"`
}

// ServeHTTP signs one request.
func (h *Sign) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	x := &exchange{h: h, w: w, r: r}
	x.serve()
}

// exchange is one sign request on its way through the pipeline. It records
// what the metrics and the log need as it learns it.
type exchange struct {
	h *Sign
	w http.ResponseWriter
	r *http.Request

	typ  signingroot.ArtifactType // "" until decoded
	key  string                   // log form of the key, once known
	body []byte
}

func (x *exchange) serve() {
	ident := x.r.PathValue("identifier")
	id, e := ParseIdentifier(ident)
	if e != nil {
		x.malformed(e)
		return
	}
	x.key = shortKeyID(id)
	body, e := server.ReadBody(x.r)
	if e != nil {
		x.malformed(e)
		return
	}
	x.body = body
	req, err := types.DecodeSignRequest(body, x.h.Policy.Params())
	if err != nil {
		var ae *apierr.Error
		if errors.As(err, &ae) {
			x.malformed(ae)
			return
		}
		x.fail(apierr.New(apierr.Internal, "decoder parameters: "+err.Error()))
		return
	}
	x.typ = req.Type()

	d, err := x.h.Policy.Check(req, id)
	if err != nil {
		x.fail(asAPIError(err))
		return
	}

	key, err := x.h.Signer.Lookup(id)
	if err != nil {
		x.fail(x.signerError(err))
		return
	}
	pk := key.PublicKey()
	x.key = pk.LogID()

	if d.PinGVR {
		if e := x.pin(d.GenesisValidatorsRoot); e != nil {
			x.fail(e)
			return
		}
	}
	if x.h.Protector != nil && d.Protection != policy.ProtectionNone {
		if e := x.protect(d, pk[:]); e != nil {
			x.fail(e)
			return
		}
	}

	sig, err := x.h.Signer.Sign(id, key, x.typ, d.SigningRoot)
	if err != nil {
		x.fail(x.signerError(err))
		return
	}
	x.respond(sig)
}

// pin binds a pending trust-on-first-use GVR: the store first, so that a
// restart keeps it, then the policy. Of concurrent first requests with
// different roots, one wins and the others get FORK_INFO_MISMATCH.
func (x *exchange) pin(gvr [32]byte) *apierr.Error {
	pinned, err := x.h.Pinner.PinGenesisValidatorsRoot(x.r.Context(), slashing.Root(gvr))
	if err != nil {
		return apierr.New(apierr.StoreUnavailable, "pin the genesis validators root: "+err.Error())
	}
	if err := x.h.Policy.PinGenesisValidatorsRoot(pinned); err != nil || pinned != gvr {
		return apierr.New(apierr.ForkInfoMismatch, "another genesis validators root was pinned first")
	}
	x.h.Log.WithField("genesis-validators-root", "0x"+hex.EncodeToString(gvr[:])).
		Warn("Genesis validators root pinned from the first accepted request (trust on first use)")
	return nil
}

// protect runs the slashing check-and-record of a block or attestation.
func (x *exchange) protect(d *policy.Decision, pubkey []byte) *apierr.Error {
	ctx, gvr := x.r.Context(), slashing.Root(d.GenesisValidatorsRoot)
	var (
		dec slashing.Decision
		err error
		op  string
	)
	start := time.Now()
	switch d.Protection {
	case policy.ProtectionBlock:
		op = metrics.OperationBlock
		dec, err = x.h.Protector.CheckAndRecordBlock(ctx, slashing.BlockRequest{
			PublicKey: pubkey, GenesisValidatorsRoot: gvr, Slot: d.Slot, SigningRoot: d.SigningRoot,
		})
	case policy.ProtectionAttestation:
		op = metrics.OperationAttestation
		dec, err = x.h.Protector.CheckAndRecordAttestation(ctx, slashing.AttestationRequest{
			PublicKey: pubkey, GenesisValidatorsRoot: gvr, SourceEpoch: d.SourceEpoch, TargetEpoch: d.TargetEpoch,
			SigningRoot: d.SigningRoot,
		})
	}
	x.h.Metrics.SlashingDatabaseDuration.WithLabelValues(op).Observe(time.Since(start).Seconds())
	switch {
	case errors.Is(err, slashing.ErrGenesisValidatorsRootMismatch):
		return apierr.New(apierr.ForkInfoMismatch, "genesis validators root differs from the store's")
	case errors.Is(err, slashing.ErrSourceAfterTarget):
		return apierr.New(apierr.InvariantViolation, "source epoch after target epoch")
	case err != nil:
		return apierr.New(apierr.StoreUnavailable, "slashing check-and-record: "+err.Error())
	case !dec.Allowed:
		x.h.Metrics.Prevented(dec.Reason).Inc()
		return apierr.New(apierr.Reason(dec.Reason), "slashing protection refused the request")
	}
	x.h.Metrics.SlashingPermitted.Inc()
	return nil
}

// signerError maps the signer's errors.
func (x *exchange) signerError(err error) *apierr.Error {
	switch {
	case errors.Is(err, signer.ErrUnknownKey):
		x.h.Metrics.MissingIdentifier.Inc()
		return apierr.New(apierr.UnknownKey, "no loaded key has this identifier")
	case errors.Is(err, signer.ErrQuarantined):
		return apierr.New(apierr.KeyQuarantined, "key quarantined after a signature fault")
	case errors.Is(err, signer.ErrSignatureFault):
		return apierr.New(apierr.SignatureFault, "signature failed verification")
	default:
		return apierr.New(apierr.Internal, "sign: "+err.Error())
	}
}

// malformed refuses a request whose identifier or body is malformed.
func (x *exchange) malformed(e *apierr.Error) {
	x.h.Metrics.MalformedRequests.Inc()
	x.fail(e)
}

// fail writes an error response and records it.
func (x *exchange) fail(e *apierr.Error) {
	server.WriteError(x.w, x.h.Log, x.r, e)
	x.record(e.Status(), e)
}

// respond writes the signature as JSON, or as text when the client asks
// for text/plain and not JSON.
func (x *exchange) respond(sig signer.Signature) {
	hexSig := "0x" + hex.EncodeToString(sig[:])
	var data []byte
	h := x.w.Header()
	if wantsText(x.r.Header.Values("Accept")) {
		h.Set("Content-Type", "text/plain; charset=utf-8")
		data = []byte(hexSig)
	} else {
		h.Set("Content-Type", server.ContentTypeJSON)
		data = append(append([]byte(`{"signature":"`), hexSig...), `"}`...)
	}
	h.Set("Content-Length", strconv.Itoa(len(data)))
	x.w.WriteHeader(http.StatusOK)
	_, _ = x.w.Write(data)
	x.record(http.StatusOK, nil)
}

// record counts the request and logs it: the type, the short key, the
// first 8 hex characters of sha256(body) and the body length, never the
// body or the full identifier. Refusals by policy, clock or slashing
// protection are logged at WARN.
func (x *exchange) record(status int, e *apierr.Error) {
	if x.typ != "" {
		x.h.Metrics.SigningRequests.WithLabelValues(string(x.typ), metrics.ResultOf(status)).Inc()
	}
	sum := sha256.Sum256(x.body)
	f := logrus.Fields{
		"type": x.typ, "key": x.key, "status": status,
		"body-sha256": hex.EncodeToString(sum[:4]), "body-length": len(x.body),
	}
	if e != nil {
		f["reason"] = e.Reason
	}
	l := x.h.Log.WithFields(f)
	switch {
	case status == http.StatusPreconditionFailed:
		l.Warn("Sign request refused")
	case status < 500:
		l.Debug("Sign request")
	}
}

// asAPIError returns the *apierr.Error in err, or an INTERNAL error.
func asAPIError(err error) *apierr.Error {
	var e *apierr.Error
	if errors.As(err, &e) {
		return e
	}
	return apierr.New(apierr.Internal, err.Error())
}

// wantsText reports whether the Accept header values list text/plain and
// not application/json (a media range with q=0 is not listed).
func wantsText(accept []string) bool {
	text, json := false, false
	for _, v := range accept {
		for part := range strings.SplitSeq(v, ",") {
			mt, params, err := mime.ParseMediaType(strings.TrimSpace(part))
			if err != nil || isZeroQ(params["q"]) {
				continue
			}
			switch mt {
			case "text/plain":
				text = true
			case "application/json":
				json = true
			}
		}
	}
	return text && !json
}

func isZeroQ(q string) bool {
	if q == "" {
		return false
	}
	f, err := strconv.ParseFloat(q, 64)
	return err == nil && f == 0
}

// shortKeyID is the log form of a key known only by its id.
func shortKeyID(id [32]byte) string { return "0x…" + hex.EncodeToString(id[:4]) }
