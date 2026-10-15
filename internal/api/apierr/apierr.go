// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package apierr holds the machine-readable refusal reasons of the consensus
// API (docs/contract.md, "Errors") and the error type that carries one.
//
// Every reason has exactly one HTTP status. Request decoders and policy
// checks return *Error; the HTTP layer writes its status, a fixed message
// and the reason, and never the detail, which is for logs.
package apierr

import (
	"errors"
	"net/http"
	"strconv"
)

// Reason is a value of the `reason` field of an error response.
type Reason string

// The error catalogue of docs/contract.md section 11, in its order.
const (
	BadIdentifier        Reason = "BAD_IDENTIFIER"
	MalformedJSON        Reason = "MALFORMED_JSON"
	UnknownField         Reason = "UNKNOWN_FIELD"
	BadField             Reason = "BAD_FIELD"
	UnknownType          Reason = "UNKNOWN_TYPE"
	MissingForkInfo      Reason = "MISSING_FORK_INFO"
	ForkInfoMismatch     Reason = "FORK_INFO_MISMATCH"
	SigningRootMismatch  Reason = "SIGNING_ROOT_MISMATCH"
	InvariantViolation   Reason = "INVARIANT_VIOLATION"
	PubkeyMismatch       Reason = "PUBKEY_MISMATCH"
	Unauthenticated      Reason = "UNAUTHENTICATED"
	ForbiddenScope       Reason = "FORBIDDEN_SCOPE"
	HostNotAllowed       Reason = "HOST_NOT_ALLOWED"
	OriginNotAllowed     Reason = "ORIGIN_NOT_ALLOWED"
	ArtifactTypeDisabled Reason = "ARTIFACT_TYPE_DISABLED"
	UnknownKey           Reason = "UNKNOWN_KEY"
	ProtectionDisabled   Reason = "PROTECTION_DISABLED"
	ReloadInProgress     Reason = "RELOAD_IN_PROGRESS"

	SlashingDoubleProposal     Reason = "SLASHING_DOUBLE_PROPOSAL"
	SlashingDoubleVote         Reason = "SLASHING_DOUBLE_VOTE"
	SlashingSurroundingVote    Reason = "SLASHING_SURROUNDING_VOTE"
	SlashingSurroundedVote     Reason = "SLASHING_SURROUNDED_VOTE"
	SlashingBelowWatermark     Reason = "SLASHING_BELOW_WATERMARK"
	SlashingAboveHighWatermark Reason = "SLASHING_ABOVE_HIGH_WATERMARK"
	ValidatorDisabled          Reason = "VALIDATOR_DISABLED"
	ClockBound                 Reason = "CLOCK_BOUND"
	RandaoSlotNotIncreasing    Reason = "RANDAO_SLOT_NOT_INCREASING"
	RandaoSlotOutOfWindow      Reason = "RANDAO_SLOT_OUT_OF_WINDOW"
	RandaoNewLayerRateLimited  Reason = "RANDAO_NEW_LAYER_RATE_LIMITED"

	BodyTooLarge            Reason = "BODY_TOO_LARGE"
	UnsupportedMediaType    Reason = "UNSUPPORTED_MEDIA_TYPE"
	RandaoUnknownCommitment Reason = "RANDAO_UNKNOWN_COMMITMENT"
	RandaoOnionExhausted    Reason = "RANDAO_ONION_EXHAUSTED"
	RandaoUnsupportedForKey Reason = "RANDAO_UNSUPPORTED_FOR_KEY"
	RandaoScanRateLimited   Reason = "RANDAO_SCAN_RATE_LIMITED"

	Internal         Reason = "INTERNAL"
	SignatureFault   Reason = "SIGNATURE_FAULT"
	StoreUnavailable Reason = "STORE_UNAVAILABLE"
	NotReady         Reason = "NOT_READY"
	Overloaded       Reason = "OVERLOADED"
	KeyQuarantined   Reason = "KEY_QUARANTINED"
)

var statuses = map[Reason]int{
	BadIdentifier:        http.StatusBadRequest,
	MalformedJSON:        http.StatusBadRequest,
	UnknownField:         http.StatusBadRequest,
	BadField:             http.StatusBadRequest,
	UnknownType:          http.StatusBadRequest,
	MissingForkInfo:      http.StatusBadRequest,
	ForkInfoMismatch:     http.StatusBadRequest,
	SigningRootMismatch:  http.StatusBadRequest,
	InvariantViolation:   http.StatusBadRequest,
	PubkeyMismatch:       http.StatusBadRequest,
	Unauthenticated:      http.StatusUnauthorized,
	ForbiddenScope:       http.StatusForbidden,
	HostNotAllowed:       http.StatusForbidden,
	OriginNotAllowed:     http.StatusForbidden,
	ArtifactTypeDisabled: http.StatusForbidden,
	UnknownKey:           http.StatusNotFound,
	ProtectionDisabled:   http.StatusNotFound,
	ReloadInProgress:     http.StatusConflict,

	SlashingDoubleProposal:     http.StatusPreconditionFailed,
	SlashingDoubleVote:         http.StatusPreconditionFailed,
	SlashingSurroundingVote:    http.StatusPreconditionFailed,
	SlashingSurroundedVote:     http.StatusPreconditionFailed,
	SlashingBelowWatermark:     http.StatusPreconditionFailed,
	SlashingAboveHighWatermark: http.StatusPreconditionFailed,
	ValidatorDisabled:          http.StatusPreconditionFailed,
	ClockBound:                 http.StatusPreconditionFailed,
	RandaoSlotNotIncreasing:    http.StatusPreconditionFailed,
	RandaoSlotOutOfWindow:      http.StatusPreconditionFailed,
	RandaoNewLayerRateLimited:  http.StatusPreconditionFailed,

	BodyTooLarge:            http.StatusRequestEntityTooLarge,
	UnsupportedMediaType:    http.StatusUnsupportedMediaType,
	RandaoUnknownCommitment: http.StatusUnprocessableEntity,
	RandaoOnionExhausted:    http.StatusUnprocessableEntity,
	RandaoUnsupportedForKey: http.StatusUnprocessableEntity,
	RandaoScanRateLimited:   http.StatusTooManyRequests,

	Internal:         http.StatusInternalServerError,
	SignatureFault:   http.StatusInternalServerError,
	StoreUnavailable: http.StatusInternalServerError,
	NotReady:         http.StatusServiceUnavailable,
	Overloaded:       http.StatusServiceUnavailable,
	KeyQuarantined:   http.StatusServiceUnavailable,
}

// Status returns the HTTP status of r, or 500 for a value outside the
// catalogue.
func (r Reason) Status() int {
	if s, ok := statuses[r]; ok {
		return s
	}
	return http.StatusInternalServerError
}

// Known reports whether r is in the catalogue.
func (r Reason) Known() bool {
	_, ok := statuses[r]
	return ok
}

// Reasons returns every reason in the catalogue, in no particular order.
func Reasons() []Reason {
	out := make([]Reason, 0, len(statuses))
	for r := range statuses {
		out = append(out, r)
	}
	return out
}

// Error is a refusal with its reason.
//
// Field is the JSON path of the offending field ("" for the whole body), for
// example "aggregate_and_proof.aggregate.signatures[3]". Detail is a fixed
// description. Neither ever contains request values, so both may be logged;
// an unknown field name is quoted and truncated.
type Error struct {
	Reason Reason
	Field  string
	Detail string
}

// New returns an error with reason r and detail.
func New(r Reason, detail string) *Error {
	return &Error{Reason: r, Detail: detail}
}

// Error formats the reason, the field path and the detail.
func (e *Error) Error() string {
	s := string(e.Reason)
	if e.Field != "" {
		s += " at " + e.Field
	}
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}

// Status returns the HTTP status of the reason.
func (e *Error) Status() int { return e.Reason.Status() }

// In prefixes the field path with an object key or an array index segment
// ("[3]") and returns e.
func (e *Error) In(segment string) *Error {
	switch {
	case e.Field == "":
		e.Field = segment
	case e.Field[0] == '[':
		e.Field = segment + e.Field
	default:
		e.Field = segment + "." + e.Field
	}
	return e
}

// Index returns the path segment of array element i.
func Index(i int) string {
	return "[" + strconv.Itoa(i) + "]"
}

// ReasonOf returns the reason of the first *Error in err's chain.
func ReasonOf(err error) (Reason, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason, true
	}
	return "", false
}
