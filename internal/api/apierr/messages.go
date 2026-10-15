// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package apierr

// messages are the fixed `message` strings of error responses. They name no
// path, value or internal error, so they are safe to send to any caller.
var messages = map[Reason]string{
	BadIdentifier:        "malformed identifier",
	MalformedJSON:        "malformed JSON",
	UnknownField:         "unknown field in request",
	BadField:             "invalid field value",
	UnknownType:          "unknown artifact type",
	MissingForkInfo:      "fork_info is required",
	ForkInfoMismatch:     "fork_info does not match the configured network",
	SigningRootMismatch:  "signing root does not match the request",
	InvariantViolation:   "request violates an invariant",
	PubkeyMismatch:       "pubkey does not match the identifier",
	Unauthenticated:      "unauthenticated",
	ForbiddenScope:       "token does not grant this scope",
	HostNotAllowed:       "host not authorized",
	OriginNotAllowed:     "cross-origin requests are not allowed",
	ArtifactTypeDisabled: "artifact type disabled",
	UnknownKey:           "public key not found",
	ProtectionDisabled:   "slashing protection is disabled",
	ReloadInProgress:     "reload already in progress",

	SlashingDoubleProposal:     "slashing protection refused the request",
	SlashingDoubleVote:         "slashing protection refused the request",
	SlashingSurroundingVote:    "slashing protection refused the request",
	SlashingSurroundedVote:     "slashing protection refused the request",
	SlashingBelowWatermark:     "slashing protection refused the request",
	SlashingAboveHighWatermark: "slashing protection refused the request",
	ValidatorDisabled:          "slashing protection refused the request",
	ClockBound:                 "request is outside the wall-clock bound",
	RandaoSlotNotIncreasing:    "randao reveal refused",
	RandaoSlotOutOfWindow:      "randao reveal refused",
	RandaoNewLayerRateLimited:  "randao new-layer rate limit reached for this key",

	BodyTooLarge:            "request body too large",
	UnsupportedMediaType:    "unsupported media type",
	RandaoUnknownCommitment: "commitment is not in this key's onion",
	RandaoOnionExhausted:    "onion exhausted",
	RandaoUnsupportedForKey: "key cannot produce randao reveals",
	RandaoScanRateLimited:   "randao scan rate limited",

	Internal:         "internal error",
	SignatureFault:   "internal error",
	StoreUnavailable: "slashing protection store unavailable",
	NotReady:         "signer is starting",
	Overloaded:       "signing queue full",
	KeyQuarantined:   "key quarantined",
}

// Message returns the fixed message of r, or "internal error" for a value
// outside the catalogue.
func (r Reason) Message() string {
	if m, ok := messages[r]; ok {
		return m
	}
	return messages[Internal]
}
