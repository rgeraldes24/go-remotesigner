// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
	"github.com/rgeraldes24/go-remotesigner/internal/api/jsonutil"
)

// RandaoRevealRequest is a decoded body of
// POST /api/v1/consensus/randao_reveal/{identifier} (docs/contract.md
// section 14.2).
type RandaoRevealRequest struct {
	// Slot is the proposal slot.
	Slot uint64
	// RandaoCommitment is the validator's commitment as the client read it
	// from its beacon node.
	RandaoCommitment [32]byte
	// ForkInfo scopes the reveal state to a network, as for sign requests.
	ForkInfo ForkInfo
}

// DecodeRandaoRevealRequest strictly decodes a RANDAO reveal body. The
// reasons are those of DecodeSignRequest; a missing fork_info is
// MISSING_FORK_INFO.
func DecodeRandaoRevealRequest(body []byte) (*RandaoRevealRequest, error) {
	if err := jsonutil.Validate(body); err != nil {
		return nil, err
	}
	req := new(RandaoRevealRequest)
	var forkInfo jsonutil.RawValue
	if err := jsonutil.DecodeObject(body,
		jsonutil.Field{Name: "slot", Value: u64(&req.Slot)},
		jsonutil.Field{Name: "randao_commitment", Value: jsonutil.HexBytesN(req.RandaoCommitment[:])},
		jsonutil.Field{Name: "fork_info", Value: &forkInfo, Optional: true},
	); err != nil {
		return nil, err
	}
	if forkInfo == nil {
		return nil, apierr.New(apierr.MissingForkInfo, "fork_info is required")
	}
	fi, err := decodeForkInfo(forkInfo)
	if err != nil {
		return nil, err
	}
	req.ForkInfo = *fi
	return req, nil
}

// MarshalJSON writes the canonical body.
func (r RandaoRevealRequest) MarshalJSON() ([]byte, error) {
	return jsonutil.EncodeObject(
		jsonutil.Field{Name: "slot", Value: u64(&r.Slot)},
		jsonutil.Field{Name: "randao_commitment", Value: jsonutil.HexBytesN(r.RandaoCommitment[:])},
		jsonutil.Field{Name: "fork_info", Value: object(r.ForkInfo.fields())},
	)
}
