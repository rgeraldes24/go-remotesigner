// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/types"
)

// boundCases builds, for every type, a request at the value its bound reads.
var boundCases = []struct {
	name    string
	byEpoch bool // the bound reads an epoch, not a slot
	req     func(v uint64) *types.SignRequest
}{
	{"BLOCK_V2", false, func(v uint64) *types.SignRequest {
		return sign(&types.BlockV2{Header: types.BeaconBlockHeader{Slot: v}})
	}},
	{"ATTESTATION", true, func(v uint64) *types.SignRequest {
		return sign(&types.AttestationData{Slot: v, Target: types.Checkpoint{Epoch: v}})
	}},
	{"AGGREGATION_SLOT", false, func(v uint64) *types.SignRequest { return sign(&types.AggregationSlot{Slot: v}) }},
	{"AGGREGATE_AND_PROOF", false, func(v uint64) *types.SignRequest {
		r := aggregate([]byte{0x01}, 0)
		r.Payload.(*types.AggregateAttestationAndProof).Aggregate.Data.Slot = v
		return r
	}},
	{"VOLUNTARY_EXIT", true, func(v uint64) *types.SignRequest { return sign(&types.VoluntaryExit{Epoch: v}) }},
	{"SYNC_COMMITTEE_MESSAGE", false, func(v uint64) *types.SignRequest { return sign(&types.SyncCommitteeMessage{Slot: v}) }},
	{"SYNC_COMMITTEE_SELECTION_PROOF", false, func(v uint64) *types.SignRequest {
		return sign(&types.SyncAggregatorSelectionData{Slot: v})
	}},
	{"SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF", false, func(v uint64) *types.SignRequest {
		r := contribution(0, []byte{0x01, 0x00}, 1)
		r.Payload.(*types.ContributionAndProof).Contribution.Slot = v
		return r
	}},
}

func checkErr(p *Policy, req *types.SignRequest) error {
	_, err := p.Check(req, testKeyID)
	return err
}

// Every type at its bound passes and one past it is refused with 412
// CLOCK_BOUND, including both selection proofs at now_slot + skew + 1.
func TestClockBounds(t *testing.T) {
	for _, skew := range []uint64{0, 1, 3} {
		p := newPolicy(t, Config{ClockSkewSlots: skew, VoluntaryExitsEnabled: true, Now: at(100, 5)})
		for _, c := range boundCases {
			limit := 100 + skew // now_slot + skew
			if c.byEpoch {
				limit = 100/6 + 1 // now_epoch + 1, independent of the skew
			}
			if err := checkErr(p, c.req(limit)); err != nil {
				t.Errorf("skew %d, %s at %d: %v", skew, c.name, limit, err)
			}
			if err := checkErr(p, c.req(limit+1)); reason(t, err) != apierr.ClockBound {
				t.Errorf("skew %d, %s at %d: %v, want CLOCK_BOUND", skew, c.name, limit+1, err)
			}
			if err := checkErr(p, c.req(1<<64-1)); reason(t, err) != apierr.ClockBound {
				t.Errorf("skew %d, %s at max uint64: %v", skew, c.name, err)
			}
			if err := checkErr(p, c.req(0)); err != nil {
				t.Errorf("skew %d, %s at 0: %v", skew, c.name, err)
			}
		}
	}
}

func TestRegistrationBound(t *testing.T) {
	now := int64(genesis + 1005)
	p := newPolicy(t, Config{Now: func() time.Time { return time.Unix(now, 0) }})
	if err := checkErr(p, registration(1, uint64(now)+10)); err != nil {
		t.Errorf("timestamp now+SECONDS_PER_SLOT refused: %v", err)
	}
	if err := checkErr(p, registration(1, uint64(now)+11)); reason(t, err) != apierr.ClockBound {
		t.Errorf("timestamp now+SECONDS_PER_SLOT+1: %v", err)
	}
	if err := checkErr(p, registration(1, 0)); err != nil {
		t.Errorf("old timestamp refused: %v", err)
	}
}

// Without the genesis time every bound is off (docs/contract.md section 12).
func TestClockBoundsNeedGenesisTime(t *testing.T) {
	p := newPolicy(t, Config{Network: e2e(t, true, false), VoluntaryExitsEnabled: true})
	if p.ClockBoundsActive() {
		t.Fatal("bounds active without genesis time")
	}
	for _, c := range boundCases {
		if err := checkErr(p, c.req(1<<64-1)); err != nil {
			t.Errorf("%s far in the future: %v", c.name, err)
		}
	}
	if err := checkErr(p, registration(1, 1<<64-1)); err != nil {
		t.Errorf("registration far in the future: %v", err)
	}
	if !newPolicy(t, Config{}).ClockBoundsActive() {
		t.Error("bounds inactive with genesis time")
	}
}

// Before genesis now_slot is negative and floors: 5 s before genesis it is
// -1, 15 s before it is -2.
func TestClockBeforeGenesis(t *testing.T) {
	tests := []struct {
		offset int64 // seconds relative to genesis
		skew   uint64
		slot0  bool // slot 0 allowed
		epoch0 bool // epoch 0 allowed
	}{
		{0, 0, true, true},
		{-5, 1, true, true},  // now_slot -1, limit 0
		{-5, 0, false, true}, // limit -1; now_epoch -1, limit 0
		{-15, 1, false, true},
		{-15, 2, true, true},
		{-65, 5, false, false}, // now_slot -7, now_epoch -2
		{-genesis - 100, 1, false, false},
	}
	for _, tt := range tests {
		now := func() time.Time { return time.Unix(genesis+tt.offset, 0) }
		p := newPolicy(t, Config{ClockSkewSlots: tt.skew, Now: now})
		blockErr := checkErr(p, boundCases[0].req(0))
		attErr := checkErr(p, boundCases[1].req(0))
		if (blockErr == nil) != tt.slot0 || (attErr == nil) != tt.epoch0 {
			t.Errorf("offset %d skew %d: block %v, attestation %v", tt.offset, tt.skew, blockErr, attErr)
		}
	}
}

func TestClockSkewSaturates(t *testing.T) {
	p := newPolicy(t, Config{ClockSkewSlots: 1<<64 - 1})
	if err := checkErr(p, boundCases[0].req(1<<64-1)); err != nil {
		t.Errorf("max skew: %v", err)
	}
}
