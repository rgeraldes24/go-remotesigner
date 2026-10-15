// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"math/bits"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/types"
)

// Wall-clock bounds (docs/contract.md section 12). With
// now_slot = (unix_now - genesis_time) / SECONDS_PER_SLOT,
// now_epoch = now_slot / SLOTS_PER_EPOCH and skew = ClockSkewSlots:
//
//	BLOCK_V2                               slot              ≤ now_slot + skew
//	ATTESTATION                            target.epoch      ≤ now_epoch + 1
//	AGGREGATION_SLOT                       slot              ≤ now_slot + skew
//	AGGREGATE_AND_PROOF                    aggregate.data.slot ≤ now_slot + skew
//	VOLUNTARY_EXIT                         epoch             ≤ now_epoch + 1
//	SYNC_COMMITTEE_MESSAGE                 slot              ≤ now_slot + skew
//	SYNC_COMMITTEE_SELECTION_PROOF         slot              ≤ now_slot + skew
//	SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF  contribution.slot ≤ now_slot + skew
//	VALIDATOR_REGISTRATION                 timestamp         ≤ unix_now + SECONDS_PER_SLOT
//
// Every bound is off while the genesis time is unknown, as the contract
// states; the server then refuses to start on a non-loopback listener unless
// told otherwise. Before genesis now_slot is negative and floors towards
// minus infinity.

// ClockBoundsActive reports whether the bounds apply, which needs the
// genesis time.
func (p *Policy) ClockBoundsActive() bool { return p.genesisKnown }

// checkClock is step 7.
func (p *Policy) checkClock(req *types.SignRequest) error {
	if !p.genesisKnown {
		return nil
	}
	now := p.now()
	ok := true
	if reg, isReg := req.Payload.(*types.ValidatorRegistrationV1); isReg {
		ok = signedTime{mag: unixNow(now)}.allows(reg.Timestamp, p.cfg.SecondsPerSlot)
	} else {
		slot := p.nowSlot(now)
		bySlot := func(s uint64) bool { return slot.allows(s, p.skew) }
		byEpoch := func(e uint64) bool { return slot.div(p.cfg.SlotsPerEpoch).allows(e, 1) }
		switch pl := req.Payload.(type) {
		case *types.BlockV2:
			ok = bySlot(pl.Header.Slot)
		case *types.AttestationData:
			ok = byEpoch(pl.Target.Epoch)
		case *types.AggregationSlot:
			ok = bySlot(pl.Slot)
		case *types.AggregateAttestationAndProof:
			ok = bySlot(pl.Aggregate.Data.Slot)
		case *types.VoluntaryExit:
			ok = byEpoch(pl.Epoch)
		case *types.SyncCommitteeMessage:
			ok = bySlot(pl.Slot)
		case *types.SyncAggregatorSelectionData:
			ok = bySlot(pl.Slot)
		case *types.ContributionAndProof:
			ok = bySlot(pl.Contribution.Slot)
		}
	}
	if !ok {
		return apierr.New(apierr.ClockBound, "request is ahead of the wall clock")
	}
	return nil
}

// signedTime is a slot or epoch that may lie before genesis: the value mag,
// negated when neg.
type signedTime struct {
	mag uint64
	neg bool
}

// unixNow returns the Unix time of now, clamped to zero.
func unixNow(now time.Time) uint64 {
	return uint64(max(now.Unix(), 0))
}

// nowSlot returns now_slot.
func (p *Policy) nowSlot(now time.Time) signedTime {
	t, sps := unixNow(now), p.cfg.SecondsPerSlot
	if t >= p.genesisTime {
		return signedTime{mag: (t - p.genesisTime) / sps}
	}
	return signedTime{mag: ceilDiv(p.genesisTime-t, sps), neg: true}
}

// div is floor division by n > 0.
func (s signedTime) div(n uint64) signedTime {
	if !s.neg {
		return signedTime{mag: s.mag / n}
	}
	return signedTime{mag: ceilDiv(s.mag, n), neg: true}
}

// allows reports whether v ≤ s + delta, without overflow.
func (s signedTime) allows(v, delta uint64) bool {
	if !s.neg {
		limit, carry := bits.Add64(s.mag, delta, 0)
		return carry != 0 || v <= limit
	}
	return delta >= s.mag && v <= delta-s.mag
}

func ceilDiv(a, b uint64) uint64 { return a/b + min(a%b, 1) }
