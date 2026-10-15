// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package policy decides whether a decoded sign request may proceed to key
// lookup, slashing protection and signing. It runs steps 3 to 7 of the
// validation pipeline (docs/contract.md section 7), in this order:
//
//  3. type allowlist and policy: exits are off unless enabled, and a
//     registration's fee recipient must match the key's pin
//     (403 ARTIFACT_TYPE_DISABLED);
//  4. semantic invariants (400 INVARIANT_VIOLATION, PUBKEY_MISMATCH);
//  5. the signing root, recomputed from the signer's own network and
//     compared with the client's (400 SIGNING_ROOT_MISMATCH);
//  6. the network binding of fork_info (400 FORK_INFO_MISMATCH);
//  7. the wall-clock bound (412 CLOCK_BOUND).
//
// It also says which types slashing protection covers. Refusals are
// *apierr.Error values.
package policy

import (
	"errors"
	"math/bits"
	"sync/atomic"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/signingroot"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/types"
	"github.com/rgeraldes24/go-remotesigner/internal/network"
)

// DefaultClockSkewSlots is the default of --signing-clock-skew-slots.
const DefaultClockSkewSlots = 1

// Config configures a Policy.
type Config struct {
	// Network is the chain the signer is bound to.
	Network *network.Network
	// ClockSkewSlots is --signing-clock-skew-slots.
	ClockSkewSlots uint64
	// VoluntaryExitsEnabled is --voluntary-exit-signing-enabled.
	VoluntaryExitsEnabled bool
	// FeeRecipients holds the pins of --registration-fee-recipient-file, or
	// is nil when the flag is unset.
	FeeRecipients *FeeRecipientPins
	// Now is the wall clock; nil means time.Now.
	Now func() time.Time
}

// Protection says which slashing rule covers a request.
type Protection uint8

const (
	// ProtectionNone: no slashing rule applies.
	ProtectionNone Protection = iota
	// ProtectionBlock: the block rule on Decision.Slot.
	ProtectionBlock
	// ProtectionAttestation: the attestation rules on Decision.SourceEpoch
	// and Decision.TargetEpoch.
	ProtectionAttestation
)

// ProtectionFor returns the slashing rule that covers type t: blocks and
// attestations only.
func ProtectionFor(t signingroot.ArtifactType) Protection {
	switch t {
	case signingroot.BlockV2:
		return ProtectionBlock
	case signingroot.Attestation:
		return ProtectionAttestation
	default:
		return ProtectionNone
	}
}

// Decision is the outcome of an accepted request.
type Decision struct {
	Type        signingroot.ArtifactType
	SigningRoot [32]byte
	// GenesisValidatorsRoot is the GVR the domain was computed with: the
	// bound one, or the request's while a trust-on-first-use pin is pending.
	// It is zero for VALIDATOR_REGISTRATION, whose domain uses no GVR.
	GenesisValidatorsRoot [32]byte
	// PinGVR is set when the GVR came from the request because no pin
	// exists yet. The caller pins it (store first, then
	// PinGenesisValidatorsRoot) when the request is accepted.
	PinGVR bool

	Protection Protection
	// Slot is the block slot (ProtectionBlock).
	Slot uint64
	// SourceEpoch and TargetEpoch are the attestation's (ProtectionAttestation).
	SourceEpoch, TargetEpoch uint64
}

// Policy checks requests against one network. It is safe for concurrent use.
type Policy struct {
	cfg network.Config
	gvr atomic.Pointer[[32]byte] // nil while a TOFU pin is pending

	genesisTime  uint64
	genesisKnown bool
	skew         uint64
	exits        bool
	pins         *FeeRecipientPins
	now          func() time.Time
}

// Errors returned by New and PinGenesisValidatorsRoot.
var (
	ErrNoNetwork      = errors.New("policy: no network")
	ErrNoGVR          = errors.New("policy: genesis validators root unknown, and trust on first use is allowed only for file networks")
	ErrGVRPinned      = errors.New("policy: a different genesis validators root is already bound")
	ErrInvalidNetwork = errors.New("policy: network has no slot timing or sync committee")
)

// New returns the policy for cfg.
func New(cfg Config) (*Policy, error) {
	n := cfg.Network
	if n == nil {
		return nil, ErrNoNetwork
	}
	c := n.Config
	if c.SlotsPerEpoch == 0 || c.SecondsPerSlot == 0 || c.SyncCommitteeSubnetCount == 0 ||
		c.SyncSubcommitteeSize() == 0 {
		return nil, ErrInvalidNetwork
	}
	if !n.GVRKnown() && !n.TOFUAllowed() {
		return nil, ErrNoGVR
	}
	p := &Policy{
		cfg:          c,
		genesisTime:  n.GenesisTime,
		genesisKnown: n.GenesisTimeKnown(),
		skew:         cfg.ClockSkewSlots,
		exits:        cfg.VoluntaryExitsEnabled,
		pins:         cfg.FeeRecipients,
		now:          cfg.Now,
	}
	if p.now == nil {
		p.now = time.Now
	}
	if n.GVRKnown() {
		gvr := n.GenesisValidatorsRoot
		p.gvr.Store(&gvr)
	}
	return p, nil
}

// Params returns the decoder parameters of the network.
func (p *Policy) Params() types.Params {
	return types.Params{SyncSubcommitteeSize: p.cfg.SyncSubcommitteeSize()}
}

// Enabled reports whether type t may be signed at all.
func (p *Policy) Enabled(t signingroot.ArtifactType) bool {
	if _, known := signingroot.RuleFor(t); !known {
		return false
	}
	return t != signingroot.VoluntaryExit || p.exits
}

// EnabledTypes returns the enabled artifact types in contract order, as
// `capabilities` reports them.
func (p *Policy) EnabledTypes() []signingroot.ArtifactType {
	var out []signingroot.ArtifactType
	for _, t := range types.ArtifactTypes() {
		if p.Enabled(t) {
			out = append(out, t)
		}
	}
	return out
}

// GenesisValidatorsRoot returns the bound GVR, or false while a
// trust-on-first-use pin is pending.
func (p *Policy) GenesisValidatorsRoot() ([32]byte, bool) {
	if g := p.gvr.Load(); g != nil {
		return *g, true
	}
	return [32]byte{}, false
}

// PinGenesisValidatorsRoot binds a trust-on-first-use GVR. It succeeds when
// no GVR is bound or the same one is, and fails with ErrGVRPinned otherwise.
func (p *Policy) PinGenesisValidatorsRoot(gvr [32]byte) error {
	if p.gvr.CompareAndSwap(nil, &gvr) {
		return nil
	}
	if cur, _ := p.GenesisValidatorsRoot(); cur != gvr {
		return ErrGVRPinned
	}
	return nil
}

// CheckForkInfo is step 6 for sign and RANDAO requests: both versions must
// be the network's GENESIS_FORK_VERSION, the fork epoch 0, and the GVR the
// bound one. While a trust-on-first-use pin is pending any GVR passes, and
// pin reports that the caller must pin the returned GVR.
func (p *Policy) CheckForkInfo(fi *types.ForkInfo) (gvr [32]byte, pin bool, err error) {
	want := signingroot.Version(p.cfg.GenesisForkVersion)
	if fi.Fork.PreviousVersion != want || fi.Fork.CurrentVersion != want || fi.Fork.Epoch != 0 {
		return gvr, false, apierr.New(apierr.ForkInfoMismatch, "fork differs from the network's genesis fork")
	}
	bound, ok := p.GenesisValidatorsRoot()
	if !ok {
		return fi.GenesisValidatorsRoot, true, nil
	}
	if fi.GenesisValidatorsRoot != bound {
		return gvr, false, apierr.New(apierr.ForkInfoMismatch, "genesis validators root differs from the network's")
	}
	return bound, false, nil
}

// Check runs steps 3 to 7 on a decoded request for the key whose
// sha256(pubkey) is keyID. Nothing is signed or recorded.
func (p *Policy) Check(req *types.SignRequest, keyID [32]byte) (*Decision, error) {
	t := req.Type()
	if err := p.checkPolicy(req, keyID); err != nil {
		return nil, err
	}
	if err := p.checkInvariants(req, keyID); err != nil {
		return nil, err
	}

	d := &Decision{Type: t, Protection: ProtectionFor(t)}
	var gvr [32]byte
	if req.ForkInfo != nil {
		// Step 5 needs a GVR before step 6 checks it: the bound one, or the
		// request's while a pin is pending.
		var ok bool
		if gvr, ok = p.GenesisValidatorsRoot(); !ok {
			gvr = req.ForkInfo.GenesisValidatorsRoot
		}
	}
	chain, err := signingroot.NewChain(signingroot.Version(p.cfg.GenesisForkVersion), gvr, p.cfg.SlotsPerEpoch)
	if err != nil {
		return nil, err
	}
	if d.SigningRoot, err = req.SigningRootFor(chain); err != nil {
		return nil, apierr.New(apierr.InvariantViolation, "object has no hash-tree-root")
	}
	if req.SigningRoot != nil && *req.SigningRoot != d.SigningRoot {
		return nil, apierr.New(apierr.SigningRootMismatch, "signing_root differs from the recomputed root")
	}

	if req.ForkInfo != nil {
		if d.GenesisValidatorsRoot, d.PinGVR, err = p.CheckForkInfo(req.ForkInfo); err != nil {
			return nil, err
		}
	}

	if err := p.checkClock(req); err != nil {
		return nil, err
	}

	switch pl := req.Payload.(type) {
	case *types.BlockV2:
		d.Slot = pl.Header.Slot
	case *types.AttestationData:
		d.SourceEpoch, d.TargetEpoch = pl.Source.Epoch, pl.Target.Epoch
	}
	return d, nil
}

// checkPolicy is step 3.
func (p *Policy) checkPolicy(req *types.SignRequest, keyID [32]byte) error {
	if !p.Enabled(req.Type()) {
		return apierr.New(apierr.ArtifactTypeDisabled, "artifact type disabled")
	}
	if reg, ok := req.Payload.(*types.ValidatorRegistrationV1); ok && p.pins != nil {
		if pinned, ok := p.pins.Lookup(keyID); ok && pinned != reg.FeeRecipient {
			return apierr.New(apierr.ArtifactTypeDisabled, "fee_recipient differs from the key's pinned address")
		}
	}
	return nil
}

// checkInvariants is step 4.
func (p *Policy) checkInvariants(req *types.SignRequest, keyID [32]byte) error {
	violation := func(detail string) error { return apierr.New(apierr.InvariantViolation, detail) }
	switch pl := req.Payload.(type) {
	case *types.AttestationData:
		if pl.Source.Epoch > pl.Target.Epoch {
			return violation("source epoch after target epoch")
		}
	case *types.AggregateAttestationAndProof:
		a := &pl.Aggregate
		if len(a.Signatures) > types.MaxAttestationSignatures {
			return violation("more than 32 signatures")
		}
		if len(a.Signatures) != onesCount(a.AggregationBits)-1 { // minus the delimiter bit
			return violation("signature count differs from the set aggregation bits")
		}
	case *types.SyncAggregatorSelectionData:
		if pl.SubcommitteeIndex >= p.cfg.SyncCommitteeSubnetCount {
			return violation("subcommittee_index out of range")
		}
	case *types.ContributionAndProof:
		c := &pl.Contribution
		if c.SubcommitteeIndex >= p.cfg.SyncCommitteeSubnetCount {
			return violation("subcommittee_index out of range")
		}
		if len(c.Signatures) < 1 || len(c.Signatures) > types.MaxContributionSignatures {
			return violation("contribution needs 1 to 128 signatures")
		}
		if len(c.Signatures) != onesCount(c.AggregationBits) {
			return violation("signature count differs from the set aggregation bits")
		}
	case *types.ValidatorRegistrationV1:
		if types.KeyID(&pl.Pubkey) != keyID {
			return apierr.New(apierr.PubkeyMismatch, "pubkey is not the identified key")
		}
	}
	return nil
}

func onesCount(b []byte) int {
	n := 0
	for _, c := range b {
		n += bits.OnesCount8(c)
	}
	return n
}
