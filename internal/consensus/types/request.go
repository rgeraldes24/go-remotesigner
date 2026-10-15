// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"crypto/sha256"
	"errors"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
	"github.com/rgeraldes24/go-remotesigner/internal/api/jsonutil"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/signingroot"
)

// Params are the network values the strict decoder needs.
type Params struct {
	// SyncSubcommitteeSize is the bit length of
	// SyncCommitteeContribution.aggregation_bits: SYNC_COMMITTEE_SIZE /
	// SYNC_COMMITTEE_SUBNET_COUNT, 16 on minimal presets and 128 on mainnet.
	SyncSubcommitteeSize uint64
}

// ErrParams is returned when Params cannot decode a request. It is a
// configuration error, not a client error.
var ErrParams = errors.New("types: Params.SyncSubcommitteeSize must be positive")

// KeyID returns sha256(pubkey), by which keys are identified and looked up.
func KeyID(pubkey *Pubkey) [32]byte {
	return sha256.Sum256(pubkey[:])
}

// Payload is the artifact-specific object of a sign request: one of
// *BlockV2, *AttestationData, *AggregationSlot,
// *AggregateAttestationAndProof, *VoluntaryExit, *SyncCommitteeMessage,
// *SyncAggregatorSelectionData, *ContributionAndProof and
// *ValidatorRegistrationV1.
type Payload interface {
	// ArtifactType is the request's `type`.
	ArtifactType() signingroot.ArtifactType
	// ObjectRoot returns the hash-tree-root of the object that is signed.
	ObjectRoot() ([32]byte, error)
	// DomainAt returns the slot or epoch from which the type's rule
	// (signingroot.RuleFor) selects the fork version. It is zero for
	// VALIDATOR_REGISTRATION, whose rule reads none.
	DomainAt() uint64

	fields(*Params) []jsonutil.Field
}

// BlockV2 is the payload of BLOCK_V2: `{"version": "ZOND", "block_header":
// {…}}`. Only the header is sent; its root equals the root of the full and
// of the blinded Zond block, so one shape covers both.
type BlockV2 struct {
	Header BeaconBlockHeader
}

func (*BlockV2) ArtifactType() signingroot.ArtifactType { return signingroot.BlockV2 }
func (b *BlockV2) ObjectRoot() ([32]byte, error)        { return b.Header.HashTreeRoot() }
func (b *BlockV2) DomainAt() uint64                     { return b.Header.Slot }
func (b *BlockV2) fields(*Params) []jsonutil.Field {
	return []jsonutil.Field{
		{Name: "version", Value: zondVersion{}},
		{Name: "block_header", Value: object(b.Header.fields())},
	}
}

// AggregationSlot is the payload of AGGREGATION_SLOT, the aggregation
// selection proof. The signed object is the slot as an SSZ uint64.
type AggregationSlot struct {
	Slot uint64
}

func (*AggregationSlot) ArtifactType() signingroot.ArtifactType { return signingroot.AggregationSlot }
func (a *AggregationSlot) ObjectRoot() ([32]byte, error)        { return Uint64(a.Slot).HashTreeRoot() }
func (a *AggregationSlot) DomainAt() uint64                     { return a.Slot }
func (a *AggregationSlot) fields(*Params) []jsonutil.Field {
	return []jsonutil.Field{{Name: "slot", Value: u64(&a.Slot)}}
}

// SyncCommitteeMessage is the payload of SYNC_COMMITTEE_MESSAGE. The signed
// object is the block root itself; the slot only selects the fork version.
type SyncCommitteeMessage struct {
	BeaconBlockRoot [32]byte
	Slot            uint64
}

func (*SyncCommitteeMessage) ArtifactType() signingroot.ArtifactType {
	return signingroot.SyncCommitteeMessage
}
func (m *SyncCommitteeMessage) ObjectRoot() ([32]byte, error) {
	return Bytes32(m.BeaconBlockRoot).HashTreeRoot()
}
func (m *SyncCommitteeMessage) DomainAt() uint64 { return m.Slot }
func (m *SyncCommitteeMessage) fields(*Params) []jsonutil.Field {
	return []jsonutil.Field{
		{Name: "beacon_block_root", Value: jsonutil.HexBytesN(m.BeaconBlockRoot[:])},
		{Name: "slot", Value: u64(&m.Slot)},
	}
}

// The containers that are payloads as they are.

func (AttestationData) ArtifactType() signingroot.ArtifactType { return signingroot.Attestation }
func (d AttestationData) ObjectRoot() ([32]byte, error)        { return d.HashTreeRoot() }
func (d AttestationData) DomainAt() uint64                     { return d.Target.Epoch }

func (*AggregateAttestationAndProof) ArtifactType() signingroot.ArtifactType {
	return signingroot.AggregateAndProof
}
func (p *AggregateAttestationAndProof) ObjectRoot() ([32]byte, error) { return p.HashTreeRoot() }
func (p *AggregateAttestationAndProof) DomainAt() uint64              { return p.Aggregate.Data.Slot }

func (VoluntaryExit) ArtifactType() signingroot.ArtifactType { return signingroot.VoluntaryExit }
func (e VoluntaryExit) ObjectRoot() ([32]byte, error)        { return e.HashTreeRoot() }
func (e VoluntaryExit) DomainAt() uint64                     { return e.Epoch }

func (SyncAggregatorSelectionData) ArtifactType() signingroot.ArtifactType {
	return signingroot.SyncCommitteeSelectionProof
}
func (s SyncAggregatorSelectionData) ObjectRoot() ([32]byte, error) { return s.HashTreeRoot() }
func (s SyncAggregatorSelectionData) DomainAt() uint64              { return s.Slot }

func (*ContributionAndProof) ArtifactType() signingroot.ArtifactType {
	return signingroot.SyncCommitteeContributionAndProof
}
func (p *ContributionAndProof) ObjectRoot() ([32]byte, error) { return p.HashTreeRoot() }
func (p *ContributionAndProof) DomainAt() uint64              { return p.Contribution.Slot }

func (*ValidatorRegistrationV1) ArtifactType() signingroot.ArtifactType {
	return signingroot.ValidatorRegistration
}
func (r *ValidatorRegistrationV1) ObjectRoot() ([32]byte, error) { return r.HashTreeRoot() }
func (*ValidatorRegistrationV1) DomainAt() uint64                { return 0 }

// payloadSpec ties an artifact type to its payload key and payload type.
type payloadSpec struct {
	typ signingroot.ArtifactType
	key string
	new func() Payload
}

// payloadSpecs lists the nine artifact types in contract order.
var payloadSpecs = []payloadSpec{
	{signingroot.BlockV2, "beacon_block", func() Payload { return new(BlockV2) }},
	{signingroot.Attestation, "attestation", func() Payload { return new(AttestationData) }},
	{signingroot.AggregationSlot, "aggregation_slot", func() Payload { return new(AggregationSlot) }},
	{signingroot.AggregateAndProof, "aggregate_and_proof", func() Payload { return new(AggregateAttestationAndProof) }},
	{signingroot.VoluntaryExit, "voluntary_exit", func() Payload { return new(VoluntaryExit) }},
	{signingroot.SyncCommitteeMessage, "sync_committee_message", func() Payload { return new(SyncCommitteeMessage) }},
	{signingroot.SyncCommitteeSelectionProof, "sync_aggregator_selection_data",
		func() Payload { return new(SyncAggregatorSelectionData) }},
	{signingroot.SyncCommitteeContributionAndProof, "contribution_and_proof",
		func() Payload { return new(ContributionAndProof) }},
	{signingroot.ValidatorRegistration, "validator_registration",
		func() Payload { return new(ValidatorRegistrationV1) }},
}

func specFor(t signingroot.ArtifactType) (int, bool) {
	for i := range payloadSpecs {
		if payloadSpecs[i].typ == t {
			return i, true
		}
	}
	return 0, false
}

// ArtifactTypes returns the nine artifact types in contract order.
func ArtifactTypes() []signingroot.ArtifactType {
	out := make([]signingroot.ArtifactType, len(payloadSpecs))
	for i := range payloadSpecs {
		out[i] = payloadSpecs[i].typ
	}
	return out
}

// ForkInfo is the request's `fork_info`. The signer never computes a domain
// from it; the policy only checks that it names the signer's own network.
type ForkInfo struct {
	Fork                  signingroot.Fork
	GenesisValidatorsRoot [32]byte
}

func (f *ForkInfo) fields() []jsonutil.Field {
	fork := object{
		{Name: "previous_version", Value: jsonutil.HexBytesN(f.Fork.PreviousVersion[:])},
		{Name: "current_version", Value: jsonutil.HexBytesN(f.Fork.CurrentVersion[:])},
		{Name: "epoch", Value: u64(&f.Fork.Epoch)},
	}
	return []jsonutil.Field{
		{Name: "fork", Value: fork},
		{Name: "genesis_validators_root", Value: jsonutil.HexBytesN(f.GenesisValidatorsRoot[:])},
	}
}

// decodeForkInfo decodes a present `fork_info` value.
func decodeForkInfo(raw []byte) (*ForkInfo, error) {
	fi := new(ForkInfo)
	if err := object(fi.fields()).UnmarshalJSON(raw); err != nil {
		return nil, in(err, "fork_info")
	}
	return fi, nil
}

// SignRequest is a decoded body of POST /api/v1/consensus/sign/{identifier}.
type SignRequest struct {
	// ForkInfo is nil exactly for VALIDATOR_REGISTRATION.
	ForkInfo *ForkInfo
	// SigningRoot is the optional root the client computed, from
	// `signing_root` or its alias `signingRoot`.
	SigningRoot *[32]byte
	Payload     Payload
}

// Type returns the artifact type.
func (r *SignRequest) Type() signingroot.ArtifactType { return r.Payload.ArtifactType() }

// SigningRootFor computes the signing root of the request on chain c: the
// object root of the payload, with the domain that the type's rule selects
// from c (never from ForkInfo).
func (r *SignRequest) SigningRootFor(c signingroot.Chain) ([32]byte, error) {
	root, err := r.Payload.ObjectRoot()
	if err != nil {
		return [32]byte{}, err
	}
	return c.SigningRoot(r.Type(), root, r.Payload.DomainAt())
}

// DecodeSignRequest strictly decodes a sign request body (docs/contract.md
// sections 4, 7 and 8). Every client error is an *apierr.Error:
//
//   - MALFORMED_JSON: invalid JSON, a duplicate key, or both signing_root
//     and signingRoot;
//   - UNKNOWN_FIELD: a key the type's schema does not define, at any level,
//     including another type's payload key and fork_info on a registration;
//   - UNKNOWN_TYPE: a `type` that is not one of the nine, compared exactly;
//   - MISSING_FORK_INFO: no fork_info on a type that needs it;
//   - BAD_FIELD: a missing field or a value of the wrong type, form or
//     length, including a contribution bitvector of the wrong preset.
//
// The returned request aliases nothing in body.
func DecodeSignRequest(body []byte, p Params) (*SignRequest, error) {
	if p.SyncSubcommitteeSize == 0 {
		return nil, ErrParams
	}
	if err := jsonutil.Validate(body); err != nil {
		return nil, err
	}
	var typ, forkInfo, root, rootAlias jsonutil.RawValue
	raw := make([]jsonutil.RawValue, len(payloadSpecs))
	fields := make([]jsonutil.Field, 0, 4+len(payloadSpecs))
	fields = append(fields,
		jsonutil.Field{Name: "type", Value: &typ, Optional: true},
		jsonutil.Field{Name: "fork_info", Value: &forkInfo, Optional: true},
		jsonutil.Field{Name: "signing_root", Value: &root, Optional: true},
		jsonutil.Field{Name: "signingRoot", Value: &rootAlias, Optional: true},
	)
	for i := range payloadSpecs {
		fields = append(fields, jsonutil.Field{Name: payloadSpecs[i].key, Value: &raw[i], Optional: true})
	}
	if err := jsonutil.DecodeObject(body, fields...); err != nil {
		return nil, err
	}

	if typ == nil {
		return nil, apierr.New(apierr.BadField, "missing field").In("type")
	}
	var t jsonutil.String
	if err := t.UnmarshalJSON(typ); err != nil {
		return nil, in(err, "type")
	}
	k, ok := specFor(signingroot.ArtifactType(t))
	if !ok {
		return nil, apierr.New(apierr.UnknownType, "unknown artifact type").In("type")
	}
	spec := payloadSpecs[k]
	for i := range payloadSpecs {
		if i != k && raw[i] != nil {
			return nil, apierr.New(apierr.UnknownField, "payload key of another type").In(payloadSpecs[i].key)
		}
	}
	switch {
	case spec.typ == signingroot.ValidatorRegistration && forkInfo != nil:
		return nil, apierr.New(apierr.UnknownField, "registrations carry no fork_info").In("fork_info")
	case spec.typ != signingroot.ValidatorRegistration && forkInfo == nil:
		return nil, apierr.New(apierr.MissingForkInfo, "fork_info is required")
	case root != nil && rootAlias != nil:
		return nil, apierr.New(apierr.MalformedJSON, "both signing_root and signingRoot")
	}

	req := new(SignRequest)
	if root != nil || rootAlias != nil {
		name, v := "signing_root", root
		if rootAlias != nil {
			name, v = "signingRoot", rootAlias
		}
		req.SigningRoot = new([32]byte)
		if err := jsonutil.HexBytesN(req.SigningRoot[:]).UnmarshalJSON(v); err != nil {
			return nil, in(err, name)
		}
	}
	if forkInfo != nil {
		fi, err := decodeForkInfo(forkInfo)
		if err != nil {
			return nil, err
		}
		req.ForkInfo = fi
	}
	if raw[k] == nil {
		return nil, apierr.New(apierr.BadField, "missing field").In(spec.key)
	}
	req.Payload = spec.new()
	if err := object(req.Payload.fields(&p)).UnmarshalJSON(raw[k]); err != nil {
		return nil, in(err, spec.key)
	}
	return req, nil
}

// MarshalJSON writes the canonical body: type, fork_info, signing_root and
// the payload, with lowercase hex.
func (r SignRequest) MarshalJSON() ([]byte, error) {
	if r.Payload == nil {
		return nil, errors.New("types: sign request has no payload")
	}
	k, ok := specFor(r.Payload.ArtifactType())
	if !ok {
		return nil, errors.New("types: unknown payload type")
	}
	typ := jsonutil.String(payloadSpecs[k].typ)
	fields := []jsonutil.Field{{Name: "type", Value: &typ}}
	if r.ForkInfo != nil {
		fields = append(fields, jsonutil.Field{Name: "fork_info", Value: object(r.ForkInfo.fields())})
	}
	if r.SigningRoot != nil {
		fields = append(fields, jsonutil.Field{Name: "signing_root", Value: jsonutil.HexBytesN(r.SigningRoot[:])})
	}
	fields = append(fields, jsonutil.Field{Name: payloadSpecs[k].key, Value: object(r.Payload.fields(nil))})
	return jsonutil.EncodeObject(fields...)
}

// in adds a path segment to a decoding error.
func in(err error, segment string) error {
	var e *apierr.Error
	if errors.As(err, &e) {
		return e.In(segment)
	}
	return err
}
