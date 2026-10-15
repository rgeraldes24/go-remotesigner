// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package signer turns an accepted request into a released signature: it
// picks the signing mode by artifact type, signs under the key's own mutex,
// verifies the signature before it is released, and quarantines a key whose
// signature fails verification (docs/contract.md sections 7 and 15).
//
// A quarantined key refuses to sign until the next key load gives it a
// fresh copy (see Release); the faulty bytes are wiped and never returned.
package signer

import (
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/consensus/signingroot"
	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/metrics"
)

// ID is a key id: SHA-256 of the public key.
type ID = [mldsa87.IDSize]byte

// Signature is a packed ML-DSA-87 signature.
type Signature = [mldsa87.SignatureSize]byte

// Key is a loaded key as the signing path uses it. *mldsa87.Key implements
// it; Sign must serialise signing on the key and return mldsa87.ErrZeroized
// once the key has been removed.
type Key interface {
	PublicKey() mldsa87.PublicKey
	Sign(message []byte, mode mldsa87.Mode) (Signature, error)
}

// Errors returned by Lookup and Sign.
var (
	// ErrUnknownKey: no key is loaded under the id, or it was removed while
	// the request ran (404 UNKNOWN_KEY).
	ErrUnknownKey = errors.New("signer: key not loaded")
	// ErrQuarantined: the key is quarantined (503 KEY_QUARANTINED).
	ErrQuarantined = errors.New("signer: key quarantined")
	// ErrSignatureFault: the signature failed verification; it was
	// discarded and the key quarantined (500 SIGNATURE_FAULT).
	ErrSignatureFault = errors.New("signer: signature failed verification")
)

// Config configures a Signer.
type Config struct {
	// Lookup returns the loaded key with an id.
	Lookup func(ID) (Key, bool)
	// SelectionProofMode is the mode of the two selection proofs
	// (--selection-proof-signing); every other type is hedged.
	SelectionProofMode mldsa87.Mode
	// Metrics receives the verify failures, quarantine size and signing
	// durations.
	Metrics *metrics.Metrics
	Log     logrus.FieldLogger
}

// Signer signs accepted requests. It is safe for concurrent use.
type Signer struct {
	lookup    func(ID) (Key, bool)
	selection mldsa87.Mode
	m         *metrics.Metrics
	log       logrus.FieldLogger

	mu          sync.Mutex
	quarantined map[ID]Key // the key object whose signature failed
}

// New returns a Signer.
func New(cfg Config) *Signer {
	if cfg.Log == nil {
		cfg.Log = logrus.New()
	}
	return &Signer{
		lookup:      cfg.Lookup,
		selection:   cfg.SelectionProofMode,
		m:           cfg.Metrics,
		log:         cfg.Log,
		quarantined: map[ID]Key{},
	}
}

// ModeFor is the mode table: the selection proofs (AGGREGATION_SLOT and
// SYNC_COMMITTEE_SELECTION_PROOF) use the configured selection-proof mode,
// deterministic by default; every other type is hedged. Deterministic
// signing is safe here only because every signature is verified before
// release, signing is serialised per key, and the startup self-test has
// passed.
func (s *Signer) ModeFor(t signingroot.ArtifactType) mldsa87.Mode {
	switch t {
	case signingroot.AggregationSlot, signingroot.SyncCommitteeSelectionProof:
		return s.selection
	default:
		return mldsa87.Hedged
	}
}

// Lookup returns the key with id, or ErrUnknownKey or ErrQuarantined.
func (s *Signer) Lookup(id ID) (Key, error) {
	k, ok := s.lookup(id)
	if !ok {
		return nil, ErrUnknownKey
	}
	if s.isQuarantined(id) {
		return nil, ErrQuarantined
	}
	return k, nil
}

// Sign signs root with k, the key with id, in the mode of type t, and
// verifies the signature against the key's public key before returning
// it. A signature that does not verify is wiped, the key is quarantined and
// ErrSignatureFault is returned. A key removed while the request ran gives
// ErrUnknownKey.
func (s *Signer) Sign(id ID, k Key, t signingroot.ArtifactType, root [32]byte) (Signature, error) {
	if s.isQuarantined(id) {
		return Signature{}, ErrQuarantined
	}
	start := time.Now()
	sig, err := k.Sign(root[:], s.ModeFor(t))
	if errors.Is(err, mldsa87.ErrZeroized) {
		return Signature{}, ErrUnknownKey
	}
	if err != nil {
		return Signature{}, err
	}
	pk := k.PublicKey()
	if !mldsa87.Verify(&pk, root[:], sig[:]) {
		clear(sig[:])
		s.quarantine(id, k)
		s.log.WithFields(logrus.Fields{"key": pk.LogID(), "type": t}).
			Error("A signature failed verification: it was discarded and the key is quarantined until the next reload")
		return Signature{}, ErrSignatureFault
	}
	if s.m != nil {
		s.m.SigningDuration.WithLabelValues(string(t)).Observe(time.Since(start).Seconds())
	}
	return sig, nil
}

// Quarantined reports whether the key with id is quarantined.
func (s *Signer) Quarantined(id ID) bool { return s.isQuarantined(id) }

// Release lifts the quarantine of every key that the provider no longer
// holds as the faulty object: one that a key load replaced with a freshly
// derived copy, or removed. The runner calls it after each key load. It
// returns the number of keys still quarantined.
func (s *Signer) Release() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, faulty := range s.quarantined {
		if cur, ok := s.lookup(id); !ok || cur != faulty {
			delete(s.quarantined, id)
			s.log.WithField("key-id", shortID(id)).Info("Quarantine lifted: the key was reloaded")
		}
	}
	s.setGauge()
	return len(s.quarantined)
}

func (s *Signer) isQuarantined(id ID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, q := s.quarantined[id]
	return q
}

func (s *Signer) quarantine(id ID, k Key) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.quarantined[id] = k
	if s.m != nil {
		s.m.VerifyFailures.Inc()
	}
	s.setGauge()
}

// setGauge needs s.mu.
func (s *Signer) setGauge() {
	if s.m != nil {
		s.m.KeysQuarantined.Set(float64(len(s.quarantined)))
	}
}

// shortID is the log form of a key id alone: 0x and its first 8 hex
// characters.
func shortID(id ID) string { return "0x" + hex.EncodeToString(id[:4]) }
