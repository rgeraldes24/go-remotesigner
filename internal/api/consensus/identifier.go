// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package consensus holds the handlers of the /api/v1/consensus/ routes.
package consensus

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
)

// Identifier lengths, "0x" included (docs/contract.md section 3).
const (
	CanonicalIdentifierLength = 2 + 2*mldsa87.PublicKeySize // a public key
	ShortIdentifierLength     = 2 + 2*sha256.Size           // sha256 of a public key
)

// ParseIdentifier returns the key id (sha256 of the public key) that an
// {identifier} path segment names. Its length, prefix and characters are
// checked before anything is decoded, so a malformed identifier of any size
// costs one length comparison; it is refused with 400 BAD_IDENTIFIER.
func ParseIdentifier(s string) ([sha256.Size]byte, *apierr.Error) {
	var id [sha256.Size]byte
	if len(s) != CanonicalIdentifierLength && len(s) != ShortIdentifierLength {
		return id, apierr.New(apierr.BadIdentifier, "identifier has neither the canonical nor the short length")
	}
	if s[0] != '0' || s[1] != 'x' {
		return id, apierr.New(apierr.BadIdentifier, "identifier lacks the 0x prefix")
	}
	h := s[2:]
	for i := 0; i < len(h); i++ {
		if !isHex(h[i]) {
			return id, apierr.New(apierr.BadIdentifier, "identifier is not hex")
		}
	}
	if len(s) == ShortIdentifierLength {
		_, _ = hex.Decode(id[:], []byte(h))
		return id, nil
	}
	var pk [mldsa87.PublicKeySize]byte
	_, _ = hex.Decode(pk[:], []byte(h))
	return sha256.Sum256(pk[:]), nil
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}
