// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/rgeraldes24/go-remotesigner/internal/api/jsonutil"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/types"
)

// FeeRecipientPins are the per-key fee recipients of
// --registration-fee-recipient-file (docs/reference/registration-fee-recipient-file.md).
// A VALIDATOR_REGISTRATION for a pinned key is refused unless its
// fee_recipient is the pinned address; keys without a pin are not
// restricted.
type FeeRecipientPins struct {
	byKey map[[32]byte]types.Address
}

// ErrPinFile reports a fee-recipient file that cannot be used.
var ErrPinFile = errors.New("policy: invalid fee-recipient file")

// LoadFeeRecipientPins reads and parses a fee-recipient file.
func LoadFeeRecipientPins(path string) (*FeeRecipientPins, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: read fee-recipient file: %w", err)
	}
	pins, err := ParseFeeRecipientPins(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return pins, nil
}

// ParseFeeRecipientPins parses a fee-recipient file: a YAML list (JSON is
// accepted as YAML) of entries with exactly two keys, `key` and
// `fee_recipient`:
//
//   - key: 0x6a0520f46e95a03d3957eb79b5756ac5c57a29c57c4344c0ba4c2b19dd6fa73c
//     fee_recipient: Q2b3f5c7d…
//
// `key` is a key identifier as in API paths: the sha256 alias (0x + 64 hex)
// or the canonical public key (0x + 5,184 hex). A list is used rather than a
// mapping because YAML limits mapping keys to 1,024 characters. A key may
// appear once, in either form. An empty list is refused, because it would
// pin nothing.
func ParseFeeRecipientPins(data []byte) (*FeeRecipientPins, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%w: not YAML: %v", ErrPinFile, err)
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("%w: want a list of {key, fee_recipient} entries", ErrPinFile)
	}
	entries := doc.Content[0].Content
	if len(entries) == 0 {
		return nil, fmt.Errorf("%w: no entries", ErrPinFile)
	}
	pins := &FeeRecipientPins{byKey: make(map[[32]byte]types.Address, len(entries))}
	for _, e := range entries {
		id, addr, err := parsePinEntry(e)
		if err != nil {
			return nil, fmt.Errorf("%w: line %d: %v", ErrPinFile, e.Line, err)
		}
		if _, dup := pins.byKey[id]; dup {
			return nil, fmt.Errorf("%w: line %d: key pinned twice", ErrPinFile, e.Line)
		}
		pins.byKey[id] = addr
	}
	return pins, nil
}

// parsePinEntry parses one {key, fee_recipient} mapping.
func parsePinEntry(e *yaml.Node) (id [32]byte, addr types.Address, err error) {
	if e.Kind != yaml.MappingNode {
		return id, addr, errors.New("entry must be a mapping with key and fee_recipient")
	}
	var key, fee *yaml.Node
	for i := 0; i+1 < len(e.Content); i += 2 {
		k, v := e.Content[i], e.Content[i+1]
		if v.Kind != yaml.ScalarNode {
			return id, addr, errors.New("values must be strings")
		}
		switch {
		case k.Value == "key" && key == nil:
			key = v
		case k.Value == "fee_recipient" && fee == nil:
			fee = v
		default:
			return id, addr, errors.New("entries have exactly the keys key and fee_recipient")
		}
	}
	if key == nil || fee == nil {
		return id, addr, errors.New("entries need both key and fee_recipient")
	}
	if id, err = parseKeyIdentifier(key.Value); err != nil {
		return id, addr, err
	}
	a, err := jsonutil.ParseQAddress(fee.Value)
	if err != nil {
		return id, addr, fmt.Errorf("fee_recipient: %v", err)
	}
	return id, types.Address(a), nil
}

// Lookup returns the pin of the key whose sha256(pubkey) is keyID.
func (p *FeeRecipientPins) Lookup(keyID [32]byte) (types.Address, bool) {
	a, ok := p.byKey[keyID]
	return a, ok
}

// Len returns the number of pinned keys.
func (p *FeeRecipientPins) Len() int { return len(p.byKey) }

// parseKeyIdentifier returns sha256(pubkey) for either identifier form.
func parseKeyIdentifier(s string) ([32]byte, error) {
	var id [32]byte
	h, ok := strings.CutPrefix(s, "0x")
	if !ok {
		return id, errors.New("key identifier needs a 0x prefix")
	}
	switch len(h) {
	case 2 * len(id):
		if _, err := hex.Decode(id[:], []byte(h)); err != nil {
			return id, errors.New("key identifier is not hex")
		}
		return id, nil
	case 2 * types.PubkeyLength:
		var pk types.Pubkey
		if _, err := hex.Decode(pk[:], []byte(h)); err != nil {
			return id, errors.New("key identifier is not hex")
		}
		return sha256.Sum256(pk[:]), nil
	default:
		return id, errors.New("key identifier must be a 2,592-byte public key or its sha256")
	}
}
