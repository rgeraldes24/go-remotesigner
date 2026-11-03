// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package slashing

import "context"

// RandaoState is a validator's RANDAO hash-onion frontier: the deepest layer this signer has released. It is the
// only RANDAO data a store keeps; the seed and any precomputed future layer are never stored.
type RandaoState struct {
	// Index is m, the deepest released index counted from x_0.
	Index uint64
	// Reveal is R = x_m, the value released at Index.
	Reveal Root
	// LastSlot is the slot of the last release that moved the frontier.
	LastSlot uint64
}

// RandaoStore persists RANDAO frontiers, one per registered validator, under the store's pinned genesis validators
// root. Every method returns ErrValidatorNotRegistered for an unregistered key.
type RandaoStore interface {
	// RandaoState returns the validator's frontier, if one is stored.
	RandaoState(ctx context.Context, id KeyID) (RandaoState, bool, error)
	// CompareAndSwapRandaoState stores next only if the validator is enabled and the stored frontier equals old,
	// where a nil old means that no frontier is stored. It reports whether it stored next; when it did, next is
	// durable before it returns. For a disabled validator it stores nothing and returns ErrValidatorDisabled. It
	// reads the enabled flag in the transaction that writes the frontier, serialised with every disable
	// (SetValidatorEnabled, or UpdateHistory's SetEnabled and DisableForImport): a disable that has returned is seen,
	// one still open is waited for, and one that starts after the read waits for the commit. bbolt and the memory
	// store hold the validator's RANDAO lock in every disable; Postgres reads the validators row FOR SHARE, which
	// conflicts with the update of that row every disable makes, so each waits for the other's transaction to end.
	CompareAndSwapRandaoState(ctx context.Context, id KeyID, old *RandaoState, next RandaoState) (bool, error)
	// DeleteRandaoState removes the validator's frontier (an operator reset). Deleting an absent frontier is not an
	// error.
	DeleteRandaoState(ctx context.Context, id KeyID) error
}
