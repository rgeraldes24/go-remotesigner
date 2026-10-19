// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package execution

import (
	"context"
	"sync"
)

// senderLocks holds one lock per sending account, which qrl_sendTransaction
// holds across fill, sign and send, so that two calls for one account never
// take the same nonce from the node. Waiting for a lock ends with the
// request's context. Only loaded accounts are locked, so the map is bounded
// by the accounts ever loaded.
type senderLocks struct {
	mu    sync.Mutex
	locks map[Address]chan struct{}
}

// lock takes from's lock, or returns ctx's error once ctx ends first. The
// returned function releases it.
func (s *senderLocks) lock(ctx context.Context, from Address) (func(), error) {
	s.mu.Lock()
	if s.locks == nil {
		s.locks = map[Address]chan struct{}{}
	}
	c, ok := s.locks[from]
	if !ok {
		c = make(chan struct{}, 1)
		s.locks[from] = c
	}
	s.mu.Unlock()
	select {
	case c <- struct{}{}:
		return func() { <-c }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
