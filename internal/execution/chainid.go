// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package execution

import (
	"context"
	"errors"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// ChainCheckInterval is how often the signer compares --chain-id with the
// node's qrl_chainId after the check at startup.
const ChainCheckInterval = 10 * time.Minute

// ChainRetryInterval is how often the signer asks again while the node has
// not answered qrl_chainId once: until then the check has no verdict, and
// a node that was down at startup is compared as soon as it answers, not
// ChainCheckInterval later.
const ChainRetryInterval = 15 * time.Second

// Chain-check verdicts.
const (
	chainUnchecked int32 = iota // no answer from the node yet
	chainMatches
	chainDiffers
)

// chainMonitor compares --chain-id with the chain ID of the node and keeps
// the verdict of the last answer. While the node's chain ID differs, the
// signer refuses to sign transactions. A check the node does not answer
// keeps the previous verdict.
type chainMonitor struct {
	want  *big.Int
	proxy *proxy
	log   logrus.FieldLogger

	verdict atomic.Int32
	mu      sync.Mutex
	got     *big.Int // the node's chain ID at the last answer
}

func newChainMonitor(want *big.Int, p *proxy, log logrus.FieldLogger) *chainMonitor {
	return &chainMonitor{want: want, proxy: p, log: log}
}

// run checks now, then every retry until the node first answers, then
// every interval, until ctx ends.
func (m *chainMonitor) run(ctx context.Context, interval, retry time.Duration) {
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.check(ctx)
			if m.verdict.Load() == chainUnchecked {
				t.Reset(retry)
			} else {
				t.Reset(interval)
			}
		}
	}
}

// check asks the node for its chain ID once and records the verdict.
func (m *chainMonitor) check(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 2*m.proxy.ds.timeout)
	defer cancel()
	a, e := m.proxy.call(ctx, nextCallID(), MethodChainID)
	if e == nil && a.err != nil {
		e = a.err
	}
	var got *big.Int
	if e == nil {
		q, qe := quantity(a.result, MethodChainID)
		if qe != nil {
			e = qe
		} else {
			got = q.ToInt()
		}
	}
	if e != nil {
		if !errors.Is(ctx.Err(), context.Canceled) {
			m.log.WithField("error", e.Message).Warn("Could not read the downstream node's chain ID; " +
				"the previous verdict stands")
		}
		return
	}
	m.mu.Lock()
	m.got = got
	m.mu.Unlock()
	switch {
	case got.Cmp(m.want) == 0:
		if m.verdict.Swap(chainMatches) != chainMatches {
			m.log.WithField("chain-id", m.want).Info("The downstream node's chain ID matches --chain-id")
		}
	default:
		m.verdict.Store(chainDiffers)
		m.log.WithFields(logrus.Fields{"chain-id": m.want, "node-chain-id": got}).
			Error("The downstream node's chain ID differs from --chain-id; transactions are refused until they match")
	}
}

// refusal returns the refusal of a transaction while the node's chain ID
// differs from --chain-id, or nil.
func (m *chainMonitor) refusal() *refusal {
	if m == nil || m.verdict.Load() != chainDiffers {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return refuse("the downstream node's chain ID is %s, not --chain-id %s", m.got, m.want)
}
