// Copyright 2021 ConsenSys AG.
// Copyright 2026 The go-remotesigner Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//
// Modified by The go-remotesigner Authors, 2026: translated from Java to Go and adapted for QRL.
// Derived from Web3Signer
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/DbPrunerRunner.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package runner

import (
	"context"
	"errors"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// pruner runs slashing.Prune in the background: once at startup with bbolt, then every interval. A failed run is
// logged and the next one runs on schedule, as in Web3Signer's DbPrunerRunner; unlike it, the bbolt store's startup
// run is not optional (DEVIATIONS.md X56), and the window is in the network's slots per epoch. A Postgres store is
// shared by every replica, which would all prune it at once when they start together: its first run waits one
// interval, as Web3Signer's does by default, and each transaction covers one validator.
type pruner struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// startPruner starts pruning store with the configured window, in epochs of slotsPerEpoch slots: now and then at
// every interval when atStartup is set, else at every interval.
func startPruner(store slashing.Store, cfg config.Pruning, slotsPerEpoch uint64, atStartup bool,
	log logrus.FieldLogger) *pruner {
	ctx, cancel := context.WithCancel(context.Background())
	p := &pruner{cancel: cancel, done: make(chan struct{})}
	pc := slashing.PruneConfig{EpochsToKeep: cfg.EpochsToKeep, SlotsPerEpoch: slotsPerEpoch}
	if !atStartup {
		pc.Batch = 1
	}
	log = log.WithFields(logrus.Fields{"epochs-to-keep": cfg.EpochsToKeep, "slots-per-epoch": slotsPerEpoch})
	go func() {
		defer close(p.done)
		ticker := time.NewTicker(cfg.Interval)
		defer ticker.Stop()
		for first := atStartup; ; first = true {
			if first {
				pruneOnce(ctx, store, pc, log)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	when := "now, then at every interval"
	if !atStartup {
		when = "at every interval"
	}
	log.WithField("interval", cfg.Interval).Info("Slashing-protection pruning scheduled: " + when)
	return p
}

func pruneOnce(ctx context.Context, store slashing.Store, cfg slashing.PruneConfig, log logrus.FieldLogger) {
	start := time.Now()
	res, err := slashing.Prune(ctx, store, cfg)
	f := logrus.Fields{"validators": res.Validators, "blocks-deleted": res.Blocks,
		"attestations-deleted": res.Attestations, "duration": time.Since(start).Round(time.Millisecond)}
	switch {
	case errors.Is(err, context.Canceled):
		log.WithFields(f).Info("Slashing-protection pruning stopped by shutdown")
	case err != nil:
		log.WithFields(f).WithError(err).Error("Slashing-protection pruning failed; it runs again at the next interval")
	default:
		log.WithFields(f).Info("Slashing-protection pruning finished")
	}
}

// stop ends the pruner and waits for a running batch to finish, so that the store can be closed.
func (p *pruner) stop() {
	if p == nil {
		return
	}
	p.cancel()
	<-p.done
}
