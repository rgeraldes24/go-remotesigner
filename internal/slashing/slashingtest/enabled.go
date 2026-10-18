// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package slashingtest

import (
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// enabledWait is how long the suite waits to see whether SetValidatorEnabled returns while a transaction for the
// same validator is open. A store that serialises them never returns in that window, so a slow machine can only
// hide a bug, never report a false one.
const enabledWait = 100 * time.Millisecond

// runEnabledSerialisation checks that SetValidatorEnabled is serialised with the validator's block, attestation and
// history transactions: it does not return while one is open, the open one keeps reading the old flag, and a
// transaction that starts after it returns reads the new flag.
func runEnabledSerialisation(t *testing.T, newStore Factory) {
	kinds := []struct {
		name    string
		enabled func(s slashing.Store, during func()) (bool, error)
	}{
		{"block transaction", func(s slashing.Store, during func()) (bool, error) {
			var enabled bool
			err := s.UpdateBlocks(bg, id(0), func(tx slashing.BlockTx) error {
				during()
				var err error
				enabled, err = tx.Enabled()
				return err
			})
			return enabled, err
		}},
		{"attestation transaction", func(s slashing.Store, during func()) (bool, error) {
			var enabled bool
			err := s.UpdateAttestations(bg, id(0), func(tx slashing.AttestationTx) error {
				during()
				var err error
				enabled, err = tx.Enabled()
				return err
			})
			return enabled, err
		}},
		{"history transaction", func(s slashing.Store, during func()) (bool, error) {
			var enabled bool
			err := s.UpdateHistory(bg, []slashing.KeyID{id(0)}, func(_ slashing.KeyID, tx slashing.HistoryTx) error {
				during()
				var err error
				enabled, err = tx.Enabled()
				return err
			})
			return enabled, err
		}},
	}
	for _, kind := range kinds {
		t.Run(kind.name, func(t *testing.T) {
			s := openWithKeys(t, newStore, 1)
			entered, release := make(chan struct{}), make(chan struct{})
			type result struct {
				enabled bool
				err     error
			}
			txDone := make(chan result, 1)
			go func() {
				enabled, err := kind.enabled(s, func() {
					close(entered)
					<-release
				})
				txDone <- result{enabled, err}
			}()
			select {
			case <-entered:
			case r := <-txDone:
				t.Fatalf("the %s returned without calling its function: %v", kind.name, r.err)
			}

			setDone := make(chan error, 1)
			go func() { setDone <- s.SetValidatorEnabled(bg, id(0), false) }()
			select {
			case err := <-setDone:
				t.Errorf("SetValidatorEnabled returned (%v) while a %s was open", err, kind.name)
				setDone <- err
			case <-time.After(enabledWait):
			}
			close(release)

			r := <-txDone
			must(t, r.err)
			if !r.enabled {
				t.Errorf("the open %s read the new flag", kind.name)
			}
			must(t, <-setDone)
			enabled, err := kind.enabled(s, func() {})
			must(t, err)
			if enabled {
				t.Errorf("a %s that started after SetValidatorEnabled read the old flag", kind.name)
			}
		})
	}
}
