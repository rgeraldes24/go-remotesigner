// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package execution

import "testing"

func TestAllowlist(t *testing.T) {
	tests := []struct {
		entries []string
		allowed []string
		refused []string
	}{
		{defaultAllow, []string{"qrl_blockNumber", "net_version", "web3_clientVersion", "qrl_"},
			[]string{"admin_addPeer", "debug_traceCall", "eth_call", "personal_sign", "Qrl_x", "qrlx", ""}},
		{[]string{"*"}, []string{"admin_addPeer", "anything"}, nil},
		{[]string{"qrl_getBalance", " net_* ", ""}, []string{"qrl_getBalance", "net_listening"},
			[]string{"qrl_getBalanceX", "qrl_blockNumber"}},
		{nil, nil, []string{"qrl_blockNumber"}},
		{[]string{""}, nil, []string{"qrl_blockNumber"}},
	}
	for _, tt := range tests {
		a, err := ParseAllowlist(tt.entries)
		if err != nil {
			t.Fatalf("%q: %v", tt.entries, err)
		}
		for _, m := range tt.allowed {
			if !a.Allows(m) {
				t.Errorf("%q refuses %q", tt.entries, m)
			}
		}
		for _, m := range tt.refused {
			if a.Allows(m) {
				t.Errorf("%q allows %q", tt.entries, m)
			}
		}
	}
	for _, bad := range []string{"qrl_*_x", "*qrl", "qrl-x", "qrl.*", "**", "a b"} {
		if _, err := ParseAllowlist([]string{bad}); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}
