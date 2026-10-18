// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package execution

import (
	"fmt"
	"strings"
)

// Allowlist decides which methods are forwarded to the downstream node
// (--execution-proxy-allowed-methods, by default qrl_*, net_* and web3_*:
// the chain, network and client namespaces; admin_*, debug_*, personal_*,
// miner_*, txpool_*, account_* and eth_* are then not forwarded). An entry
// is a method name, a prefix ending in "*" (qrl_*), or "*" alone, which
// forwards every method. Names are case-sensitive, as gqrl's are.
type Allowlist struct {
	exact    map[string]bool
	prefixes []string
	all      bool
}

// ParseAllowlist checks the entries of --execution-proxy-allowed-methods.
// Blank entries are ignored, so an empty value forwards nothing.
func ParseAllowlist(entries []string) (*Allowlist, error) {
	a := &Allowlist{exact: map[string]bool{}}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		name, wildcard := strings.CutSuffix(e, "*")
		if !validMethodChars(name) || (!wildcard && name == "") {
			return nil, fmt.Errorf("method pattern %q: want a method name, a prefix ending in *, or *", e)
		}
		switch {
		case wildcard && name == "":
			a.all = true
		case wildcard:
			a.prefixes = append(a.prefixes, name)
		default:
			a.exact[name] = true
		}
	}
	return a, nil
}

// validMethodChars reports whether s holds only the characters of a
// JSON-RPC method name: letters, digits and underscores.
func validMethodChars(s string) bool {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '_':
		default:
			return false
		}
	}
	return true
}

// Allows reports whether method may be forwarded.
func (a *Allowlist) Allows(method string) bool {
	if a.all || a.exact[method] {
		return true
	}
	for _, p := range a.prefixes {
		if strings.HasPrefix(method, p) {
			return true
		}
	}
	return false
}
