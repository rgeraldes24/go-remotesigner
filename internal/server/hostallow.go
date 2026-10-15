// Copyright 2020 ConsenSys AG.
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
// core/src/main/java/tech/pegasys/web3signer/core/service/http/HostAllowListHandler.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package server

import (
	"net"
	"strings"
)

// AllowAllHosts is the host-allowlist entry that admits every Host header.
const AllowAllHosts = "*"

// hostAllowlist is the DNS-rebinding defence: a request is served only when
// its Host header, without the port, is in the list (case-insensitively), or
// the list contains "*". A request without a Host is refused unless "*" is
// listed.
type hostAllowlist struct {
	any   bool
	hosts map[string]struct{}
}

func newHostAllowlist(entries []string) hostAllowlist {
	l := hostAllowlist{hosts: make(map[string]struct{}, len(entries))}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == AllowAllHosts {
			l.any = true
			continue
		}
		if e != "" {
			l.hosts[strings.ToLower(trimBrackets(e))] = struct{}{}
		}
	}
	return l
}

func (l hostAllowlist) allows(hostHeader string) bool {
	if l.any {
		return true
	}
	host := hostOnly(hostHeader)
	if host == "" {
		return false
	}
	_, ok := l.hosts[strings.ToLower(host)]
	return ok
}

// hostOnly strips the port from a Host header value, and the brackets from
// an IPv6 literal.
func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return trimBrackets(h)
}

func trimBrackets(h string) string {
	if len(h) >= 2 && h[0] == '[' && h[len(h)-1] == ']' {
		return h[1 : len(h)-1]
	}
	return h
}
