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
// core/src/main/java/tech/pegasys/web3signer/core/service/http/HostAllowListHandler.java and
// commandline/src/main/java/tech/pegasys/web3signer/commandline/config/AllowListHostsProperty.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package server

import (
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
)

// AllowAllHosts is the host-allowlist entry that admits every Host header.
const AllowAllHosts = "*"

// The list words of --http-host-allowlist.
const (
	allowAllWord  = "all"  // the same as AllowAllHosts
	allowNoneWord = "none" // alone, an empty list that refuses every host
)

// Errors returned by ParseHostAllowlist.
var (
	ErrAllowlistNoneMixed = errors.New(`host allowlist: "none" cannot be combined with other hosts`)
	ErrAllowlistAllMixed  = errors.New(`host allowlist: "*" or "all" cannot be combined with other hosts`)
)

// ParseHostAllowlist applies the list words of --http-host-allowlist, as
// Web3Signer does: "all" is "*", and "none" alone is an empty list that
// refuses every host. Neither "none" nor "*" may be combined with other
// entries. Entries are trimmed, empty ones dropped, and the words matched
// case-insensitively.
func ParseHostAllowlist(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	none := false
	for _, h := range in {
		h = strings.TrimSpace(h)
		switch {
		case h == "":
			continue
		case strings.EqualFold(h, allowNoneWord):
			none = true
			continue
		case strings.EqualFold(h, allowAllWord):
			h = AllowAllHosts
		}
		out = append(out, h)
	}
	switch {
	case none && len(out) > 0:
		return nil, ErrAllowlistNoneMixed
	case len(out) > 1 && slices.Contains(out, AllowAllHosts):
		return nil, ErrAllowlistAllMixed
	}
	return out, nil
}

// RequireAllowedHost is the DNS-rebinding defence: it serves a request only
// when its Host header, without the port, is in allowlist
// (case-insensitively), or allowlist contains "*", and refuses any other
// with 403 HOST_NOT_ALLOWED. A request without a Host is refused unless "*"
// is listed. The API listener runs it with --http-host-allowlist and the
// metrics listener with --metrics-host-allowlist.
func RequireAllowedHost(allowlist []string, log logrus.FieldLogger, next http.Handler) http.Handler {
	hosts := newHostAllowlist(allowlist)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hosts.allows(r.Host) {
			WriteError(w, log, r, apierr.New(apierr.HostNotAllowed, "Host not in the allowlist"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// hostAllowlist is a parsed allowlist; see RequireAllowedHost.
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
