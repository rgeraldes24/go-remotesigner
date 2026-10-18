// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package hashicorp

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strings"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/secretfile"
	"github.com/rgeraldes24/go-remotesigner/internal/server/tlsconf"
)

// maxKnownServersFile bounds a known-servers file.
const maxKnownServersFile = 1 << 20

// LoadKnownServers reads a known-servers file, the format of Web3Signer's
// tlsKnownServersPath: one "<host>:<port> <SHA-256 fingerprint>" per
// line, the fingerprint in hex with or without colons, an IPv6 host in
// brackets. Blank lines and lines starting with # are skipped. The result
// maps a lower-case host:port to its fingerprints.
func LoadKnownServers(path string) (map[string][]tlsconf.Fingerprint, error) {
	data, err := secretfile.ReadCapped(path, maxKnownServersFile)
	if err != nil {
		return nil, fmt.Errorf("known servers file: %w", err)
	}
	out := map[string][]tlsconf.Fingerprint{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(nil, maxKnownServersFile)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 {
			return nil, fmt.Errorf("known servers file %s line %d: want \"<host>:<port> <sha256 fingerprint>\"", path, n)
		}
		host, port, err := net.SplitHostPort(f[0])
		if err != nil || host == "" || port == "" {
			return nil, fmt.Errorf("known servers file %s line %d: want \"<host>:<port> <sha256 fingerprint>\"", path, n)
		}
		fp, err := tlsconf.ParseFingerprint(f[1])
		if err != nil {
			return nil, fmt.Errorf("known servers file %s line %d: %w", path, n, err)
		}
		k := strings.ToLower(net.JoinHostPort(host, port))
		out[k] = append(out[k], fp)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("known servers file %s: %w", path, err)
	}
	return out, nil
}
