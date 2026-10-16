// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package qrlv1

import (
	"bytes"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
)

// Password is the candidate set of one password:
// the NFKD-normalised password with the C0 controls and DEL stripped (what
// qrysm's keystore v1 encrypts with), the older alternative normalisation
// that qrysm's decryptor also tries, and the raw bytes (what the deposit
// CLI encrypts with). Equal candidates are tried once, so a printable-ASCII
// password costs a single Argon2id run.
//
// One Password can open many keystores, concurrently. The caller wipes it
// when it has opened the last one.
type Password struct {
	norm, alt, raw []byte
	wiped          bool
}

// NewPassword returns the candidate set of p, taken as given. Passwords
// read from a file go through TrimPassword first.
func NewPassword(p []byte) *Password {
	s := string(p)
	return &Password{
		norm: []byte(normPassphrase(s)),
		alt:  []byte(altNormPassphrase(s)),
		raw:  bytes.Clone(p),
	}
}

// Wipe zeroes the candidates; a wiped Password opens no keystore. The
// strings that the normalisation builds on the way are unreachable once
// NewPassword returns, and are left to the garbage collector.
func (p *Password) Wipe() {
	if p == nil {
		return
	}
	for _, b := range [][]byte{p.norm, p.alt, p.raw} {
		mldsa87.Wipe(b)
	}
	p.norm, p.alt, p.raw, p.wiped = nil, nil, nil, true
}

// TrimPassword strips the trailing carriage returns and line feeds of a
// password file's content, as qrysm and the deposit CLI do when they read
// one.
func TrimPassword(b []byte) []byte {
	return bytes.TrimRight(b, "\r\n")
}

// candidates returns the distinct candidates in the order the flavour
// tries them: the encoding its producer uses first.
func (p *Password) candidates(f Flavour) [][]byte {
	if p == nil || p.wiped {
		return nil
	}
	order := [][]byte{p.norm, p.alt, p.raw}
	if f == DepositCLI {
		order = [][]byte{p.raw, p.norm, p.alt}
	}
	out := make([][]byte, 0, len(order))
	for _, c := range order {
		dup := false
		for _, o := range out {
			dup = dup || bytes.Equal(o, c)
		}
		if !dup {
			out = append(out, c)
		}
	}
	return out
}
