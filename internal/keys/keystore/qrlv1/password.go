// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package qrlv1

import "bytes"

// Password is the candidate set of one password (DESIGN §3.6.2, G3 §A.2):
// the NFKD-normalised password with the C0 controls and DEL stripped (what
// qrysm's keystore v1 encrypts with), the older alternative normalisation
// that qrysm's decryptor also tries, and the raw bytes (what the deposit
// CLI encrypts with). Equal candidates are tried once, so a printable-ASCII
// password costs a single Argon2id run.
type Password struct {
	norm, alt, raw []byte
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

// TrimPassword strips the trailing carriage returns and line feeds of a
// password file's content, as qrysm and the deposit CLI do when they read
// one.
func TrimPassword(b []byte) []byte {
	return bytes.TrimRight(b, "\r\n")
}

// candidates returns the distinct candidates in the order the flavour
// tries them: the encoding its producer uses first.
func (p *Password) candidates(f Flavour) [][]byte {
	if p == nil {
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
