// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package secretfile reads the files that hold key material in the clear:
// password files and key-config files with a seed. It checks that such a
// file is readable by its owner only, reads it into a single buffer of
// bounded size, and wipes what it read when the read fails.
//
// A secret file that its group or other users can read is refused under
// the strict policy (--strict-file-permissions, the default) and loaded
// with a warning otherwise. On Windows, whose files have no POSIX mode
// bits (Go reports every file as 0666, or 0444 when it is read-only), that
// check is not made: access there is governed by the file's ACL.
package secretfile

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
	"syscall"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
)

// Errors. Callers match them with errors.Is.
var (
	// ErrInsecure: the file is readable by its group or by other users.
	ErrInsecure = errors.New("readable by group or other users; restrict it to its owner (chmod 0600 or 0400) " +
		"or set --strict-file-permissions=false")
	// ErrNotRegular: the path is not a regular file.
	ErrNotRegular = errors.New("not a regular file")
	// ErrTooLarge: the file holds more than the limit.
	ErrTooLarge = errors.New("file too large")
)

// Policy is what to do with a secret file that is readable by its group or
// by other users.
type Policy struct {
	// Strict refuses the file with ErrInsecure.
	Strict bool
	// Warn is called with the path and mode of such a file when Strict is
	// false; nil warns nobody.
	Warn func(path string, mode fs.FileMode)
}

// posixModes reports whether file modes carry the owner, group and other
// permission bits; on Windows they do not.
var posixModes = runtime.GOOS != "windows"

// Check applies p to the file at path with info fi (which follows
// symlinks, as os.Stat does): it fails for anything but a regular file,
// and, where file modes carry POSIX permissions, for a file readable by
// group or others under the strict policy.
func (p Policy) Check(path string, fi fs.FileInfo) error {
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s: %w", path, ErrNotRegular)
	}
	if !posixModes || fi.Mode().Perm()&0o044 == 0 {
		return nil
	}
	if p.Strict {
		return fmt.Errorf("%s: mode %04o: %w", path, fi.Mode().Perm(), ErrInsecure)
	}
	if p.Warn != nil {
		p.Warn(path, fi.Mode().Perm())
	}
	return nil
}

// Read checks and reads the secret file at path, which must hold at most
// limit bytes. The mode is checked on the opened file, so the file read is
// the file checked. The caller wipes the result with mldsa87.Wipe.
func Read(path string, limit int64, p Policy) ([]byte, error) {
	data, _, err := read(path, limit, func(fi fs.FileInfo) error { return p.Check(path, fi) })
	return data, err
}

// ReadInfo reads the regular file at path, which must hold at most limit
// bytes, and returns its content and the mode and times it had when it was
// read, so that the caller can apply a Policy once it knows what the file
// holds.
func ReadInfo(path string, limit int64) ([]byte, fs.FileInfo, error) {
	return read(path, limit, func(fi fs.FileInfo) error {
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("%s: %w", path, ErrNotRegular)
		}
		return nil
	})
}

// ReadCapped reads the regular file at path, which must hold at most limit
// bytes, with no mode check: for files that hold no secret in the clear,
// such as an encrypted keystore.
func ReadCapped(path string, limit int64) ([]byte, error) {
	data, _, err := ReadInfo(path, limit)
	return data, err
}

// read opens path, applies check to the opened file and reads it into a
// buffer sized from the file, at most limit bytes.
//
// The file is opened with O_NONBLOCK, so that a path swapped for a FIFO
// after the directory was listed cannot block the loader in open: the
// open returns at once and the check refuses what is not a regular file.
// On a regular file the flag changes nothing.
func read(path string, limit int64, check func(fs.FileInfo) error) ([]byte, fs.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if err := check(fi); err != nil {
		return nil, nil, err
	}
	if fi.Size() > limit {
		return nil, nil, fmt.Errorf("%s: %w: larger than %d bytes", path, ErrTooLarge, limit)
	}
	data, err := ReadLimited(f, fi.Size())
	if errors.Is(err, ErrTooLarge) {
		return nil, nil, fmt.Errorf("%s: changed while it was read", path)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	return data, fi, nil
}

// ReadLimited reads r, which must hold at most limit bytes, into a single
// buffer of limit+1 bytes. Unlike io.ReadAll, it never grows the buffer, so
// no copy of a secret is left behind, and it wipes what it read when r
// fails or holds more than limit bytes.
func ReadLimited(r io.Reader, limit int64) ([]byte, error) {
	buf := make([]byte, limit+1)
	n, err := io.ReadFull(r, buf)
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return buf[:n], nil
	case err != nil:
		mldsa87.Wipe(buf)
		return nil, err
	default: // buf is full
		mldsa87.Wipe(buf)
		return nil, fmt.Errorf("%w: larger than %d bytes", ErrTooLarge, limit)
	}
}
