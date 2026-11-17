// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package secretfile reads the files that hold key material in the clear:
// password files and key-config files with a seed. It checks that such a
// file is readable and writable by its owner only, reads it into a single
// buffer of bounded size, and wipes what it read when the read fails.
//
// A secret file that its group or other users can read or write is refused
// under the strict policy (--strict-file-permissions, the default) and
// loaded with a warning otherwise: one they can read leaks the secret, and
// one they can write lets them choose it, which for a token file is the
// credential itself. The same policy applies to a directory that a secret
// file is about to be created in, when its group or other users can write
// it, or that holds a token file that is loaded.
//
// The owner counts as the mode does: a secret file, or such a directory,
// that belongs to another user than the signer's (its effective uid) and
// root can be read, replaced or given another mode by that user whatever
// its mode says, so it is refused or warned about under the same policy.
//
// Trust files (the client CA and known-clients files, the config file)
// hold no secret, so anyone may read them, but whoever can write one
// decides whom the signer trusts or how it runs: CheckTrusted and
// ReadTrusted apply the policy to one that its group or other users can
// write, or that another user owns.
//
// On Windows, whose files have no POSIX mode bits (Go reports every file
// as 0666, or 0444 when it is read-only) and no uid, these checks are not
// made: access there is governed by the file's ACL.
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
	// ErrInsecure: the file is readable or writable by its group or by
	// other users.
	ErrInsecure = errors.New("readable or writable by group or other users; restrict it to its owner " +
		"(chmod 0600 or 0400) or set --strict-file-permissions=false")
	// ErrDirInsecure: the directory that holds a token file, or that one
	// is to be created in, is writable by its group or by other users.
	ErrDirInsecure = errors.New("writable by group or other users, who could replace the files in it; " +
		"restrict it to its owner (chmod 0700) or set --strict-file-permissions=false")
	// ErrForeignOwner: the file or directory belongs to another user than
	// the signer's and root.
	ErrForeignOwner = errors.New("owned by another user than the signer's and root, who can read or replace it " +
		"whatever its mode; chown it to the signer's user or set --strict-file-permissions=false")
	// ErrWritable: the trust file is writable by its group or by other
	// users.
	ErrWritable = errors.New("writable by group or other users, who could change what the signer trusts or how " +
		"it runs; remove their write permission (chmod go-w) or set --strict-file-permissions=false")
	// ErrNotRegular: the path is not a regular file.
	ErrNotRegular = errors.New("not a regular file")
	// ErrTooLarge: the file holds more than the limit.
	ErrTooLarge = errors.New("file too large")
)

// Policy is what to do with a secret file that is readable or writable by
// its group or by other users, with a directory that holds a token file,
// or is to hold one, and that they can write, with a trust file that they
// can write, and with any of these that another user than the signer's
// and root owns.
type Policy struct {
	// Strict refuses the file with ErrInsecure (a trust file with
	// ErrWritable), the directory with ErrDirInsecure, and a foreign owner
	// with ErrForeignOwner.
	Strict bool
	// Warn is called with the path and mode of such a file when Strict is
	// false; nil warns nobody.
	Warn func(path string, mode fs.FileMode)
	// WarnOwner is called with the path and owner of a file or directory
	// that another user than the signer's and root owns, when Strict is
	// false; nil warns nobody.
	WarnOwner func(path string, uid uint32)
	// WarnDir is called with the path and mode of such a directory (its
	// permission bits and its setuid, setgid and sticky bits; Octal formats
	// them) when Strict is false; nil warns nobody.
	WarnDir func(path string, mode fs.FileMode)
}

// Modes that the policy refuses: group or other read and write for a
// secret file, group or other write for the directory that holds it and
// for a trust file.
const (
	insecureFile  fs.FileMode = 0o066
	insecureDir   fs.FileMode = 0o022
	insecureTrust fs.FileMode = 0o022
)

// euid is the signer's effective uid; tests replace it.
var euid = os.Geteuid

// checkOwner applies p to the owner of the file or directory named name
// (its path, with what it is before it for a directory): one that belongs
// to neither the signer's effective uid nor root is refused under the
// strict policy. Where a file has no uid (Windows, a file system that is
// not the operating system's) nothing is checked.
func (p Policy) checkOwner(name, path string, fi fs.FileInfo) error {
	uid, ok := ownerOf(fi)
	if !ok || uid == 0 || int64(uid) == int64(euid()) {
		return nil
	}
	if p.Strict {
		return fmt.Errorf("%s: owner uid %d, signer uid %d: %w", name, uid, euid(), ErrForeignOwner)
	}
	if p.WarnOwner != nil {
		p.WarnOwner(path, uid)
	}
	return nil
}

// posixModes reports whether file modes carry the owner, group and other
// permission bits; on Windows they do not.
var posixModes = runtime.GOOS != "windows"

// Check applies p to the file at path with info fi (which follows
// symlinks, as os.Stat does): it fails for anything but a regular file,
// and, where file modes carry POSIX permissions, for a file readable or
// writable by group or others, or owned by another user than the signer's
// and root, under the strict policy.
func (p Policy) Check(path string, fi fs.FileInfo) error {
	return p.checkFile(path, fi, insecureFile, ErrInsecure)
}

// CheckTrusted applies p to the trust file at path with info fi: it fails
// for anything but a regular file, and, where file modes carry POSIX
// permissions, for a file writable by group or others, or owned by
// another user than the signer's and root, under the strict policy. A
// trust file may be readable by anyone.
func (p Policy) CheckTrusted(path string, fi fs.FileInfo) error {
	return p.checkFile(path, fi, insecureTrust, ErrWritable)
}

// checkFile refuses anything but a regular file, and applies p to a file
// with one of the insecure mode bits, with refusal as the strict policy's
// error, and to its owner.
func (p Policy) checkFile(path string, fi fs.FileInfo, insecure fs.FileMode, refusal error) error {
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s: %w", path, ErrNotRegular)
	}
	if !posixModes {
		return nil
	}
	if perm := fi.Mode().Perm(); perm&insecure != 0 {
		if p.Strict {
			return fmt.Errorf("%s: mode %04o: %w", path, perm, refusal)
		}
		if p.Warn != nil {
			p.Warn(path, perm)
		}
	}
	return p.checkOwner(path, path, fi)
}

// CheckDir applies p to the directory at path with info fi, which holds a
// secret file or in which one is about to be created: it fails for
// anything but a directory, and, where file modes carry POSIX
// permissions, for a directory writable by group or others, or owned by
// another user than the signer's and root, under the strict policy, since
// they could replace the file, or plant their own before it is written.
// The sticky bit exempts nothing: it protects the entries of other users
// only.
func (p Policy) CheckDir(path string, fi fs.FileInfo) error {
	if !fi.IsDir() {
		return fmt.Errorf("directory %s: not a directory", path)
	}
	if !posixModes {
		return nil
	}
	if fi.Mode().Perm()&insecureDir != 0 {
		mode := fi.Mode() & (fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky)
		if p.Strict {
			return fmt.Errorf("directory %s: mode %s: %w", path, Octal(mode), ErrDirInsecure)
		}
		if p.WarnDir != nil {
			p.WarnDir(path, mode)
		}
	}
	return p.checkOwner("directory "+path, path, fi)
}

// Octal formats mode's permission bits, and its setuid, setgid and sticky
// bits, as the octal mode that chmod takes: 1777 for /tmp, 2770 for a
// volume root that a Kubernetes fsGroup was applied to.
func Octal(mode fs.FileMode) string {
	m := uint32(mode.Perm())
	if mode&fs.ModeSetuid != 0 {
		m |= 0o4000
	}
	if mode&fs.ModeSetgid != 0 {
		m |= 0o2000
	}
	if mode&fs.ModeSticky != 0 {
		m |= 0o1000
	}
	return fmt.Sprintf("%04o", m)
}

// Read checks and reads the secret file at path, which must hold at most
// limit bytes. The mode is checked on the opened file, so the file read is
// the file checked. The caller wipes the result with mldsa87.Wipe.
func Read(path string, limit int64, p Policy) ([]byte, error) {
	data, _, err := read(path, limit, func(fi fs.FileInfo) error { return p.Check(path, fi) })
	return data, err
}

// ReadTrusted checks and reads the trust file at path, which must hold at
// most limit bytes. Like Read, it checks the opened file.
func ReadTrusted(path string, limit int64, p Policy) ([]byte, error) {
	data, _, err := read(path, limit, func(fi fs.FileInfo) error { return p.CheckTrusted(path, fi) })
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
