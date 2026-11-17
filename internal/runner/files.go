// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"fmt"
	"io/fs"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secretfile"
)

// ServerFilePolicy is the --strict-file-permissions policy of the listener's
// own secret files: the sign, admin and metrics token files, read at
// startup and on SIGHUP, and the TLS private key, PKCS#12 keystore and its
// password file, and a reused self-signed key. A file that its group or
// other users can read or write, a directory that they can write and that
// holds a token file or is to have a missing one generated in it
// (--data-path for the default token files), and a file or directory that
// another user than the signer's and root owns, are refused under the
// strict policy and logged at WARN otherwise.
func ServerFilePolicy(cfg *config.Config, log logrus.FieldLogger) secretfile.Policy {
	return secretfile.Policy{
		Strict: cfg.StrictFilePermissions,
		Warn: func(path string, mode fs.FileMode) {
			log.WithFields(logrus.Fields{"file": path, "mode": fmt.Sprintf("%04o", mode)}).
				Warn("A token or TLS key file is readable or writable by its group or other users; restrict it to " +
					"its owner (chmod 0600)")
		},
		WarnDir: func(path string, mode fs.FileMode) {
			log.WithFields(logrus.Fields{"directory": path, "mode": secretfile.Octal(mode)}).
				Warn("A token file's directory is writable by its group or other users, who could replace the " +
					"token; restrict the directory to its owner (chmod 0700)")
		},
		WarnOwner: warnOwner(log, "A token or TLS key file, or a token file's directory, is owned by another user "+
			"than the signer's and root, who can read or replace it; chown it to the signer's user"),
	}
}

// warnOwner logs msg at WARN for a file or directory that another user
// than the signer's and root owns.
func warnOwner(log logrus.FieldLogger, msg string) func(string, uint32) {
	return func(path string, uid uint32) {
		log.WithFields(logrus.Fields{"file": path, "owner-uid": uid}).Warn(msg)
	}
}
