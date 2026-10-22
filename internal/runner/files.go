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
// other users can read is refused under the strict policy and logged at
// WARN otherwise.
func ServerFilePolicy(cfg *config.Config, log logrus.FieldLogger) secretfile.Policy {
	return secretfile.Policy{Strict: cfg.StrictFilePermissions, Warn: func(path string, mode fs.FileMode) {
		log.WithFields(logrus.Fields{"file": path, "mode": fmt.Sprintf("%04o", mode)}).
			Warn("A token or TLS key file is readable by its group or other users; restrict it to its owner (chmod 0600)")
	}}
}
