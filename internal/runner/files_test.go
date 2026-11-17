// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secretfile"
)

// credentialLog returns a logger and the buffer it writes its lines to.
func credentialLog() (*logrus.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	log := logrus.New()
	log.SetOutput(&buf)
	log.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true, DisableColors: true})
	return log, &buf
}

// Every file policy the signer builds follows --strict-file-permissions
// and, without it, logs at WARN what it lets through: a loose mode, a
// loose token directory, and a file or directory of another user, each
// naming the path and what is wrong with it.
func TestFilePolicies(t *testing.T) {
	for _, tt := range []struct {
		name   string
		policy func(*config.Config, logrus.FieldLogger) secretfile.Policy
		mode   string // the mode warning
		dir    string // the directory warning, when the policy has one
		owner  string // the owner warning
	}{
		{name: "server files", policy: ServerFilePolicy,
			mode:  "A token or TLS key file is readable or writable by its group or other users",
			dir:   "A token file is generated in a directory that its group or other users can write",
			owner: "A token or TLS key file, or a token file's directory, is owned by another user"},
		{name: "secret files", policy: SecretPolicy,
			mode:  "A secret file is readable or writable by its group or other users",
			owner: "A secret file is owned by another user"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, strict := range []bool{true, false} {
				log, out := credentialLog()
				p := tt.policy(&config.Config{StrictFilePermissions: strict}, log)
				if p.Strict != strict {
					t.Fatalf("Strict = %v with --strict-file-permissions=%v", p.Strict, strict)
				}
				if p.Warn == nil || p.WarnOwner == nil || (p.WarnDir == nil) != (tt.dir == "") {
					t.Fatalf("warnings: mode %v, owner %v, directory %v", p.Warn != nil, p.WarnOwner != nil, p.WarnDir != nil)
				}
				p.Warn("/etc/signer/file", 0o664)
				if got := out.String(); !strings.Contains(got, "level=warning") || !strings.Contains(got, tt.mode) ||
					!strings.Contains(got, "file=/etc/signer/file") || !strings.Contains(got, "mode=0664") {
					t.Errorf("mode warning: %s", got)
				}
				out.Reset()
				p.WarnOwner("/etc/signer/file", 1000)
				if got := out.String(); !strings.Contains(got, "level=warning") || !strings.Contains(got, tt.owner) ||
					!strings.Contains(got, "file=/etc/signer/file") || !strings.Contains(got, "owner-uid=1000") {
					t.Errorf("owner warning: %s", got)
				}
				if tt.dir == "" {
					continue
				}
				out.Reset()
				p.WarnDir("/data", 0o770)
				if got := out.String(); !strings.Contains(got, "level=warning") || !strings.Contains(got, tt.dir) ||
					!strings.Contains(got, "directory=/data") || !strings.Contains(got, "mode=0770") {
					t.Errorf("directory warning: %s", got)
				}
			}
		})
	}
}
