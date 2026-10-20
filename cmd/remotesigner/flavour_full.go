// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package main

import (
	"fmt"
	"io"
	"regexp"

	"github.com/urfave/cli/v2"

	"github.com/rgeraldes24/go-remotesigner/cmd/remotesigner/flags"
)

// binaryName is the name of the default flavour: consensus and execution
// mode.
const binaryName = "remotesigner"

// releasesURL is the page of go-remotesigner's GitHub releases, which
// carry the source archives; the release of version v is at
// releasesURL/tag/v<v>.
const releasesURL = "https://github.com/rgeraldes24/go-remotesigner/releases"

// releaseVersion matches the versions a release build reports: those of
// the tags v<major>.<minor>.<patch>[-<pre-release>], the "v" dropped, and
// the dry run's <version>-SNAPSHOT-<commit>. A build without one ("dev")
// names no release.
var releaseVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`)

// flavourNotice follows the version v in --version: the notice of go-qrl,
// which execution mode links, as the LGPL asks of a combined work that
// shows notices at run time, with the directions to the notice and licence
// texts and to the corresponding source of v's release (GPLv3 section
// 6(d), which LGPLv3 section 4(d)(0) applies): its file name and the
// release that attaches it.
func flavourNotice(v string) string {
	src, release := "remotesigner-<version>-src-vendored.tar.gz", releasesURL+"/tag/v<version>"
	if releaseVersion.MatchString(v) {
		src, release = "remotesigner-"+v+"-src-vendored.tar.gz", releasesURL+"/tag/v"+v
	}
	return fmt.Sprintf(`

This binary links the go-qrl library (https://github.com/theQRL/go-qrl),
Copyright 2014-2025 The go-ethereum Authors, licensed under the GNU Lesser
General Public License v3.0 or later. See NOTICE,
LICENSES/LGPL-3.0-or-later.txt and LICENSES/GPL-3.0-or-later.txt in the
release archive, or under /usr/share/doc/remotesigner/ in the image. The
corresponding source, with go-qrl vendored, is the file
  %s
of the release
  %s`, src, release)
}

// flavourCommands are the commands only this flavour has: execution.
func flavourCommands(pick func(runFunc) runFunc, stdout, stderr io.Writer) []*cli.Command {
	return []*cli.Command{executionCommand(pick(executionRun), stdout, stderr)}
}

// flavourSections are the --config-file sections of flavourCommands.
func flavourSections() map[string][]cli.Flag {
	return map[string][]cli.Flag{flags.ExecutionCommand: flags.Execution()}
}

// cloudSecretStores reports whether this flavour links the cloud SDKs of
// the AWS, Azure and GCP secret stores.
const cloudSecretStores = true
