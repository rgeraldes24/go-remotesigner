// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

var (
	// versionHeading matches a CHANGELOG.md version heading in Keep a
	// Changelog form: "## [1.0.0] - 2026-11-02", or "## [Unreleased]".
	versionHeading = regexp.MustCompile(`^## \[([^\]]+)\](?: - (.+))?$`)
	// isoDate is the date a released version's heading carries.
	isoDate = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	// linkReference matches a Markdown link reference definition, which
	// Keep a Changelog puts at the end of the file.
	linkReference = regexp.MustCompile(`^\[[^\]]+\]: \S+$`)
)

// releaseNotes returns the release notes of the tag (v<version>) from the
// CHANGELOG.md text: the body of the version's entry, without its heading
// and the link references, with every relative link pointed at the
// repository at the tag, since a release page holds no files. It refuses a
// tag without an entry, an entry whose heading carries no date (still
// "Unreleased"), and an empty entry, so that a release cannot be published
// before its CHANGELOG.md entry is complete.
//
// CHANGELOG.md has entries for versions only (TestChangelog), so a
// pre-release tag (v1.0.0-rc.1) publishes the notes of its version's entry
// (1.0.0), which may still say "Unreleased": the version itself is not
// released yet.
func releaseNotes(changelog []byte, tag string) ([]byte, error) {
	full, ok := strings.CutPrefix(tag, "v")
	if !ok || full == "" {
		return nil, fmt.Errorf("tag %q is not a version tag v<major>.<minor>.<patch>", tag)
	}
	version, pre, _ := strings.Cut(full, "-")
	var body []string
	found, in := false, false
	for _, line := range strings.Split(string(changelog), "\n") {
		if m := versionHeading.FindStringSubmatch(line); m != nil {
			in = false
			if m[1] != version {
				continue
			}
			if found {
				return nil, fmt.Errorf("CHANGELOG.md has two entries for %s", version)
			}
			if !isoDate.MatchString(m[2]) && (pre == "" || m[2] != "Unreleased") {
				return nil, fmt.Errorf("CHANGELOG.md: the %s entry is dated %q; write the tag's date (YYYY-MM-DD) in its heading before tagging", version, m[2])
			}
			found, in = true, true
			continue
		}
		if in && !linkReference.MatchString(line) {
			body = append(body, line)
		}
	}
	if !found && pre != "" {
		return nil, fmt.Errorf("CHANGELOG.md has no entry for %s, the version of the pre-release %s", version, full)
	}
	if !found {
		return nil, fmt.Errorf("CHANGELOG.md has no entry for %s", version)
	}
	notes := bytes.TrimSpace([]byte(strings.Join(body, "\n")))
	if len(notes) == 0 {
		return nil, fmt.Errorf("CHANGELOG.md: the %s entry is empty", version)
	}
	notes = linkToRepository(notes, tag, func(string) bool { return false })
	return append(notes, '\n'), nil
}
