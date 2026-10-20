// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const changelogFixture = `# Changelog

Intro with [a link](docs/contract.md).

## [Unreleased]

## [1.1.0] - Unreleased

### Added

- Execution mode.

## [1.0.0] - 2026-11-02

The first release ([deviations](DEVIATIONS.md), [section 20](docs/contract.md#20-versioning-and-change-control),
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), [below](#added)).

### Added

- Consensus signing.

## [0.9.0] - 2026-10-01

### Fixed

- Something.

[Unreleased]: https://github.com/rgeraldes24/go-remotesigner/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/rgeraldes24/go-remotesigner/releases/tag/v1.0.0
`

func TestReleaseNotes(t *testing.T) {
	got, err := releaseNotes([]byte(changelogFixture), "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	want := `The first release ([deviations](https://github.com/rgeraldes24/go-remotesigner/blob/v1.0.0/DEVIATIONS.md), ` +
		`[section 20](https://github.com/rgeraldes24/go-remotesigner/blob/v1.0.0/docs/contract.md#20-versioning-and-change-control),
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), [below](#added)).

### Added

- Consensus signing.
`
	if string(got) != want {
		t.Errorf("notes:\n%s\nwant:\n%s", got, want)
	}

	// The last entry ends before the link references.
	got, err = releaseNotes([]byte(changelogFixture), "v0.9.0")
	if err != nil || string(got) != "### Fixed\n\n- Something.\n" {
		t.Errorf("v0.9.0 notes %q, %v", got, err)
	}
}

// A pre-release tag publishes the notes of its version's entry, dated or
// still Unreleased, with the links pointed at the pre-release tag.
func TestReleaseNotesPreRelease(t *testing.T) {
	got, err := releaseNotes([]byte(changelogFixture), "v1.1.0-rc.1")
	if err != nil || string(got) != "### Added\n\n- Execution mode.\n" {
		t.Errorf("v1.1.0-rc.1 notes %q, %v", got, err)
	}
	got, err = releaseNotes([]byte(changelogFixture), "v1.0.0-rc.2")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "](https://github.com/rgeraldes24/go-remotesigner/blob/v1.0.0-rc.2/DEVIATIONS.md)") {
		t.Errorf("v1.0.0-rc.2 notes do not link at the tag:\n%s", got)
	}
	// The repository's own entry, still Unreleased, makes a pre-release's
	// notes as it is.
	data, err := os.ReadFile("../../CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	if notes, err := releaseNotes(data, "v1.0.0-rc.1"); err != nil || !strings.Contains(string(notes), "### Added") {
		t.Errorf("v1.0.0-rc.1 notes from CHANGELOG.md: %v\n%s", err, notes)
	}
}

func TestReleaseNotesRefused(t *testing.T) {
	tests := []struct {
		name, changelog, tag, want string
	}{
		{"undated", changelogFixture, "v1.1.0", `dated "Unreleased"`},
		{"no entry", changelogFixture, "v2.0.0", "no entry for 2.0.0"},
		{"not a version tag", changelogFixture, "1.0.0", "not a version tag"},
		{"no date at all", "## [1.0.0]\n\n- x\n", "v1.0.0", `dated ""`},
		{"empty", "## [1.0.0] - 2026-11-02\n\n[1.0.0]: https://example.org\n", "v1.0.0", "is empty"},
		{"twice", "## [1.0.0] - 2026-11-02\n\n- a\n\n## [1.0.0] - 2026-11-03\n\n- b\n", "v1.0.0", "two entries"},
		{"pre-release without its version's entry", changelogFixture, "v2.0.0-rc.1", "no entry for 2.0.0, the version of the pre-release 2.0.0-rc.1"},
		{"pre-release of an entry without a date", "## [1.0.0]\n\n- x\n", "v1.0.0-rc.1", `dated ""`},
		{"pre-release of an empty entry", "## [1.0.0] - Unreleased\n\n[1.0.0]: https://example.org\n", "v1.0.0-rc.1", "is empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := releaseNotes([]byte(tt.changelog), tt.tag)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("releaseNotes = %q, %v; want an error mentioning %q", got, err, tt.want)
			}
		})
	}
}

// The repository's CHANGELOG.md is in Keep a Changelog form: an Unreleased
// section first, then one entry per version, newest first, each dated or
// "Unreleased" and holding only the standard kinds of change, with a link
// reference per version. It has the 1.0.0 and 1.1.0 entries, whose notes a
// release can publish once their headings carry the tag's date.
func TestChangelog(t *testing.T) {
	data, err := os.ReadFile("../../CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.HasPrefix(text, "# Changelog\n") {
		t.Error(`CHANGELOG.md does not start with "# Changelog"`)
	}
	kinds := []string{"Added", "Changed", "Deprecated", "Removed", "Fixed", "Security"}
	semver := regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`)
	var versions []string
	var prev []int
	for _, line := range strings.Split(text, "\n") {
		if kind, ok := strings.CutPrefix(line, "### "); ok && !slices.Contains(kinds, kind) {
			t.Errorf("%q: not a Keep a Changelog kind of change (%s)", line, strings.Join(kinds, ", "))
		}
		if !strings.HasPrefix(line, "## ") {
			continue
		}
		m := versionHeading.FindStringSubmatch(line)
		if m == nil {
			t.Errorf("%q: not a version heading", line)
			continue
		}
		versions = append(versions, m[1])
		if len(versions) == 1 {
			if line != "## [Unreleased]" {
				t.Errorf("the first section is %q, want ## [Unreleased]", line)
			}
			continue
		}
		v := semver.FindStringSubmatch(m[1])
		if v == nil || (m[2] != "Unreleased" && !isoDate.MatchString(m[2])) {
			t.Errorf("%q: want ## [<major>.<minor>.<patch>] - <YYYY-MM-DD or Unreleased>", line)
			continue
		}
		cur := []int{atoi(v[1]), atoi(v[2]), atoi(v[3])}
		if prev != nil && slices.Compare(cur, prev) >= 0 {
			t.Errorf("%s is listed after %v: entries go newest first", m[1], prev)
		}
		prev = cur
	}
	for _, v := range versions {
		if !strings.Contains(text, "\n["+v+"]: https://github.com/rgeraldes24/go-remotesigner/") {
			t.Errorf("no link reference for [%s]", v)
		}
	}
	for _, version := range []string{"1.0.0", "1.1.0"} {
		if !slices.Contains(versions, version) {
			t.Errorf("no %s entry", version)
			continue
		}
		heading := regexp.MustCompile(`(?m)^## \[` + regexp.QuoteMeta(version) + `\] - .*$`)
		dated := heading.ReplaceAllString(text, "## ["+version+"] - 2026-11-02")
		notes, err := releaseNotes([]byte(dated), "v"+version)
		if err != nil {
			t.Errorf("%s: %v", version, err)
			continue
		}
		if !strings.Contains(string(notes), "### Added") {
			t.Errorf("the %s notes have no Added section:\n%s", version, notes)
		}
		if strings.Contains(string(notes), "](docs/") {
			t.Errorf("the %s notes keep a relative link, which a release page cannot resolve", version)
		}
	}
}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return n
}
