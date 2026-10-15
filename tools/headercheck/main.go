// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Command headercheck enforces the licence-header policy of DESIGN §6.2.
//
// It reads the machine-readable file table in PROVENANCE.md and checks every
// .go, .sql, .yaml, .yml, .sh, Dockerfile* and deploy/**/*.json file against
// the header class recorded for it:
//
//   - new: our copyright line and SPDX Apache-2.0, and no ConsenSys line;
//   - w3s-derived: a ConsenSys line, our line, SPDX Apache-2.0, a
//     "Modified by" line and a "Derived from" line naming the upstream paths;
//   - mit-derived: the original MIT copyright line, SPDX MIT and "Modified by";
//   - vendored: the directory must hash to the recorded git tree id, i.e. be
//     byte-identical to upstream.
//
// A checked file without a row, a row whose path is missing on disk, and any
// unrecorded file under third_party/ fail the run. JSON files carry their
// notice in a top-level "description" field.
//
// Usage:
//
//	go run ./tools/headercheck [-root dir] [-provenance file]
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	root := flag.String("root", ".", "repository root")
	prov := flag.String("provenance", "PROVENANCE.md", "provenance file, relative to -root")
	flag.Parse()

	res, err := check(*root, *prov)
	if err != nil {
		fmt.Fprintln(os.Stderr, "headercheck:", err)
		os.Exit(2)
	}
	for _, p := range res.problems {
		fmt.Fprintln(os.Stderr, p)
	}
	if len(res.problems) > 0 {
		fmt.Fprintf(os.Stderr, "headercheck: %d problem(s)\n", len(res.problems))
		os.Exit(1)
	}
	fmt.Printf("headercheck: %d files and %d vendored trees OK\n", res.files, res.trees)
}
