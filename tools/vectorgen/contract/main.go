// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Command contract is the contract mode of vectorgen. It drives a running
// signer with qrysm's own remote-web3signer keymanager, the client the
// qrysm validator signs through, and checks every answer with qrysm's
// verifiers:
//
//   - CheckCapabilities, against the network's qrysm configuration, its
//     genesis validators root and the genesis time;
//   - FetchValidatingPublicKeys, through the signer's publicKeys URL;
//   - one Sign per SignRequest oneof, which covers the nine artifact types,
//     each signature checked with ml_dsa_87.VerifySignature over the signing
//     root qrysm computed; the epoch oneof must be refused by the client;
//   - one RandaoReveal, checked with randao.Verify.
//
// Both sides decode strictly: the signer refuses an unknown request field,
// the client an unknown response field. A DTO renamed on one side alone
// therefore fails here, even when that side's own tests were updated to
// match.
//
// It is a module of its own, apart from tools/vectorgen, because it needs
// another qrysm commit: the revived keymanager is not on the commit the
// golden vectors are generated from (see ../README.md). Like vectorgen it
// links qrysm (GPL-3.0), so a built binary is a GPL-3.0 combined work: it is
// a development tool, never shipped, and the signer module never imports
// it.
//
// Usage:
//
//	contract -signer http://127.0.0.1:9000 [-token-file file] [-network end-to-end]
//	         [-genesis-time 1760000000] [-vectors dir]
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/theQRL/qrysm/config/params"
)

// fixtureGenesisTime is the genesis time of the contract's worked examples
// and of the golden vectors.
const fixtureGenesisTime = 1760000000

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("contract", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o options
	fs.StringVar(&o.signer, "signer", "http://127.0.0.1:9000", "base URL of the running signer")
	fs.StringVar(&o.tokenFile, "token-file", "", "file holding the sign-scope bearer token")
	fs.StringVar(&o.network, "network", params.EndToEndName,
		"the signer's network: "+params.EndToEndName+" or "+params.EndToEndMainnetName)
	fs.Uint64Var(&o.genesisTime, "genesis-time", fixtureGenesisTime, "the chain's genesis time, as the signer knows it (unix seconds)")
	fs.StringVar(&o.vectors, "vectors", filepath.Join(defaultRepo(), "testdata", "vectors"), "golden vector directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "contract: unexpected argument %q\n", fs.Arg(0))
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	res, err := runContract(ctx, o, stdout)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "contract:", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "contract: %d passed, %d failed\n", res.passed, len(res.failed))
	if len(res.failed) > 0 {
		return 1
	}
	return 0
}

// defaultRepo is the signer repository that contains the working directory,
// or "." when there is none.
func defaultRepo() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	for d := wd; ; d = filepath.Dir(d) {
		b, err := os.ReadFile(filepath.Join(d, "go.mod"))
		if err == nil && strings.HasPrefix(string(b), "module github.com/rgeraldes24/go-remotesigner\n") {
			return d
		}
		if filepath.Dir(d) == d {
			return "."
		}
	}
}

// qrysmModule names the qrysm this tool was built with, after go.mod's
// replace directive.
func qrysmModule() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, d := range bi.Deps {
		if d.Path != "github.com/theQRL/qrysm" {
			continue
		}
		if d.Replace != nil {
			return d.Replace.Path + "@" + d.Replace.Version
		}
		return d.Path + "@" + d.Version
	}
	return "unknown"
}
