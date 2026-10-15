// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Command vectorgen generates the golden vectors under testdata/vectors and
// checks a running signer against them, using qrysm's own code as the
// oracle.
//
// It is a separate module that links qrysm (GPL-3.0), so the built tool is a
// GPL-3.0 combined work: it is a development tool, never shipped, and never
// imported by the signer module (see README.md). Its output is data,
// dedicated to the public domain under CC0-1.0.
//
// Usage:
//
//	vectorgen gen [-repo dir]
//	vectorgen verify -signer http://127.0.0.1:9000 [-token-file file] [-vectors dir]
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: vectorgen gen [-repo dir] | verify -signer url [-token-file file] [-vectors dir]")
		return 2
	}
	switch args[0] {
	case "gen":
		return runGen(args[1:], stdout, stderr)
	case "verify":
		return runVerifyCmd(args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "vectorgen: unknown command %q\n", args[0])
		return 2
	}
}

// defaultRepo is the signer repository that contains the working directory.
func defaultRepo() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	repo, err := findRepo(wd)
	if err != nil {
		return "."
	}
	return repo
}

func runGen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	repo := fs.String("repo", defaultRepo(), "go-remotesigner repository root to write into")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := generate(*repo); err != nil {
		_, _ = fmt.Fprintln(stderr, "vectorgen gen:", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "vectorgen: wrote", filepath.Join(*repo, "testdata", "vectors"), "and internal/network/embedded")
	return 0
}

func runVerifyCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	signer := fs.String("signer", "http://127.0.0.1:9000", "base URL of the running signer")
	tokenFile := fs.String("token-file", "", "file holding the sign-scope bearer token")
	vectors := fs.String("vectors", filepath.Join(defaultRepo(), "testdata", "vectors"), "fixture directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	var token string
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, "vectorgen verify:", err)
			return 2
		}
		token = strings.TrimSpace(string(b))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	res, err := runVerify(ctx, *signer, token, *vectors, stdout)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "vectorgen verify:", err)
		return 1
	}
	for _, f := range res.failures {
		_, _ = fmt.Fprintln(stderr, "FAIL:", f)
	}
	_, _ = fmt.Fprintf(stdout, "verify: %d passed, %d skipped, %d failed\n", res.passed, res.skipped, len(res.failures))
	if len(res.failures) > 0 {
		return 1
	}
	return 0
}
