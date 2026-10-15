// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Command remotesigner is a remote signing service for QRL validator clients.
//
// This is the bootstrap skeleton: it only reports its version. The consensus
// subcommand and its flags arrive with the server milestones.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"

	"github.com/urfave/cli/v2"
)

// Exit codes (DESIGN §3.9): 2 for usage errors, 1 for startup failures.
const (
	exitOK      = 0
	exitStartup = 1
	exitUsage   = 2
)

// version and commit are set at link time by the Makefile:
//
//	-ldflags "-X main.version=<version> -X main.commit=<commit>"
//
// When they are left unset, the module version and VCS revision recorded by
// the Go toolchain are used instead, so `go install` builds still identify
// themselves.
var (
	version = ""
	commit  = ""
)

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}

// run executes the CLI and maps its outcome to a process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	err := newApp(stdout, stderr).Run(args)
	if err == nil {
		return exitOK
	}
	_, _ = fmt.Fprintln(stderr, err)
	var coder cli.ExitCoder
	if errors.As(err, &coder) {
		return coder.ExitCode()
	}
	return exitStartup
}

func newApp(stdout, stderr io.Writer) *cli.App {
	return &cli.App{
		Name:            binaryName,
		Usage:           "remote signer for QRL validator clients",
		Version:         versionString(),
		Writer:          stdout,
		ErrWriter:       stderr,
		HideHelpCommand: true,
		OnUsageError: func(_ *cli.Context, err error, _ bool) error {
			return cli.Exit(fmt.Sprintf("usage error: %v", err), exitUsage)
		},
		// run maps errors to exit codes; keep urfave/cli from calling os.Exit.
		ExitErrHandler: func(*cli.Context, error) {},
	}
}

// versionString renders "<version> (commit <rev>, <go version>, <os>/<arch>)".
func versionString() string {
	v, c := version, commit
	if info, ok := debug.ReadBuildInfo(); ok {
		if v == "" && info.Main.Version != "" && info.Main.Version != "(devel)" {
			v = info.Main.Version
		}
		for _, s := range info.Settings {
			if c == "" && s.Key == "vcs.revision" {
				c = s.Value
			}
		}
	}
	if v == "" {
		v = "dev"
	}
	if c == "" {
		c = "unknown"
	}
	return fmt.Sprintf("%s (commit %s, %s, %s/%s)", v, c, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
