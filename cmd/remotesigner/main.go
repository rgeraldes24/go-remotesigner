// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Command remotesigner is a remote signing service for QRL validator clients.
//
// Usage: remotesigner [global flags] consensus [consensus flags], and in the
// default flavour remotesigner [global flags] execution [execution flags].
// The flags are defined in package flags and documented in
// docs/reference/flags.md. Exit codes: 0 after a clean shutdown, 2 for usage
// errors (including a missing --network and an invalid --config-file), 1 for
// startup failures.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/urfave/cli/v2"

	"github.com/rgeraldes24/go-remotesigner/cmd/remotesigner/flags"
)

// Exit codes: 2 for usage errors, 1 for startup failures.
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
	return runWith(args, stdout, stderr, nil)
}

// runWith is run with the signer's run function injected, for tests: a
// non-nil runSigner runs in place of every mode's own.
func runWith(args []string, stdout, stderr io.Writer, runSigner runFunc) int {
	err := newApp(stdout, stderr, runSigner).Run(args)
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

func newApp(stdout, stderr io.Writer, runSigner runFunc) *cli.App {
	pick := func(mode runFunc) runFunc {
		if runSigner != nil {
			return runSigner
		}
		return mode
	}
	v, _ := release()
	return &cli.App{
		Name:            binaryName,
		Usage:           "remote signer for QRL validator clients",
		Version:         versionString() + flavourNotice(v),
		Writer:          stdout,
		ErrWriter:       stderr,
		HideHelpCommand: true,
		Flags:           flags.Global(),
		Metadata:        map[string]any{},
		Before:          loadConfigFile,
		Commands:        append([]*cli.Command{consensusCommand(pick(defaultRun), stdout, stderr)}, flavourCommands(pick, stdout, stderr)...),
		Action:          rootAction,
		OnUsageError: func(_ *cli.Context, err error, _ bool) error {
			return cli.Exit(fmt.Sprintf("usage error: %v", err), exitUsage)
		},
		// run maps errors to exit codes; keep urfave/cli from calling os.Exit.
		ExitErrHandler: func(*cli.Context, error) {},
	}
}

// rootAction runs when no subcommand matches. It prints the help for a bare
// invocation or "help", the unstable options for Web3Signer's hidden
// "Xhelp", and reports anything else as a usage error instead of
// urfave/cli's default "No help topic" exit 3.
func rootAction(c *cli.Context) error {
	first := c.Args().First()
	switch {
	case !c.Args().Present(), first == "help" && c.NArg() == 1:
		return cli.ShowAppHelp(c)
	case first == xhelpCommand && c.NArg() == 1:
		printUnstableOptions(c.App.Writer, c.App)
		return nil
	case first == "help":
		return cli.Exit(fmt.Sprintf("usage error: help takes no arguments; run '%s --help' for usage", c.App.Name), exitUsage)
	default:
		return cli.Exit(fmt.Sprintf("usage error: unknown command %q; run '%s --help' for usage", first, c.App.Name), exitUsage)
	}
}

// versionString renders "<version> (commit <rev>, <go version>, <os>/<arch>)".
func versionString() string {
	v, c := release()
	return fmt.Sprintf("%s (commit %s, %s, %s/%s)", v, c, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

// release returns the version and commit: the link-time values, else those
// the Go toolchain recorded, else "dev" and "unknown".
func release() (v, c string) {
	info, _ := debug.ReadBuildInfo()
	return releaseFrom(version, commit, info)
}

// releaseFrom returns the version and commit from the link-time values v
// and c, else from info (nil when the binary has none). The module version
// the toolchain records for `go install …@v1.0.0` is the tag, v1.0.0; it is
// reported without its v, as the release binaries and `make build` report
// it.
func releaseFrom(v, c string, info *debug.BuildInfo) (string, string) {
	if info != nil {
		if v == "" && info.Main.Version != "" && info.Main.Version != "(devel)" {
			v = strings.TrimPrefix(info.Main.Version, "v")
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
	return v, c
}
