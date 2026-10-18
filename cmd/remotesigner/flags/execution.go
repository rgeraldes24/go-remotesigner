// Copyright 2020 ConsenSys AG.
// Copyright 2026 The go-remotesigner Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//
// Modified by The go-remotesigner Authors, 2026: translated from Java to Go and adapted for QRL.
// Derived from Web3Signer
// commandline/src/main/java/tech/pegasys/web3signer/commandline/subcommands/Eth1SubCommand.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package flags

import "github.com/urfave/cli/v2"

// Execution flag names. The definitions build in both flavours, so that the
// reference documents them; only the default flavour has the command.
const (
	ExecutionCommand             = "execution"
	DownstreamHTTPHost           = "downstream-http-host"
	DownstreamHTTPPort           = "downstream-http-port"
	DownstreamHTTPPath           = "downstream-http-path"
	DownstreamHTTPRequestTimeout = "downstream-http-request-timeout"
	DownstreamHTTPAuthHeaderFile = "downstream-http-auth-header-file"
	DownstreamHTTPTLSEnabled     = "downstream-http-tls-enabled"
	DownstreamHTTPTLSCAFile      = "downstream-http-tls-ca-file"
	DownstreamHTTPProxyHost      = "downstream-http-proxy-host"
	DownstreamHTTPProxyPort      = "downstream-http-proxy-port"
	ExecutionProxyAllowedMethods = "execution-proxy-allowed-methods"
)

// Execution defaults, Web3Signer's for the downstream node.
const (
	DefaultDownstreamHost      = "127.0.0.1"
	DefaultDownstreamPort      = 8545
	DefaultDownstreamPath      = "/"
	DefaultDownstreamTimeoutMS = 5000
	DefaultDownstreamProxyPort = 80
)

// DefaultAllowedMethods is the default of --execution-proxy-allowed-methods.
var DefaultAllowedMethods = []string{"qrl_*", "net_*", "web3_*"}

// Execution returns the flags of the execution subcommand.
func Execution() []cli.Flag {
	return withEnv(ExecutionCommand, []cli.Flag{
		&cli.StringFlag{Name: DownstreamHTTPHost, Value: DefaultDownstreamHost, Usage: "Host of the gqrl node that forwarded requests go to"},
		&cli.UintFlag{Name: DownstreamHTTPPort, Value: DefaultDownstreamPort, Usage: "HTTP JSON-RPC port of the gqrl node"},
		&cli.StringFlag{Name: DownstreamHTTPPath, Value: DefaultDownstreamPath, Usage: "Path on the gqrl node that requests are posted to; a plain URL path"},
		&cli.UintFlag{Name: DownstreamHTTPRequestTimeout, Value: DefaultDownstreamTimeoutMS, Usage: "Milliseconds to wait for the node to connect, complete TLS and send its response headers; it is then answered with 504"},
		&cli.StringFlag{Name: DownstreamHTTPAuthHeaderFile, Usage: "File whose first line is the Authorization header value sent to the node (for example \"Bearer <token>\"), in place of any client credential; a secret file, read at startup", TakesFile: true},
		&cli.BoolFlag{Name: DownstreamHTTPTLSEnabled, Usage: "Connect to the node over TLS (https), verifying its certificate against the system roots or --downstream-http-tls-ca-file"},
		&cli.StringFlag{Name: DownstreamHTTPTLSCAFile, Usage: "PEM CAs that replace the system roots for the node's certificate; needs --downstream-http-tls-enabled", TakesFile: true},
		&cli.StringFlag{Name: DownstreamHTTPProxyHost, Usage: "HTTP proxy host to reach the node through; unset connects directly (proxy environment variables are never read)"},
		&cli.UintFlag{Name: DownstreamHTTPProxyPort, Value: DefaultDownstreamProxyPort, Usage: "Port of --downstream-http-proxy-host"},
		&cli.StringSliceFlag{Name: ExecutionProxyAllowedMethods, Value: cli.NewStringSlice(DefaultAllowedMethods...), Usage: "JSON-RPC methods forwarded to the node: names, prefixes ending in * (qrl_*), or * for all; the others get -32601. Applies to every element of a batch; the signer's own methods are never forwarded."},
		&cli.StringFlag{Name: KeystoresPath, Usage: "Directory of go-qrl account keystores to load: every non-hidden *.json file in it", TakesFile: true},
		&cli.StringFlag{Name: KeystoresPasswordFile, Usage: "File holding the password of every keystore in --keystores-path; not with --keystores-passwords-path", TakesFile: true},
		&cli.StringFlag{Name: KeystoresPasswordsPath, Usage: "Directory of password files, <name>.txt for keystore <name>.json; not with --keystores-password-file", TakesFile: true},
	})
}
