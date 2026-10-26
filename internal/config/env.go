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
// commandline/src/main/java/tech/pegasys/web3signer/commandline/valueprovider/EnvironmentVariableDefaultProvider.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package config

import "strings"

// EnvPrefix prefixes every environment variable.
const EnvPrefix = "REMOTESIGNER"

// EnvVars returns the environment variables of a flag: one per name and
// alias, as Web3Signer derives one from every name of an option, its
// one-letter alias included (-l of --logging is REMOTESIGNER_L):
// REMOTESIGNER_[<COMMAND>_]<NAME> with dashes as underscores, in upper case.
// command is "" for a global flag and "consensus" for a flag of that
// subcommand, so --http-listen-port is REMOTESIGNER_HTTP_LISTEN_PORT and
// consensus --network is REMOTESIGNER_CONSENSUS_NETWORK. A name that begins
// with its command's name does not repeat it: execution
// --execution-policy-file is REMOTESIGNER_EXECUTION_POLICY_FILE, not
// REMOTESIGNER_EXECUTION_EXECUTION_POLICY_FILE.
func EnvVars(command string, names ...string) []string {
	prefix := EnvPrefix + "_"
	if command != "" {
		prefix += envName(command) + "_"
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		n = strings.TrimLeft(n, "-")
		if rest, ok := strings.CutPrefix(n, command+"-"); command != "" && ok && rest != "" {
			n = rest
		}
		out = append(out, prefix+envName(n))
	}
	return out
}

func envName(s string) string {
	return strings.ToUpper(strings.ReplaceAll(s, "-", "_"))
}
