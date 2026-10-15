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
// core/src/main/java/tech/pegasys/web3signer/core/Runner.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package server

import (
	"fmt"
	"os"
	"path/filepath"
)

// PortsFileName is the ports file written into --data-path.
const PortsFileName = "remotesigner.ports"

// WritePortsFile writes the bound ports to <dataPath>/remotesigner.ports in
// Java properties form ("http-port=9000", and "metrics-port=9001" when
// metricsPort is not 0, that is when the metrics listener runs), so that a
// harness that started the signer on port 0 can find it. The caller removes
// the file on shutdown.
func WritePortsFile(dataPath string, httpPort, metricsPort int) (string, error) {
	path := filepath.Join(dataPath, PortsFileName)
	content := fmt.Sprintf("# This file contains the ports used by the running instance of remotesigner. "+
		"It is deleted when remotesigner shuts down.\nhttp-port=%d\n", httpPort)
	if metricsPort != 0 {
		content += fmt.Sprintf("metrics-port=%d\n", metricsPort)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", fmt.Errorf("server: write ports file: %w", err)
	}
	return path, nil
}
