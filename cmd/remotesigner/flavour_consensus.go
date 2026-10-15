// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build noexecution

package main

// binaryName is the name of the consensus-only flavour, built with
// -tags noexecution. It links permissively licensed code only.
const binaryName = "remotesigner-consensus"
