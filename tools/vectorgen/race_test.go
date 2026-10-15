// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build race

package main

// raceEnabled is true under the race detector, which makes full generation
// too slow for a test.
const raceEnabled = true
