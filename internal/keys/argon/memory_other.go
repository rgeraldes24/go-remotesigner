// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package argon

func cgroupLimit() (int64, bool) { return 0, false }

func totalRAM() (uint64, bool) { return 0, false }
