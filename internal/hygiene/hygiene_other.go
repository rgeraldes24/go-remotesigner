// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package hygiene

const supported = false

func apply(Config) error { return nil }

func state() (bool, uint64, error) { return false, 0, ErrUnsupported }
