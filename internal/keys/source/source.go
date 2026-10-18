// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package source holds what the key loaders share: the version of a source
// that lets a reload skip an unchanged one, and the worker pool that loads
// sources in parallel.
package source

import (
	"context"
	"io/fs"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RacyWindow is how recently a file may have been modified for its version
// to be trusted. A file written again within the timestamp granularity of
// its file system (up to two seconds on some) can keep its size and
// modification time, so a file modified less than RacyWindow before the
// load started gets no version and is loaded again next time.
const RacyWindow = 2 * time.Second

// Version is the version of a source made of the files fis, in order: each
// file's size and modification time. It is "" (never unchanged) when a file
// was modified less than RacyWindow before start.
func Version(start time.Time, fis ...fs.FileInfo) string {
	var b strings.Builder
	for i, fi := range fis {
		if fi.ModTime().After(start.Add(-RacyWindow)) {
			return ""
		}
		if i > 0 {
			b.WriteByte(';')
		}
		b.WriteString(strconv.FormatInt(fi.Size(), 10))
		b.WriteByte('@')
		b.WriteString(strconv.FormatInt(fi.ModTime().UnixNano(), 10))
	}
	return b.String()
}

// Unchanged reports whether a source is loaded at a version, so that the
// loader keeps its keys instead of loading it again.
type Unchanged func(source, version string) bool

// ProgressInterval is how often Each reports progress.
const ProgressInterval = 30 * time.Second

// Each calls fn(i) for every i in [0, n) on up to workers goroutines and
// returns when all calls have returned. fn handles ctx itself. When report
// is not nil and the work takes longer than ProgressInterval, report is
// called every interval with the number of calls done.
func Each(ctx context.Context, n, workers int, fn func(i int), report func(done, total int)) {
	workers = max(1, min(workers, n))
	var (
		next, done atomic.Int64
		wg         sync.WaitGroup
	)
	finished := make(chan struct{})
	if report != nil {
		go func() {
			t := time.NewTicker(ProgressInterval)
			defer t.Stop()
			for {
				select {
				case <-finished:
					return
				case <-ctx.Done():
					return
				case <-t.C:
					report(int(done.Load()), n)
				}
			}
		}()
	}
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1) - 1)
				if i >= n {
					return
				}
				fn(i)
				done.Add(1)
			}
		}()
	}
	wg.Wait()
	close(finished)
}
