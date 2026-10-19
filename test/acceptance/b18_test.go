// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package acceptance

import (
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystoretest"
)

// B18 (docs/benchmarks.md): the keymanager imports 100 standard-KDF
// keystores (Argon2id t=8, m=262144 KiB) within 100 × t_B10 / P + 10 s,
// with no write-deadline error. An import takes at most 64 keystores, so
// the 100 go in two requests, 64 and 36, one after the other; the time is
// from the first request to the second response. P and t_B10 are measured
// as for B11: the signer's standard-KDF concurrency, and the mean time of
// one decrypt when P run together in the test process, before the signer
// starts and after it stops, the larger of the two.
func TestB18KeymanagerImport(t *testing.T) {
	benchEnabled(t)
	const n, password = 100, "password"
	sealer, err := keystoretest.NewSealer(password, keystoretest.Standard)
	if err != nil {
		t.Fatal(err)
	}
	keystores := make([]string, n)
	for i := range n {
		ks, err := sealer.DepositCLI(keystoretest.Seed("b18", i), i, true)
		if err != nil {
			t.Fatal(err)
		}
		keystores[i] = string(ks)
	}
	p := expectedStandard()
	before := decryptTime(t, []byte(keystores[0]), password, p)

	s := startKM(t, options{})
	s.waitReady()
	if got := standardConcurrency(t, s); got != p {
		t.Fatalf("the signer runs %d standard decrypts at once; t(P) was measured at P = %d", got, p)
	}
	stop := make(chan struct{})
	peak := peakRSS(s.cmd.Process.Pid, stop)
	start := time.Now()
	var took []time.Duration
	for _, part := range [][2]int{{0, 64}, {64, n}} {
		begin := time.Now()
		pws := slices.Repeat([]string{password}, part[1]-part[0])
		code, r, out := s.km("POST", importBody(t, keystores[part[0]:part[1]], pws, ""))
		if code != 200 || !slices.Equal(r.statuses(), slices.Repeat([]string{"imported"}, part[1]-part[0])) {
			t.Fatalf("import of keystores %d-%d: %d %.500s", part[0], part[1], code, out)
		}
		took = append(took, time.Since(begin))
	}
	elapsed := time.Since(start)
	close(stop)
	peakKiB := <-peak
	if got := len(s.publicKeys()); got != n {
		t.Fatalf("%d keys loaded", got)
	}
	s.signal(syscall.SIGTERM)
	<-s.done
	after := decryptTime(t, []byte(keystores[0]), password, p)

	tB10 := max(before, after)
	bound := time.Duration(float64(n)*float64(tB10)/float64(p)) + 10*time.Second
	t.Logf("B18: %d standard keystores imported in %v (%v for 64, %v for 36) at P=%d; t(P) = %v (%v before, %v "+
		"after); bound 100·t/P + 10 s = %v; peak RSS %d MiB", n, elapsed.Round(time.Millisecond),
		took[0].Round(time.Millisecond), took[1].Round(time.Millisecond), p, tB10.Round(time.Millisecond),
		before.Round(time.Millisecond), after.Round(time.Millisecond), bound.Round(time.Second), peakKiB>>10)
	if elapsed > bound {
		t.Errorf("B18 missed: %v > %v", elapsed, bound)
	}
}
