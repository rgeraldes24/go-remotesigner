// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package secretstest

import (
	"os"
	"strings"
	"testing"
)

// EnvCloudRequired, set to 1 by make test-cloud (and so in the CI job
// cloud-secrets), makes a test against a real store fail, not skip, when
// the environment that points it at the store is missing: a renamed
// variable cannot leave the job green with nothing run.
const EnvCloudRequired = "REMOTESIGNER_TEST_CLOUD_REQUIRED"

// CloudEnv returns the values of the environment variables names, which
// point a test at a real store. When one is empty it skips t, or fails it
// under EnvCloudRequired=1; how says how to set them.
func CloudEnv(t testing.TB, how string, names ...string) []string {
	t.Helper()
	values := make([]string, len(names))
	var missing []string
	for i, n := range names {
		if values[i] = os.Getenv(n); values[i] == "" {
			missing = append(missing, n)
		}
	}
	if len(missing) == 0 {
		return values
	}
	if os.Getenv(EnvCloudRequired) == "1" {
		t.Fatalf("%s=1 but %s not set (%s)", EnvCloudRequired, strings.Join(missing, ", "), how)
	}
	t.Skipf("set %s to run against a real store (%s)", strings.Join(names, ", "), how)
	return nil
}
