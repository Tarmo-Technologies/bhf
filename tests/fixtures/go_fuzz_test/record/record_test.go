// SPDX-License-Identifier: Apache-2.0

package record_test

import (
	"testing"

	"example.com/widget/record"
)

// FuzzParseRecord is an external test's fuzz test that calls a name only
// the package's internal test file defines.
func FuzzParseRecord(f *testing.F) {
	f.Add([]byte("R12"))
	f.Fuzz(func(t *testing.T, data []byte) {
		record.ParseRecord(data)
	})
}
