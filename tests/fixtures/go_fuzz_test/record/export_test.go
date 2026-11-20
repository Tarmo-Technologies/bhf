// SPDX-License-Identifier: Apache-2.0

package record

import "testing"

// ParseRecord exports parseRecord to the package's external tests, as Go's
// export_test.go idiom does.
var ParseRecord = parseRecord

func TestParseRecord(t *testing.T) {
	if got := parseRecord([]byte("R1")); got != 20 {
		t.Fatalf("parseRecord = %d, want 20", got)
	}
}
