// SPDX-License-Identifier: Apache-2.0

package parser

import "testing"

// checkSize is a helper the fuzz test shares with the unit tests.
func checkSize(t *testing.T, size int) {
	t.Helper()
	if size == 0 {
		t.Fatal("a kind of size 0")
	}
}

func TestParseHeader(t *testing.T) {
	if got := parseHeader([]byte("BHF\x01")); got != 20 {
		t.Fatalf("parseHeader = %d, want 20", got)
	}
}
