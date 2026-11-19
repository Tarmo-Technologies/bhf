// SPDX-License-Identifier: Apache-2.0

package codec_test

import (
	"testing"

	"example.com/widget/codec"
)

// FuzzFieldLen is an external test's fuzz test with two arguments; it fails
// through t.Fatalf, not a panic.
func FuzzFieldLen(f *testing.F) {
	f.Add([]byte("WA"), 2)
	f.Fuzz(func(t *testing.T, data []byte, limit int) {
		if n := codec.FieldLen(data); n > len(data) {
			t.Fatalf("FieldLen took %d bytes of %d", n, len(data))
		}
		_ = limit
	})
}
