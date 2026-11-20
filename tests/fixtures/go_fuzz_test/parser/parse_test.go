// SPDX-License-Identifier: Apache-2.0

package parser

import "testing"

// FuzzParse is the project's native fuzz test. Its seed corpus holds a valid
// record one byte away from the planted bug.
func FuzzParse(f *testing.F) {
	f.Add([]byte("hello"))
	f.Fuzz(func(t *testing.T, data []byte) {
		checkSize(t, parseHeader(data))
	})
}
