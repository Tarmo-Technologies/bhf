// SPDX-License-Identifier: Apache-2.0
// The project's own fuzz test of ParseWidget: a provided harness, which the
// dependency's init stops just the same.
package widget

import "testing"

func FuzzParseWidget(f *testing.F) {
	f.Add([]byte("W1"))
	f.Fuzz(func(t *testing.T, data []byte) {
		ParseWidget(data)
	})
}
