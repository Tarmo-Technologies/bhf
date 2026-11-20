// SPDX-License-Identifier: Apache-2.0
// The package under test. It is sound; it imports a dependency whose init
// panics on this toolchain.
package widget

import "bhf.example/initpanic/legacycodec"

// ParseWidget parses a widget record and returns its checksum.
func ParseWidget(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	return legacycodec.Checksum(data[1:])
}
