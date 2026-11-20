// SPDX-License-Identifier: Apache-2.0
// A dependency whose package init refuses the running toolchain, the way a
// library tied to one Go release checks a runtime layout as it loads. Every
// program that imports it panics before main runs, so no input ever reaches
// the code that imports it.
package legacycodec

import (
	"runtime"
	"strings"
)

// The only Go release whose session state layout this package matches.
const layoutRelease = "go1.15"

func init() {
	if !strings.HasPrefix(runtime.Version(), layoutRelease+".") {
		panic("legacycodec: session state layout doesn't match " + runtime.Version())
	}
}

// Checksum sums the bytes of a record.
func Checksum(data []byte) int {
	sum := 0
	for _, b := range data {
		sum += int(b)
	}
	return sum
}
