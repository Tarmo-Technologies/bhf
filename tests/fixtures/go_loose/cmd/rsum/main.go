// SPDX-License-Identifier: Apache-2.0
// A command outside every Go module, for the bhf Go lane. A `package main`
// cannot be imported, so bhf renames the package in its copy. Checksum is
// the fuzzable entry point; a planted bug divides by zero (CWE-369).
package main

import (
	"fmt"
	"os"
)

// Checksum folds the record into a sum, then divides by its declared width.
// A planted bug: a width digit of '0' divides by zero.
func Checksum(data []byte) int {
	if len(data) < 2 || data[0] != 'W' {
		return 0
	}
	sum := 0
	for _, b := range data[2:] {
		sum += int(b)
	}
	return sum / int(data[1]-'0')
}

func main() {
	fmt.Println(Checksum([]byte(os.Args[1])))
}
