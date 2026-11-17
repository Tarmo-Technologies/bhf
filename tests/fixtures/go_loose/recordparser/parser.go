// SPDX-License-Identifier: Apache-2.0
// A GOPATH-era package for the bhf Go lane: there is no go.mod above it, so
// bhf copies it into a module of its own. ParseRecord is the fuzzable entry
// point; a crafted first byte drives an out-of-bounds index (CWE-125).
package recordparser

// ParseRecord parses a tagged record. A planted bug: on tag 'A' it reads
// five bytes past the tag without checking the length.
func ParseRecord(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	if data[0] == 'A' {
		return int(data[1]) + int(data[2]) + int(data[3]) + int(data[4]) + int(data[5])
	}
	return len(data)
}
