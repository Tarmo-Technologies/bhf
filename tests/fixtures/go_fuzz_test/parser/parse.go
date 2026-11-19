// SPDX-License-Identifier: Apache-2.0

// Package parser reads widget records. It exports nothing bhf could harness
// itself: its only fuzz entry point is the project's own FuzzParse.
package parser

// parseHeader reads a record header: the magic "BHF", then a kind byte that
// indexes the kind table, and returns the kind's size, or -1 when data is no
// record. The planted bug: the kind byte is not checked against the table.
func parseHeader(data []byte) int {
	if len(data) < 4 || string(data[:3]) != "BHF" {
		return -1
	}
	sizes := [4]int{10, 20, 30, 40}
	return sizes[data[3]]
}
