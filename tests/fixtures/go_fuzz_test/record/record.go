// SPDX-License-Identifier: Apache-2.0

// Package record measures widget records. Its parser is unexported: the
// package's external fuzz test reaches it through the name export_test.go
// gives it.
package record

// parseRecord returns the average width of a record's fields, in tenths of
// a byte: an 'R', then the fields, one byte each. The planted bug: a record
// of no fields divides by zero.
func parseRecord(data []byte) int {
	if len(data) == 0 || data[0] != 'R' {
		return -1
	}
	return len(data) * 10 / (len(data) - 1)
}
