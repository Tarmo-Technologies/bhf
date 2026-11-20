// SPDX-License-Identifier: Apache-2.0

// Package codec measures length-prefixed widget fields.
package codec

// FieldLen returns how many bytes of data the field at its start takes: one
// length byte and that many bytes, at most what data holds. The planted bug:
// a field whose length byte is 'W', followed by 'X', is measured from the
// wrong end and claims more bytes than data holds. It panics nowhere: only
// the fuzz test's own check catches it.
func FieldLen(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	n := int(data[0])
	if data[0] == 'W' && len(data) > 1 && data[1] == 'X' {
		return n + len(data)
	}
	if n > len(data)-1 {
		n = len(data) - 1
	}
	return n + 1
}
