// SPDX-License-Identifier: Apache-2.0
// Fixture for the Go `--force` path: Feed still needs a synthesized receiver,
// while Render's plain-data map is driven from a JSON field without force.
//   * Feed is a method, so it needs a receiver value.
//   * Render takes raw bytes and a JSON-decodable map.
// Each carries a planted out-of-bounds read (CWE-125) reachable from the input
// bytes alone, so a harness that really executes the target can find it.
package forcelib

// Option is an exported data-only type used in Render's map parameter.
type Option struct {
	Name string
}

// Decoder is the method receiver. Its zero value is usable, so a forced harness
// can call Feed without a constructor.
type Decoder struct {
	Limit int
}

// Feed reads a length-prefixed body. Planted bug: on tag 'M' it indexes past the
// slice without checking the length.
func (d *Decoder) Feed(data []byte) int {
	if len(data) == 0 {
		return d.Limit
	}
	if data[0] == 'M' {
		return int(data[1]) + int(data[2]) + int(data[3]) + int(data[4])
	}
	return len(data)
}

// Render takes a JSON-decodable map alongside the fuzz bytes. Planted bug:
// on tag 'R' it indexes past the slice.
func Render(data []byte, opts map[string]Option) int {
	if len(data) == 0 {
		return len(opts)
	}
	if data[0] == 'R' {
		return int(data[1]) + int(data[2]) + int(data[3]) + int(data[4])
	}
	return len(data) + len(opts)
}
