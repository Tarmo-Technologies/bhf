// SPDX-License-Identifier: Apache-2.0
// MatchFilter is no Must function, yet it hands its input to
// regexp.MustCompile, which panics on a pattern that does not compile. A
// caller's filter string reaches that panic: a defect in MatchFilter, not
// MustCompile's documented contract.
package hashspec

import "regexp"

// MatchFilter reports whether a widget name matches a filter pattern.
func MatchFilter(filter string) bool {
	return regexp.MustCompile(filter).MatchString("widget")
}
