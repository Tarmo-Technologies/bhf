// SPDX-License-Identifier: Apache-2.0
// A hash-spec parser in the shape Go libraries ship one. ParseHash returns an
// error for input it rejects; MustParseHash, meant for constants, panics on
// that error, which is its documented behaviour and not a defect. The same
// goes for template.Must in RenderPage. MustParseTag has a planted bug in its
// own body: a short `#` tag is sliced past its end.
package hashspec

import (
	"errors"
	"strings"
	"text/template"
)

// Hash is a parsed "scheme:digest" spec.
type Hash struct {
	Scheme string
	Digest string
}

// ParseHash parses a "scheme:digest" spec.
func ParseHash(s string) (Hash, error) {
	scheme, digest, ok := strings.Cut(s, ":")
	if !ok || scheme == "" || digest == "" {
		return Hash{}, errors.New("hashspec: want scheme:digest")
	}
	return Hash{Scheme: scheme, Digest: digest}, nil
}

// MustParseHash is like ParseHash but panics if s cannot be parsed. It
// simplifies initializing package variables from constants.
func MustParseHash(s string) Hash {
	h, err := ParseHash(s)
	if err != nil {
		panic(err)
	}
	return h
}

// MustParseTag parses a "#ab" tag and panics on any other input.
func MustParseTag(s string) string {
	if strings.HasPrefix(s, "#") {
		// Planted bug: a tag shorter than "#ab" is sliced past its end.
		return s[1:3]
	}
	panic("hashspec: want a #tag")
}

// RenderPage compiles a page template whose actions are written <like this>.
// The template is part of the program, so a bad one panics.
func RenderPage(text string) *template.Template {
	return template.Must(template.New("page").Delims("<", ">").Parse(text))
}
