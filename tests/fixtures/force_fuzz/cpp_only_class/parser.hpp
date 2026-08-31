// SPDX-License-Identifier: Apache-2.0
#ifndef BHF_PARSER_HPP
#define BHF_PARSER_HPP

// This header intentionally does NOT declare class Parser. Parser is defined
// only in parser.cpp, so an external harness that #includes this header sees an
// undefined type for Parser::scan — the C++ ".cpp-only class" pre-build gate.
int bhf_parser_version(void);

#endif
