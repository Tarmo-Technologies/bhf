// SPDX-License-Identifier: Apache-2.0
//
// A browser-oriented module: it reads `location.hostname` as it loads, which
// no Node defines (Node 21 and later define `navigator`, so a module that
// reads only that loads there without a stand-in), and its header parser has
// a planted bug.
'use strict';

const host = location.hostname;

function parseHeader(input) {
  const parts = String(input).split(':');
  if (parts[0].startsWith('U') && parts.length < 2) {
    // Planted: a `U...` header with no `:` is not handled.
    throw new Error(`unparsed ${host} header`);
  }
  return parts.length;
}

module.exports = { parseHeader };
