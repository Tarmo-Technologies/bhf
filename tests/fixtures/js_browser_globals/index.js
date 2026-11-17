// SPDX-License-Identifier: Apache-2.0
//
// A browser-oriented module: it reads `navigator.userAgent` as it loads, which
// Node 20 does not define, and its header parser has a planted bug.
'use strict';

const agent = navigator.userAgent.split(' ')[0];

function parseHeader(input) {
  const parts = String(input).split(':');
  if (parts[0].startsWith('U') && parts.length < 2) {
    // Planted: a `U...` header with no `:` is not handled.
    throw new Error(`unparsed ${agent} header`);
  }
  return parts.length;
}

module.exports = { parseHeader };
