// SPDX-License-Identifier: Apache-2.0
//
// Tests for a browser before it uses one: it needs no stand-ins.
'use strict';

function describe(input) {
  const where = typeof window === 'undefined' ? 'server' : 'browser';
  return `${where}:${String(input).length}`;
}

module.exports = { describe };
