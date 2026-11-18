// SPDX-License-Identifier: Apache-2.0
//
// Touches `window` only when called.
'use strict';

function widthFor(input) {
  const text = String(input);
  return Math.min(window.innerWidth || 800, text.length * 8);
}

module.exports = { widthFor };
