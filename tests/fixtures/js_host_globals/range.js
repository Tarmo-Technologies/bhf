// SPDX-License-Identifier: Apache-2.0
//
// A range reader with a planted bug: anything but a `low-high` pair of
// decimal numbers takes a branch that names a table nothing declares. Only a
// sample of the format, such as a seed file, shows an input that avoids it.
'use strict';

function parseRange(data) {
  const text = Buffer.from(data).toString('latin1');
  if (/^[0-9]+-[0-9]+$/.test(text)) {
    return text.split('-').length;
  }
  return rangeTable.lookup(text);
}

module.exports = { parseRange };
