// SPDX-License-Identifier: Apache-2.0
//
// A record decoder with a planted bug: a record longer than 8 bytes takes a
// branch that names a codec nothing declares.
'use strict';

function decodeRecord(data) {
  if (data.length > 8) {
    return recordCodec.decode(data);
  }
  return data.length;
}

module.exports = { decodeRecord };
