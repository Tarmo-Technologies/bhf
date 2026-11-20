// SPDX-License-Identifier: Apache-2.0
//
// A frame reader with a planted bug: a frame without the BHF1 header takes
// the legacy branch, which names a decoder nothing declares. Every short
// input takes that branch; one that starts with the header does not.
'use strict';

function parseFrame(data) {
  const text = Buffer.from(data).toString('latin1');
  if (text.startsWith('BHF1')) {
    return text.length;
  }
  return legacyFrames.decode(text);
}

module.exports = { parseFrame };
