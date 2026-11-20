// SPDX-License-Identifier: Apache-2.0
//
// Written for a host that injects `hostApp` (an embedding runtime, an
// extension host). Under Node every call stops at the missing global before
// the input is used.
'use strict';

function readUpload(data) {
  const store = hostApp.uploads;
  return store.save(data);
}

module.exports = { readUpload };
