// SPDX-License-Identifier: Apache-2.0
function packet_checksum(data) {
    let result = 0;
    for (let i = 0; i < data.length; ++i) result = (result + data.charCodeAt(i)) % 251;
    return result;
}
module.exports = { packet_checksum };
