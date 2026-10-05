// SPDX-License-Identifier: Apache-2.0
export function packet_checksum(data: string): number {
    let result = 0;
    for (let i = 0; i < data.length; ++i) result = (result + data.charCodeAt(i)) % 251;
    return result;
}
