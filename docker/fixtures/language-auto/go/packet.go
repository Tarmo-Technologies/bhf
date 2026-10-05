// SPDX-License-Identifier: Apache-2.0
package packet

func PacketChecksum(data []byte) uint32 {
    var result uint32
    for _, value := range data { result = (result + uint32(value)) % 251 }
    return result
}
