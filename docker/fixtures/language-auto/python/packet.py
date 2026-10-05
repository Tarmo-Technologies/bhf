# SPDX-License-Identifier: Apache-2.0
def packet_checksum(data: bytes) -> int:
    return sum(data) % 251
