// SPDX-License-Identifier: Apache-2.0
#include <stddef.h>
unsigned int packet_checksum(const unsigned char *data, size_t len) {
    unsigned int result = 0;
    for (size_t i = 0; i < len; ++i) result = (result + data[i]) % 251;
    return result;
}
