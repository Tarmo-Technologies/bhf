// SPDX-License-Identifier: Apache-2.0
#include <string>
unsigned int packet_checksum(const std::string &data) {
    unsigned int result = 0;
    for (unsigned char value : data) result = (result + value) % 251;
    return result;
}
