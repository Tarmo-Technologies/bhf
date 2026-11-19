// SPDX-License-Identifier: Apache-2.0
//
// Fixture firmware: a record parser that checks the input byte by byte, so a
// longer matching prefix reaches more of the code. The input arrives in
// rx_buf, with its length in rx_len.

#include <stdint.h>

uint8_t rx_buf[64];
volatile uint32_t rx_len;
volatile uint32_t result;
static const uint32_t weights[4] = {3, 5, 7, 11};
uint32_t scale = 2;

static uint32_t checksum(const uint8_t *buf, uint32_t len) {
    uint32_t sum = 0;
    for (uint32_t i = 0; i < len; i++) {
        sum += buf[i] * weights[i & 3] * scale;
    }
    return sum;
}

static uint32_t parse_record(const uint8_t *buf, uint32_t len) {
    if (len > 0 && buf[0] == 'F') {
        if (len > 1 && buf[1] == 'U') {
            if (len > 2 && buf[2] == 'Z') {
                if (len > 3 && buf[3] == 'Z') {
                    switch (len > 4 ? buf[4] : 0) {
                    case 'a':
                        return checksum(buf + 5, len - 5) / 3;
                    case 'b':
                        return checksum(buf, len) % 7;
                    case 'c':
                        return (uint32_t)((int32_t)checksum(buf, len) / -5);
                    case 'd':
                        return checksum(buf, len) << 3;
                    default:
                        return 4;
                    }
                }
                return 3;
            }
            return 2;
        }
        return 1;
    }
    return 0;
}

int main(void) {
    uint32_t len = rx_len;
    if (len > sizeof(rx_buf)) {
        len = sizeof(rx_buf);
    }
    result = parse_record(rx_buf, len);
    for (;;) {
        __asm__ volatile("wfi");
    }
}
