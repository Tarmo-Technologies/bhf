// SPDX-License-Identifier: Apache-2.0
//
// Fixture firmware that takes its input from a peripheral, not from a buffer
// in RAM: it checks the peripheral's ID register, then reads a length and
// the record from the receive data register, one byte per read, and parses
// the record byte by byte. A "FUZZW" record stores a byte at the offset it
// names, which nothing checks against the table it indexes.
//
//   PERIPH_ID    0x40013000  reads 0x4c31a5c3 on the real part
//   PERIPH_DATA  0x40013004  the receive FIFO: one byte per read
//
//   record: "FUZZ", a command, then for W a little-endian offset and a byte

#include <stdint.h>

#define PERIPH_ID (*(volatile uint32_t *)0x40013000u)
#define PERIPH_DATA (*(volatile uint8_t *)0x40013004u)
#define PERIPH_ID_VALUE 0x4c31a5c3u

uint8_t record[32];
uint8_t table[16];
volatile uint32_t result;
// 1: the ID register did not match; 2: a record was parsed.
volatile uint32_t state;

static uint32_t read_word(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 | (uint32_t)bytes[2] << 16 |
           (uint32_t)bytes[3] << 24;
}

__attribute__((noinline)) static uint32_t parse_record(const uint8_t *buf, uint32_t len) {
    if (len > 0 && buf[0] == 'F') {
        if (len > 1 && buf[1] == 'U') {
            if (len > 2 && buf[2] == 'Z') {
                if (len > 3 && buf[3] == 'Z') {
                    if (len > 4 && buf[4] == 'W' && len >= 10) {
                        table[read_word(buf + 5)] = buf[9];
                        return 5;
                    }
                    return 4;
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
    if (PERIPH_ID != PERIPH_ID_VALUE) {
        state = 1;
        for (;;) {
            __asm__ volatile("wfi");
        }
    }
    uint32_t len = PERIPH_DATA;
    if (len > sizeof(record)) {
        len = sizeof(record);
    }
    for (uint32_t i = 0; i < len; i++) {
        record[i] = PERIPH_DATA;
    }
    result = parse_record(record, len);
    state = 2;
    for (;;) {
        __asm__ volatile("wfi");
    }
}
