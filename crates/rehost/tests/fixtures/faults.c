// SPDX-License-Identifier: Apache-2.0
//
// Fixture firmware with one fault of each class behind a command byte. The
// input arrives in rx_buf with its length in rx_len: "FUZZ", a command, and
// for W, R and J a little-endian address.
//
//   W addr  store a word at addr          (invalid access when unmapped)
//   R addr  load a word from addr         (invalid access when unmapped)
//   J addr  call the function at addr     (bad PC)
//   U       execute UDF                   (HardFault)
//   D n     divide by n, with the trap on (HardFault when n is 0)

#include <stdint.h>

uint8_t rx_buf[64];
volatile uint32_t rx_len;
volatile uint32_t sink;

typedef void (*handler_fn)(void);

static uint32_t read_word(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 | (uint32_t)bytes[2] << 16 |
           (uint32_t)bytes[3] << 24;
}

__attribute__((noinline)) static void copy_at(uint32_t address, uint32_t value) {
    *(volatile uint32_t *)address = value;
}

__attribute__((noinline)) static void parse_record(const uint8_t *buf, uint32_t len) {
    if (len < 5 || buf[0] != 'F' || buf[1] != 'U' || buf[2] != 'Z' || buf[3] != 'Z') {
        return;
    }
    uint32_t operand = len >= 9 ? read_word(buf + 5) : 0;
    switch (buf[4]) {
    case 'W':
        copy_at(operand, 0x11223344u);
        break;
    case 'R':
        sink = *(volatile uint32_t *)operand;
        break;
    case 'J':
        ((handler_fn)operand)();
        break;
    case 'U':
        __builtin_trap();
    case 'D':
        sink = 1000u / (len > 5 ? buf[5] : 1u);
        break;
    default:
        sink = buf[4];
        break;
    }
}

int main(void) {
    // CCR.DIV_0_TRP: divide by zero faults instead of giving zero.
    *(volatile uint32_t *)0xe000ed14u |= 1u << 4;
    uint32_t len = rx_len;
    if (len > sizeof(rx_buf)) {
        len = sizeof(rx_buf);
    }
    parse_record(rx_buf, len);
    for (;;) {
        __asm__ volatile("wfi");
    }
}
