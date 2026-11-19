// SPDX-License-Identifier: Apache-2.0
//
// Fixture firmware that talks over a polled UART, the way a bare-metal
// driver does: it waits for the transmit-empty bit before each byte it
// sends and for the receive-not-empty bit before each byte it reads. It
// sends a prompt, then reads newline-terminated lines and parses each one.
// A "FUZZC" line copies as many bytes as its sixth byte says into an 8-byte
// field on the stack, which nothing checks.
//
//   USART_SR  0x40011000  bit 5 RXNE (a byte has arrived), bit 7 TXE
//   USART_DR  0x40011004  the received byte, or the byte to send
//
//   line: "FUZZ", a command, then for C a length and that many bytes

#include <stdint.h>

#define USART_SR (*(volatile uint32_t *)0x40011000u)
#define USART_DR (*(volatile uint32_t *)0x40011004u)
#define SR_RXNE (1u << 5)
#define SR_TXE (1u << 7)

uint8_t line[48];
volatile uint32_t result;
volatile uint32_t lines;

__attribute__((noinline)) static void uart_putc(uint8_t byte) {
    while (!(USART_SR & SR_TXE)) {
    }
    USART_DR = byte;
}

__attribute__((noinline)) static uint8_t uart_getc(void) {
    while (!(USART_SR & SR_RXNE)) {
    }
    return (uint8_t)USART_DR;
}

__attribute__((noinline)) static void copy_bytes(uint8_t *dst, const uint8_t *src, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) {
        dst[i] = src[i];
    }
}

__attribute__((noinline)) static uint32_t parse_line(const uint8_t *buf, uint32_t len) {
    uint8_t field[8];
    if (len < 6 || buf[0] != 'F' || buf[1] != 'U' || buf[2] != 'Z' || buf[3] != 'Z') {
        return 0;
    }
    if (buf[4] != 'C') {
        return 1;
    }
    uint32_t n = buf[5];
    if (n > len - 6) {
        n = len - 6;
    }
    copy_bytes(field, buf + 6, n);
    return 2u + field[0] + field[7];
}

int main(void) {
    uart_putc('>');
    for (;;) {
        uint32_t len = 0;
        for (;;) {
            uint8_t byte = uart_getc();
            if (byte == '\n' || len == sizeof(line)) {
                break;
            }
            line[len++] = byte;
        }
        result = parse_line(line, len);
        lines++;
        uart_putc(result > 1 ? '!' : '.');
    }
}
