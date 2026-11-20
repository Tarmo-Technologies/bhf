// SPDX-License-Identifier: Apache-2.0
//
// Fixture firmware driven by its UART's receive interrupt, as most
// bare-metal drivers are: main turns on the receiver and its interrupt, then
// sleeps in WFI, and only the interrupt handler touches the UART. The
// handler collects the bytes of a frame up to a newline and hands the frame
// to its parser, so the parser runs only from the handler: with no
// interrupt the firmware never reads a byte. A "FUZZW" frame stores a byte
// at an offset into a 16-byte table, which nothing checks.
//
//   USART1_SR   0x40011000  bit 5 RXNE (a byte has arrived)
//   USART1_DR   0x40011004  the received byte
//   USART1_CR1  0x4001100c  bit 13 UE, bit 5 RXNEIE, bit 2 RE
//   USART1 is IRQ 37 (exception 53); NVIC_ISER1 bit 5 enables it.
//
//   frame: "FUZZ", a command, then for W a little-endian offset and a byte
//
// It carries its own start-up code: the vector table reaches IRQ 37.

#include <stdint.h>

#define USART1_SR (*(volatile uint32_t *)0x40011000u)
#define USART1_DR (*(volatile uint32_t *)0x40011004u)
#define USART1_CR1 (*(volatile uint32_t *)0x4001100cu)
#define NVIC_ISER1 (*(volatile uint32_t *)0xe000e104u)
#define SR_RXNE (1u << 5)
#define CR1_UE (1u << 13)
#define CR1_RXNEIE (1u << 5)
#define CR1_RE (1u << 2)
#define USART1_IRQ 37u

extern uint32_t _estack, _sidata, _sdata, _edata, _sbss, _ebss;
int main(void);

uint8_t frame[24];
volatile uint32_t frame_len;
volatile uint32_t frames;
volatile uint8_t table[16];
volatile uint32_t last_command;

static uint32_t read_word(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | (uint32_t)bytes[1] << 8 | (uint32_t)bytes[2] << 16 |
           (uint32_t)bytes[3] << 24;
}

__attribute__((noinline)) static void parse_frame(const uint8_t *buf, uint32_t len) {
    if (len < 5 || buf[0] != 'F' || buf[1] != 'U' || buf[2] != 'Z' || buf[3] != 'Z') {
        return;
    }
    last_command = buf[4];
    if (buf[4] == 'W' && len >= 10) {
        table[read_word(buf + 5)] = buf[9];
    }
}

void USART1_IRQHandler(void) {
    if (!(USART1_SR & SR_RXNE)) {
        return;
    }
    uint8_t byte = (uint8_t)USART1_DR;
    if (byte == '\n') {
        parse_frame(frame, frame_len);
        frame_len = 0;
        frames++;
        return;
    }
    if (frame_len < sizeof(frame)) {
        frame[frame_len++] = byte;
    }
}

void Reset_Handler(void) {
    uint32_t *src = &_sidata;
    for (uint32_t *dst = &_sdata; dst < &_edata;) {
        *dst++ = *src++;
    }
    for (uint32_t *dst = &_sbss; dst < &_ebss;) {
        *dst++ = 0;
    }
    main();
    for (;;) {
    }
}

void Default_Handler(void) {
    for (;;) {
    }
}

int main(void) {
    USART1_CR1 = CR1_UE | CR1_RXNEIE | CR1_RE;
    NVIC_ISER1 = 1u << (USART1_IRQ - 32u);
    for (;;) {
        __asm__ volatile("wfi");
    }
}

__attribute__((section(".isr_vector"), used)) const void *const vector_table[16 + USART1_IRQ + 1] = {
    [0] = &_estack,
    [1] = Reset_Handler,
    [2 ... 6] = Default_Handler,
    [11] = Default_Handler,
    [12] = Default_Handler,
    [14 ... 16 + USART1_IRQ - 1] = Default_Handler,
    [16 + USART1_IRQ] = USART1_IRQHandler,
};
