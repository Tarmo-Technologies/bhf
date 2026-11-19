// SPDX-License-Identifier: Apache-2.0
//
// Fixture firmware that reads commands from a peripheral's receive FIFO, one
// byte per read, through a getter: one instruction reads the data register
// over and over, the way a status poll reads its status register, but every
// bit of each byte matters. 0x01 arms it, 0x04 ends the session, and an 'X'
// once it is armed three times stores through a wild pointer.
//
//   FIFO_DATA  0x40013004  the receive FIFO: one byte per read
//
//   input: commands, one byte each

#include <stdint.h>

#define FIFO_DATA (*(volatile uint8_t *)0x40013004u)
#define CMD_ARM 0x01u
#define CMD_END 0x04u
#define CMD_FIRE 'X'
#define WILD ((volatile uint32_t *)0x60000000u)

volatile uint32_t armed;
volatile uint32_t sessions;

__attribute__((noinline)) static uint8_t fifo_pop(void) {
    return FIFO_DATA;
}

int main(void) {
    for (;;) {
        uint8_t command = fifo_pop();
        if (command == CMD_END) {
            break;
        }
        if (command == CMD_ARM) {
            armed++;
        } else if (command == CMD_FIRE && armed >= 3) {
            *WILD = armed;
        }
    }
    sessions++;
    for (;;) {
        __asm__ volatile("wfi");
    }
}
