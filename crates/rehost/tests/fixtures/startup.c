// SPDX-License-Identifier: Apache-2.0
//
// Start-up code of the fixture firmware images: the vector table and a reset
// handler that copies .data from flash, zeroes .bss and calls main, as a
// vendor start-up file does.

#include <stdint.h>

extern uint32_t _estack, _sidata, _sdata, _edata, _sbss, _ebss;
int main(void);

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

__attribute__((section(".isr_vector"), used)) const void *const vector_table[16] = {
    &_estack,        Reset_Handler,   Default_Handler, Default_Handler,
    Default_Handler, Default_Handler, Default_Handler, 0,
    0,               0,               0,               Default_Handler,
    Default_Handler, 0,               Default_Handler, Default_Handler,
};
