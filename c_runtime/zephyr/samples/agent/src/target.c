/* SPDX-License-Identifier: Apache-2.0 */
/* The code under test of the Zephyr agent sample (#291), built with
 * -fsanitize-coverage=trace-pc: each matched byte of "BUG" is new code, and
 * the whole of it executes an undefined instruction (a CPU exception). */
#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 0 && data[0] == 'B') {
        if (size > 1 && data[1] == 'U') {
            if (size > 2 && data[2] == 'G') {
                __asm volatile("udf #0");
            }
        }
    }
    return 0;
}
