/* SPDX-License-Identifier: Apache-2.0 */
/* The code under test of the agent loopback test: each matched byte of
 * "BUG" is new code, and the whole of it writes through a null pointer. */
#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 0 && data[0] == 'B') {
        if (size > 1 && data[1] == 'U') {
            if (size > 2 && data[2] == 'G') {
                *(volatile int *)(uintptr_t)0 = 1;
            }
        }
    }
    return 0;
}
