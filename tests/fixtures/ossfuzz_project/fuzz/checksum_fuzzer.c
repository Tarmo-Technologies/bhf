/* SPDX-License-Identifier: Apache-2.0 */
#include <stddef.h>
#include <stdint.h>

#include "record.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    (void)record_checksum(data, size);
    return 0;
}
