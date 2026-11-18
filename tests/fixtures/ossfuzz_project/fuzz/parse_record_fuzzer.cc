// SPDX-License-Identifier: Apache-2.0
#include <cstddef>
#include <cstdint>

#include "record.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    record parsed;
    record_parse(data, size, &parsed);
    return 0;
}
