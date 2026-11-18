/* SPDX-License-Identifier: Apache-2.0 */
#include <stddef.h>
#include <stdint.h>

#include "bhf_agent_zephyr.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(void) {
    bhf_agent_zephyr_run(LLVMFuzzerTestOneInput);
    return 0;
}
