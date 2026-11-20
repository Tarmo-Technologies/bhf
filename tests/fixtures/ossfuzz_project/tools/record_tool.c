/* SPDX-License-Identifier: Apache-2.0 */
/* A command-line tool the build also leaves in $OUT: not a fuzz target. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "record.h"

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        printf("%08x %s\n",
               record_checksum((const uint8_t *)argv[i], strlen(argv[i])), argv[i]);
    }
    return 0;
}
