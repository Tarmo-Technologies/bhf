/* SPDX-License-Identifier: Apache-2.0 */
/* A stripped-down legacy parser for the binary adapter tests: main calls
 * handle, which calls parse_header, which compares against a magic string. */
#include <stdio.h>
#include <string.h>

int parse_header(const char *line) {
    if (strncmp(line, "LEGACY/1.0", 10) == 0)
        return 1;
    return 0;
}

int handle(const char *line) {
    return parse_header(line) ? puts("usage: legacy") : 0;
}

int main(int argc, char **argv) {
    return argc > 1 ? handle(argv[1]) : 0;
}
