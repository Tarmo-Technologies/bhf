// SPDX-License-Identifier: Apache-2.0
// Independent sanitizer replay adapter for the engine-comparison fixtures.
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

int target_one_input(const unsigned char *data, size_t size);

int main(void) {
    size_t capacity = 4096;
    size_t length = 0;
    unsigned char *buffer = malloc(capacity);
    if (buffer == NULL) return 2;
    for (;;) {
        if (length == capacity) {
            if (capacity > (size_t)-1 / 2) {
                free(buffer);
                return 2;
            }
            size_t next = capacity * 2;
            unsigned char *grown = realloc(buffer, next);
            if (grown == NULL) {
                free(buffer);
                return 2;
            }
            buffer = grown;
            capacity = next;
        }
        size_t count = fread(buffer + length, 1, capacity - length, stdin);
        length += count;
        if (count == 0) {
            if (ferror(stdin)) {
                free(buffer);
                return 2;
            }
            break;
        }
    }
    int result = target_one_input(buffer, length);
    free(buffer);
    return result;
}
