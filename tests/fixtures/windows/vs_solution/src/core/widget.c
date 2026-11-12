// SPDX-License-Identifier: Apache-2.0
#include <stdlib.h>
#include "widget.h"

/* A record is WIDGET_MAGIC, a count, then `count` slot bytes. The count is
 * checked against twice the table size instead of the table size, so a record
 * with more than WIDGET_SLOTS slot bytes writes past the heap table. */
int parse_record(const unsigned char *data, size_t len) {
    unsigned char *slots;
    unsigned count;
    unsigned i;
    int sum = 0;
    if (len < 2 || data[0] != WIDGET_MAGIC) {
        return -1;
    }
    count = data[1];
    if (count > 2 * WIDGET_SLOTS) {
        return -2;
    }
    slots = (unsigned char *)calloc(WIDGET_SLOTS, 1);
    if (!slots) {
        return -3;
    }
    for (i = 0; i < count && 2 + i < len; i++) {
        slots[i] = data[2 + i];
    }
    for (i = 0; i < WIDGET_SLOTS && i < count; i++) {
        sum += slots[i];
    }
    free(slots);
    return sum + widget_mode();
}
