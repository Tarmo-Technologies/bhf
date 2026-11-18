/* SPDX-License-Identifier: Apache-2.0 */
#include "record.h"

#include <stdlib.h>
#include <string.h>

uint32_t record_checksum(const uint8_t *data, size_t size) {
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < size; i++) {
        hash = (hash ^ data[i]) * 16777619u;
    }
    return hash;
}

int record_parse(const uint8_t *data, size_t size, struct record *out) {
    if (size < 5 || memcmp(data, "REC1", 4) != 0) {
        return -1;
    }
    size_t length = data[4];
    if (length > size - 5) {
        return -1;
    }
    uint8_t *payload = malloc(RECORD_MAX_PAYLOAD);
    if (payload == NULL) {
        return -1;
    }
    /* The planted bug: the declared length is checked against the input but
     * not against the payload buffer, so a record longer than
     * RECORD_MAX_PAYLOAD overflows it. */
    memcpy(payload, data + 5, length);
    out->length = length;
    out->checksum = record_checksum(payload, length);
    free(payload);
    return 0;
}
