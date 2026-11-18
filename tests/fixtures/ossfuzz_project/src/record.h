/* SPDX-License-Identifier: Apache-2.0 */
/* A small record format: the magic "REC1", a one-byte payload length, then
 * the payload. */
#ifndef RECORD_H
#define RECORD_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The largest payload a record holds. */
#define RECORD_MAX_PAYLOAD 16

struct record {
    size_t length;
    uint32_t checksum;
};

/* A 32-bit FNV-1a checksum of `data`. */
uint32_t record_checksum(const uint8_t *data, size_t size);

/* Parse one record from `data`; 0 on success. */
int record_parse(const uint8_t *data, size_t size, struct record *out);

#ifdef __cplusplus
}
#endif

#endif
