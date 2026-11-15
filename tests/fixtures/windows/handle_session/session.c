// SPDX-License-Identifier: Apache-2.0
#include <stdlib.h>
#include <string.h>
#include "session.h"

/* A handle-based API: init, feed records, end. The space check uses the
 * buffer's doubled size, so records fed across calls write past the buffer. */
int session_init(struct session *s, int mode) {
    s->mode = mode;
    s->used = 0;
    s->buf = (unsigned char *)calloc(16, 1);
    return s->buf ? 0 : -1;
}

int session_feed(struct session *s, const unsigned char *data, size_t len) {
    if (!s->buf || !data || len == 0 || len > 16 || data[0] != 'S') {
        return -1;
    }
    if (s->used + len > 32) {
        return -2;
    }
    memcpy(s->buf + s->used, data, len);
    s->used += len;
    return (int)s->used;
}

void session_end(struct session *s) {
    free(s->buf);
    s->buf = NULL;
}
