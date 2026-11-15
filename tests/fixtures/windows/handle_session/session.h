#ifndef SESSION_H
#define SESSION_H
#include <stddef.h>

struct session {
    int mode;
    size_t used;
    unsigned char *buf;
};

int session_init(struct session *s, int mode);
int session_feed(struct session *s, const unsigned char *data, size_t len);
void session_end(struct session *s);

#endif
