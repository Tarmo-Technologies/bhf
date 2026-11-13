#ifndef WIDGET_H
#define WIDGET_H
#include <stddef.h>
#include "tables.h"

#ifndef WIDGET_HAVE_TABLES
#error "WIDGET_HAVE_TABLES must come from the shared property sheet"
#endif
#if WIDGET_MODE != 1 && WIDGET_MODE != 2
#error "WIDGET_MODE must be 1 or 2"
#endif

#define WIDGET_MAGIC 0x57

int parse_record(const unsigned char *data, size_t len);
int widget_mode(void);

#endif
