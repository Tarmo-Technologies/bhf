// SPDX-License-Identifier: Apache-2.0
// libyaml trade-study adapter (#370): parse the input as a YAML stream, event
// by event, until the stream ends or the parser reports an error.
#include <stddef.h>

#include "yaml.h"

int target_one_input(const unsigned char *data, size_t size) {
    yaml_parser_t parser;
    if (!yaml_parser_initialize(&parser)) return 0;
    yaml_parser_set_input_string(&parser, data, size);
    for (;;) {
        yaml_event_t event;
        if (!yaml_parser_parse(&parser, &event)) break;
        int done = event.type == YAML_STREAM_END_EVENT;
        yaml_event_delete(&event);
        if (done) break;
    }
    yaml_parser_delete(&parser);
    return 0;
}
