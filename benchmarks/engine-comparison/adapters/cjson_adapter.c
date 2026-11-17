// SPDX-License-Identifier: Apache-2.0
// cJSON trade-study adapter (#255): parse the input as a length-bounded JSON
// document, print what parsed, and free it.
#include <stddef.h>

#include "cJSON.h"

int target_one_input(const unsigned char *data, size_t size) {
    cJSON *json = cJSON_ParseWithLengthOpts((const char *)data, size, NULL, 0);
    if (json != NULL) {
        char *printed = cJSON_PrintUnformatted(json);
        cJSON_free(printed);
        cJSON_Delete(json);
    }
    return 0;
}
