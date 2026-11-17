// SPDX-License-Identifier: Apache-2.0
// libpng trade-study adapter (#371): decode the input as a PNG image with the
// simplified API, to RGBA, when its size is reasonable.
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "png.h"
int target_one_input(const unsigned char *data, size_t size) {
    png_image image;
    memset(&image, 0, sizeof image);
    image.version = PNG_IMAGE_VERSION;
    if (png_image_begin_read_from_memory(&image, data, size)) {
        image.format = PNG_FORMAT_RGBA;
        size_t bytes = PNG_IMAGE_SIZE(image);
        if (bytes > 0 && bytes < (1u << 24)) {
            void *buffer = malloc(bytes);
            if (buffer) { png_image_finish_read(&image, NULL, buffer, 0, NULL); free(buffer); }
        }
    }
    png_image_free(&image);
    return 0;
}
