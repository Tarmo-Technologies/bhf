/* SPDX-License-Identifier: Apache-2.0 */
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "bhf_decode.h"

int main(void) {
    const uint8_t data[] = {
        0x10, 0x00, 0x00, 0x00,   /* i32 = 16 */
        0x05, 0x00, 0x00, 0x00,   /* bounded i32 (0..9) -> 5 */
        0x05, 0x00,               /* bhf_c_string length prefix = 5 */
        'h','e','l','l','o',      /* string content */
        0xAA                      /* trailing byte left over for next decode */
    };
    bhf_cursor c = bhf_open(data, sizeof(data));
    char *s;

    assert(bhf_i32(&c) == 16);
    assert(bhf_bounded_i32(&c, 0, 9) == 5);

    s = bhf_c_string(&c, 64);
    assert(s);
    assert(strcmp(s, "hello") == 0);
    free(s);

    /* String consumer left the trailing byte for the next decoder. */
    assert(bhf_remaining(&c) == 1);
    assert(bhf_u8(&c) == 0xAA);
    return 0;
}
