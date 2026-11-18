/* SPDX-License-Identifier: Apache-2.0 */
/* An uninstrumented binary for the image's AFL++ QEMU- and Frida-mode smokes:
 * it reads stdin and aborts on input starting "FU". */
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    char buf[8] = {0};
    ssize_t n = read(0, buf, sizeof buf);
    if (n > 1 && buf[0] == 'F') {
        if (buf[1] == 'U') abort();
        return 2;
    }
    return 0;
}
