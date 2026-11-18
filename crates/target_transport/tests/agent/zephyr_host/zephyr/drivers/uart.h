/* SPDX-License-Identifier: Apache-2.0 */
/* Host stand-in (see kernel.h): the UART is a TCP socket, and a closed link
 * is followed by the next one, as a board's UART stays up. */
#ifndef BHF_ZEPHYR_HOST_UART_H
#define BHF_ZEPHYR_HOST_UART_H

#include <zephyr/device.h>

int uart_poll_in(const struct device *dev, unsigned char *c);
void uart_poll_out(const struct device *dev, unsigned char c);

#endif
