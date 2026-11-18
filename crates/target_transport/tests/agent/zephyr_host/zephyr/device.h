/* SPDX-License-Identifier: Apache-2.0 */
/* Host stand-in (see kernel.h): one device, the agent's UART. */
#ifndef BHF_ZEPHYR_HOST_DEVICE_H
#define BHF_ZEPHYR_HOST_DEVICE_H

#include <stdbool.h>

struct device {
    int listener;
    int link;
};
extern struct device bhf_zephyr_host_uart;

#define DT_CHOSEN(name) name
#define DEVICE_DT_GET(node) (&bhf_zephyr_host_uart)
bool device_is_ready(const struct device *dev);

#endif
