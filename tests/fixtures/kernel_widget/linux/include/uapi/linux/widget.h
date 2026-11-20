/* SPDX-License-Identifier: Apache-2.0 */
/*
 * The user-space interface of the widget misc device: its ioctl commands
 * and their argument structs, laid out the way a uapi header lays them out.
 */
#ifndef _UAPI_LINUX_WIDGET_H
#define _UAPI_LINUX_WIDGET_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define WIDGET_IOC_MAGIC 'W'
#define WIDGET_NAME_LEN 16
#define WIDGET_SLOTS 4

struct widget_config {
	__u32 mode;
	__u16 flags;
	__u8 channel;
	__u8 reserved;
	char name[WIDGET_NAME_LEN];
	__aligned_u64 timeout_ns;
};

struct widget_stats {
	__u64 packets;
	__u32 errors;
	__u32 count;
	unsigned long last_jiffies;
};

struct widget_xfer {
	__u32 slot;
	__u32 len;
	__u8 data[WIDGET_NAME_LEN];
	union {
		__u32 crc;
		__u8 tag[4];
	};
	void __user *reply;
};

struct widget_reg {
	__u16 addr;
	__u8 width : 4;
	__u8 bank : 4;
	__be32 value;
} __attribute__((packed));

#define WIDGET_IOC_RESET	_IO(WIDGET_IOC_MAGIC, 0)
#define WIDGET_IOC_SET_CONFIG	_IOW(WIDGET_IOC_MAGIC, 1, struct widget_config)
#define WIDGET_IOC_GET_STATS	_IOR(WIDGET_IOC_MAGIC, 2, struct widget_stats)
#define WIDGET_IOC_XFER		_IOWR(WIDGET_IOC_MAGIC, 3, struct widget_xfer)
#define WIDGET_IOC_SET_MODE	_IOW(WIDGET_IOC_MAGIC, 4, int)
#define WIDGET_IOC_WRITE_REG	_IOW(WIDGET_IOC_MAGIC, 5, struct widget_reg)
/* Reserved: no handler dispatches on it yet. */
#define WIDGET_IOC_RESERVED	_IOW(WIDGET_IOC_MAGIC, 9, __u32)

#endif /* _UAPI_LINUX_WIDGET_H */
