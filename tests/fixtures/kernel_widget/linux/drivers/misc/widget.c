/* SPDX-License-Identifier: Apache-2.0 */
/*
 * widget: a misc character device with an ioctl interface, written the way
 * a Linux driver is. Each open file holds a widget_state; the commands set
 * its configuration, read its counters, and copy records into its slots.
 *
 * widget_copy_at() checks the slot index against the wrong bound, so
 * WIDGET_IOC_XFER with slot == WIDGET_SLOTS writes one record past the end of
 * the state: the KASAN slab-out-of-bounds write ../../../crashes/ records.
 */
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <uapi/linux/widget.h>

struct widget_state {
	struct widget_config config;
	u64 count;
	u8 slots[WIDGET_SLOTS][WIDGET_NAME_LEN];
};

static int widget_open(struct inode *inode, struct file *file)
{
	struct widget_state *state = kzalloc(sizeof(*state), GFP_KERNEL);

	if (!state)
		return -ENOMEM;
	file->private_data = state;
	return 0;
}

static int widget_release(struct inode *inode, struct file *file)
{
	kfree(file->private_data);
	return 0;
}

static long widget_copy_at(struct widget_state *state,
			   const struct widget_xfer *xfer)
{
	if (xfer->slot > WIDGET_SLOTS)
		return -EINVAL;
	memcpy(state->slots[xfer->slot], xfer->data, WIDGET_NAME_LEN);
	state->count++;
	return 0;
}

static long widget_do_xfer(struct widget_state *state, unsigned int op,
			   void __user *argp)
{
	struct widget_xfer xfer;

	switch (op) {
	case WIDGET_IOC_XFER:
		if (copy_from_user(&xfer, argp, sizeof(xfer)))
			return -EFAULT;
		return widget_copy_at(state, &xfer);
	default:
		return -ENOTTY;
	}
}

static long widget_ioctl(struct file *file, unsigned int cmd,
			 unsigned long arg)
{
	struct widget_state *state = file->private_data;
	void __user *argp = (void __user *)arg;
	struct widget_stats stats = {};
	struct widget_reg reg;
	int mode;

	switch (cmd) {
	case WIDGET_IOC_RESET:
		memset(state, 0, sizeof(*state));
		return 0;
	case WIDGET_IOC_SET_CONFIG:
		if (copy_from_user(&state->config, argp, sizeof(state->config)))
			return -EFAULT;
		return 0;
	case WIDGET_IOC_GET_STATS:
		stats.count = state->count;
		if (copy_to_user(argp, &stats, sizeof(stats)))
			return -EFAULT;
		return 0;
	case WIDGET_IOC_SET_MODE:
		if (get_user(mode, (int __user *)argp))
			return -EFAULT;
		state->config.mode = mode;
		return 0;
	case WIDGET_IOC_WRITE_REG:
		if (copy_from_user(&reg, argp, sizeof(reg)))
			return -EFAULT;
		return reg.width ? 0 : -EINVAL;
	default:
		return widget_do_xfer(state, cmd, argp);
	}
}

static const struct file_operations widget_fops = {
	.owner = THIS_MODULE,
	.open = widget_open,
	.release = widget_release,
	.unlocked_ioctl = widget_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
};

static struct miscdevice widget_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "widget",
	.fops = &widget_fops,
};
module_misc_device(widget_misc);

MODULE_DESCRIPTION("widget misc device");
