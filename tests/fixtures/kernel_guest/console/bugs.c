/* SPDX-License-Identifier: Apache-2.0 */
/*
 * bugs: a misc device whose ioctl commands each make one kind of kernel
 * bug, for recording the console reports in this directory: BUGS_NULL
 * dereferences a NULL pointer, BUGS_WARN hits a WARN_ON, BUGS_UAF reads
 * freed memory and BUGS_DOUBLE_FREE frees memory twice.
 */
#include <linux/bug.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>

#define BUGS_NULL _IO('B', 1)
#define BUGS_WARN _IO('B', 2)
#define BUGS_UAF _IO('B', 3)
#define BUGS_DOUBLE_FREE _IO('B', 4)

struct bugs_state {
	long count;
	long value;
};

/* Never set: BUGS_NULL reads through it. */
static struct bugs_state *bugs_current;

static long bugs_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct bugs_state *state;
	long value;

	switch (cmd) {
	case BUGS_NULL:
		return READ_ONCE(bugs_current)->value;
	case BUGS_WARN:
		WARN_ON(arg == 0);
		return 0;
	case BUGS_UAF:
		state = kzalloc(sizeof(*state), GFP_KERNEL);
		if (!state)
			return -ENOMEM;
		kfree(state);
		value = READ_ONCE(state->value);
		return value;
	case BUGS_DOUBLE_FREE:
		state = kzalloc(sizeof(*state), GFP_KERNEL);
		if (!state)
			return -ENOMEM;
		kfree(state);
		kfree(state);
		return 0;
	default:
		return -ENOTTY;
	}
}

static const struct file_operations bugs_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = bugs_ioctl,
};

static struct miscdevice bugs_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "bugs",
	.fops = &bugs_fops,
};
module_misc_device(bugs_misc);

MODULE_DESCRIPTION("kernel bugs on demand");
MODULE_LICENSE("Apache-2.0");
