// SPDX-License-Identifier: Apache-2.0
/*
 * kernel_executor.c: bhf's in-guest executor for Linux kernels.
 *
 * `bhf kernel run` and `bhf kernel fuzz` boot a qemu-system guest whose
 * initramfs holds this program as /init. It mounts /dev, /proc, /sys and
 * debugfs, loads the kernel modules under /bhf/modules, finds the
 * virtio-serial port named org.bhf.executor and serves the host over it:
 * each EXEC message carries a program (a list of system calls in the
 * format below), which a forked child runs with KCOV enabled; the REPLY
 * carries each call's result and the kernel PCs KCOV recorded while it ran.
 *
 * Build: cc -O2 -static -o bhf-kernel-executor kernel_executor.c
 *
 *   bhf-kernel-executor                  as /init in the guest (the default)
 *   bhf-kernel-executor --port PATH      serve over PATH, no setup
 *   bhf-kernel-executor --channel stdio  serve over stdin/stdout, no setup
 *   bhf-kernel-executor --decode         print the program on stdin, decoded
 *
 * Messages (all integers little-endian): a header {u32 magic 'BKX1', u32
 * type, u32 length} and `length` payload bytes.
 *
 *   HELLO (1, guest->host): u32 protocol, u32 flags (1: KCOV, 2: /init,
 *     4: KCOV comparisons),
 *     u32 cover entries per call, u32 max program bytes, u32 max calls,
 *     u32 data area size, u64 data area address, then three strings (u32
 *     length, bytes): uname machine, uname release, setup notes.
 *   EXEC (2, host->guest): u64 id, u32 flags (1: collect the PCs, 2:
 *     collect the comparisons instead), u32 timeout in ms, u32 program
 *     length, the program.
 *   REPLY (3, guest->host): u64 id, u32 status, u32 detail, u32 calls
 *     decoded, u32 calls run, u32 flags (1: KCOV on, 2: truncated, 4: the
 *     words are comparisons), u32 0, then per call run: u32 index, u32
 *     errno, i64 result, u32 word count, u32 flags (1: truncated), and the
 *     words: the PCs, or for each comparison KCOV's four (type, the two
 *     operands, PC).
 *
 * Programs (version 1). Every byte string decodes: a call that the input
 * ends inside is dropped, and every selector is taken modulo its range.
 *
 *   call := u8 selector, u8 argument count (mod 7), [u16 number when the
 *           selector names a raw call], argument*
 *   arg  := u8 tag (mod 4), then
 *           0 const:  u64 value
 *           1 data:   u16 length, that many bytes (fewer when the input
 *                     ends first; at most 4096), copied into the data area;
 *                     the argument is their address
 *           2 result: u8 index, the result of call (index mod calls before
 *                     it), or -1 for the first call
 *           3 out:    u16 length (at most 4096), zeroed bytes in the data
 *                     area; the argument is their address
 *
 * The selector modulo 13 names openat, close, read, write, ioctl, mmap,
 * munmap, pread64, pwrite64, lseek, fcntl, dup, or (12) a raw call whose
 * number follows. Buffers are placed 8-aligned from the start of the data
 * area (1 MiB at 0x20000000); one that does not fit is a NULL pointer. A raw
 * call that would reboot, load or unload modules, change mounts, silence the
 * console, signal or trace other processes, or touch I/O ports is not made
 * and fails with EPERM.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define BKX_MAGIC 0x31584b42u /* "BKX1" */
#define BKX_PROTOCOL 1u
#define BKX_HELLO 1u
#define BKX_EXEC 2u
#define BKX_REPLY 3u

#define BKX_STATUS_OK 0u
#define BKX_STATUS_TIMEOUT 1u
#define BKX_STATUS_SIGNALED 2u
#define BKX_STATUS_EXITED 3u
#define BKX_STATUS_SETUP 4u
#define BKX_STATUS_BAD_REQUEST 5u

#define BKP_MAX_CALLS 64
#define BKP_MAX_ARGS 6
#define BKP_MAX_ARG_BYTES 4096u
#define BKP_MAX_PROGRAM 65536u
#define BKP_DATA_ADDR 0x20000000ul
#define BKP_DATA_SIZE 0x100000u
#define BKP_NULL UINT64_MAX

#define BKX_COVER_ENTRIES (1u << 18)
#define BKX_MAX_PROGRAM_PCS (1u << 19)
#define BKX_PORT_NAME "org.bhf.executor"

/* <linux/kcov.h>, spelled out so the executor builds without kernel headers. */
#define BKX_KCOV_INIT_TRACE _IOR('c', 1, unsigned long)
#define BKX_KCOV_ENABLE _IO('c', 100)
#define BKX_KCOV_TRACE_PC 0
#define BKX_KCOV_TRACE_CMP 1

/* What a program's run collects. */
enum { BKX_COLLECT_NONE = 0, BKX_COLLECT_PCS = 1, BKX_COLLECT_CMPS = 2 };

enum { BKP_CONST = 0, BKP_DATA = 1, BKP_RESULT = 2, BKP_OUT = 3 };

struct bkp_arg {
	uint8_t kind;
	/* const: the value; result: the call index, or BKP_NULL for none;
	 * data and out: the offset in the data area, or BKP_NULL. */
	uint64_t value;
	uint32_t len;
	/* data: where its bytes start in the program. */
	uint32_t src;
};

struct bkp_call {
	uint16_t sys;
	uint16_t nr;
	uint8_t nargs;
	struct bkp_arg args[BKP_MAX_ARGS];
};

struct bkp_program {
	uint32_t ncalls;
	uint32_t data_used;
	struct bkp_call calls[BKP_MAX_CALLS];
};

struct bkp_sys {
	const char *name;
	long nr;
};

static const struct bkp_sys bkp_table[] = {
	{"openat", __NR_openat}, {"close", __NR_close},
	{"read", __NR_read},     {"write", __NR_write},
	{"ioctl", __NR_ioctl},   {"mmap", __NR_mmap},
	{"munmap", __NR_munmap}, {"pread64", __NR_pread64},
	{"pwrite64", __NR_pwrite64}, {"lseek", __NR_lseek},
	{"fcntl", __NR_fcntl},   {"dup", __NR_dup},
};
#define BKP_NSYS ((uint16_t)(sizeof(bkp_table) / sizeof(bkp_table[0])))
#define BKP_RAW BKP_NSYS

static uint16_t get16(const uint8_t *p)
{
	return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t get32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

static uint64_t get64(const uint8_t *p)
{
	uint64_t v = 0;
	int i;
	for (i = 7; i >= 0; i--)
		v = (v << 8) | p[i];
	return v;
}

/* Place `len` bytes in the data area: their offset, or BKP_NULL. */
static uint64_t bkp_place(struct bkp_program *prog, uint32_t len)
{
	uint32_t at = (prog->data_used + 7u) & ~7u;
	if (at > BKP_DATA_SIZE || len > BKP_DATA_SIZE - at)
		return BKP_NULL;
	prog->data_used = at + len;
	return at;
}

/* Decode `in` into `prog`. Total: every input decodes, to 0..64 calls. */
static void bkp_decode(const uint8_t *in, size_t len, struct bkp_program *prog)
{
	size_t pos = 0;
	memset(prog, 0, sizeof(*prog));
	while (prog->ncalls < BKP_MAX_CALLS && len - pos >= 2) {
		struct bkp_call call;
		uint32_t saved_data = prog->data_used;
		int ok = 1;
		uint8_t i;
		memset(&call, 0, sizeof(call));
		call.sys = (uint16_t)(in[pos] % (BKP_NSYS + 1));
		call.nargs = (uint8_t)(in[pos + 1] % (BKP_MAX_ARGS + 1));
		pos += 2;
		if (call.sys == BKP_RAW) {
			if (len - pos < 2)
				break;
			call.nr = get16(in + pos);
			pos += 2;
		}
		for (i = 0; i < call.nargs && ok; i++) {
			struct bkp_arg *arg = &call.args[i];
			uint32_t n;
			if (pos >= len) {
				ok = 0;
				break;
			}
			arg->kind = (uint8_t)(in[pos] % 4);
			pos++;
			switch (arg->kind) {
			case BKP_CONST:
				if (len - pos < 8) {
					ok = 0;
					break;
				}
				arg->value = get64(in + pos);
				pos += 8;
				break;
			case BKP_DATA:
				if (len - pos < 2) {
					ok = 0;
					break;
				}
				n = get16(in + pos);
				pos += 2;
				if (n > BKP_MAX_ARG_BYTES)
					n = BKP_MAX_ARG_BYTES;
				if (n > len - pos)
					n = (uint32_t)(len - pos);
				arg->len = n;
				arg->src = (uint32_t)pos;
				arg->value = bkp_place(prog, n);
				pos += n;
				break;
			case BKP_RESULT:
				if (len - pos < 1) {
					ok = 0;
					break;
				}
				arg->value = prog->ncalls == 0
						     ? BKP_NULL
						     : (uint64_t)(in[pos] % prog->ncalls);
				pos++;
				break;
			default: /* BKP_OUT */
				if (len - pos < 2) {
					ok = 0;
					break;
				}
				n = get16(in + pos);
				pos += 2;
				if (n > BKP_MAX_ARG_BYTES)
					n = BKP_MAX_ARG_BYTES;
				arg->len = n;
				arg->value = bkp_place(prog, n);
				break;
			}
		}
		if (!ok) {
			prog->data_used = saved_data;
			break;
		}
		prog->calls[prog->ncalls++] = call;
	}
}

static const char *bkp_name(const struct bkp_call *call)
{
	return call->sys < BKP_NSYS ? bkp_table[call->sys].name : "syscall";
}

/* The decoded program, one line per call and argument (`--decode`). */
static void bkp_dump(const uint8_t *in, const struct bkp_program *prog, FILE *out)
{
	uint32_t c, b;
	uint8_t i;
	fprintf(out, "calls %u data 0x%x\n", prog->ncalls, prog->data_used);
	for (c = 0; c < prog->ncalls; c++) {
		const struct bkp_call *call = &prog->calls[c];
		fprintf(out, "call %u %s", c, bkp_name(call));
		if (call->sys == BKP_RAW)
			fprintf(out, " nr=%u", call->nr);
		fprintf(out, " nargs %u\n", call->nargs);
		for (i = 0; i < call->nargs; i++) {
			const struct bkp_arg *arg = &call->args[i];
			fprintf(out, " arg %u ", i);
			switch (arg->kind) {
			case BKP_CONST:
				fprintf(out, "const 0x%llx\n", (unsigned long long)arg->value);
				break;
			case BKP_RESULT:
				if (arg->value == BKP_NULL)
					fprintf(out, "result none\n");
				else
					fprintf(out, "result %llu\n", (unsigned long long)arg->value);
				break;
			default:
				fprintf(out, "%s ", arg->kind == BKP_DATA ? "data" : "out");
				if (arg->value == BKP_NULL)
					fprintf(out, "null");
				else
					fprintf(out, "0x%llx", (unsigned long long)arg->value);
				fprintf(out, " len %u", arg->len);
				if (arg->kind == BKP_DATA) {
					fputc(' ', out);
					for (b = 0; b < arg->len; b++)
						fprintf(out, "%02x", in[arg->src + b]);
				}
				fputc('\n', out);
				break;
			}
		}
	}
}

/* ── Channel ───────────────────────────────────────────────────────────── */

static int chan_in = -1;
static int chan_out = -1;

static int write_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	while (len > 0) {
		ssize_t n = write(fd, p, len);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return -1;
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

/* 1: read it all; 0: the host is not connected; -1: error. */
static int read_all(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;
	while (len > 0) {
		ssize_t n = read(fd, p, len);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0)
			return -1;
		if (n == 0)
			return 0;
		p += n;
		len -= (size_t)n;
	}
	return 1;
}

struct buf {
	uint8_t *data;
	size_t len;
	size_t cap;
};

static void buf_reserve(struct buf *b, size_t more)
{
	if (b->len + more <= b->cap)
		return;
	while (b->cap < b->len + more)
		b->cap = b->cap ? b->cap * 2 : 4096;
	b->data = realloc(b->data, b->cap);
	if (!b->data) {
		perror("bhf-executor: realloc");
		_exit(1);
	}
}

static void put32(struct buf *b, uint32_t v)
{
	int i;
	buf_reserve(b, 4);
	for (i = 0; i < 4; i++)
		b->data[b->len++] = (uint8_t)(v >> (8 * i));
}

static void put64(struct buf *b, uint64_t v)
{
	int i;
	buf_reserve(b, 8);
	for (i = 0; i < 8; i++)
		b->data[b->len++] = (uint8_t)(v >> (8 * i));
}

static void put_string(struct buf *b, const char *s)
{
	size_t n = strlen(s);
	put32(b, (uint32_t)n);
	buf_reserve(b, n);
	memcpy(b->data + b->len, s, n);
	b->len += n;
}

/* Send `payload` as a message of `type`. */
static int send_message(uint32_t type, const struct buf *payload)
{
	struct buf head = {0, 0, 0};
	int ret;
	put32(&head, BKX_MAGIC);
	put32(&head, type);
	put32(&head, (uint32_t)payload->len);
	ret = write_all(chan_out, head.data, head.len);
	if (ret == 0 && payload->len > 0)
		ret = write_all(chan_out, payload->data, payload->len);
	free(head.data);
	return ret;
}

/* ── Guest setup ───────────────────────────────────────────────────────── */

static char notes[4096];
/* Only the guest's /init writes to the kernel log. */
static int log_to_kmsg;

static void note(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* Add a line to the setup notes HELLO carries, and to the kernel log. */
static void note(const char *fmt, ...)
{
	char line[512];
	va_list ap;
	int fd;
	size_t used = strlen(notes);
	va_start(ap, fmt);
	vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);
	if (used + strlen(line) + 2 < sizeof(notes)) {
		strcat(notes, line);
		strcat(notes, "\n");
	}
	fd = log_to_kmsg ? open("/dev/kmsg", O_WRONLY | O_CLOEXEC) : -1;
	if (fd >= 0) {
		dprintf(fd, "<5>bhf-executor: %s\n", line);
		close(fd);
	}
}

static void power_off(void)
{
	sync();
	reboot(RB_POWER_OFF);
	_exit(1);
}

static void mount_or_note(const char *source, const char *target, const char *type)
{
	mkdir(target, 0755);
	if (mount(source, target, type, 0, NULL) != 0 && errno != EBUSY)
		note("mount %s on %s: %s", type, target, strerror(errno));
}

static int compare_names(const struct dirent **a, const struct dirent **b)
{
	return strcmp((*a)->d_name, (*b)->d_name);
}

/* Load every /bhf/modules/<name>.ko, in name order. */
static void load_modules(void)
{
	struct dirent **names;
	int n = scandir("/bhf/modules", &names, NULL, compare_names);
	int i;
	if (n < 0)
		return;
	for (i = 0; i < n; i++) {
		char path[512];
		const char *name = names[i]->d_name;
		size_t len = strlen(name);
		int fd;
		if (len > 3 && strcmp(name + len - 3, ".ko") == 0) {
			snprintf(path, sizeof(path), "/bhf/modules/%s", name);
			fd = open(path, O_RDONLY | O_CLOEXEC);
			if (fd < 0)
				note("module %s: open: %s", name, strerror(errno));
			else if (syscall(__NR_finit_module, fd, "", 0) != 0)
				note("module %s: not loaded: %s", name, strerror(errno));
			else
				note("module %s: loaded", name);
			if (fd >= 0)
				close(fd);
		}
		free(names[i]);
	}
	free(names);
}

/* The /dev node of the virtio-serial port named BKX_PORT_NAME. */
static int find_port(char *path, size_t size)
{
	int attempt;
	for (attempt = 0; attempt < 200; attempt++) {
		DIR *dir = opendir("/sys/class/virtio-ports");
		struct dirent *entry;
		if (dir) {
			while ((entry = readdir(dir)) != NULL) {
				char name_path[512], name[128];
				ssize_t n;
				int fd;
				if (entry->d_name[0] == '.')
					continue;
				snprintf(name_path, sizeof(name_path), "/sys/class/virtio-ports/%s/name",
					 entry->d_name);
				fd = open(name_path, O_RDONLY | O_CLOEXEC);
				if (fd < 0)
					continue;
				n = read(fd, name, sizeof(name) - 1);
				close(fd);
				if (n <= 0)
					continue;
				name[n] = 0;
				if (name[n - 1] == '\n')
					name[n - 1] = 0;
				if (strcmp(name, BKX_PORT_NAME) == 0) {
					snprintf(path, size, "/dev/%s", entry->d_name);
					closedir(dir);
					return 0;
				}
			}
			closedir(dir);
		}
		usleep(50 * 1000);
	}
	return -1;
}

/* ── Running a program ─────────────────────────────────────────────────── */

struct call_record {
	uint32_t err;
	int64_t ret;
	uint32_t npcs;
	uint32_t flags;
	uint64_t first_pc;
};

/* What the child writes for the parent, in memory both map. */
struct results {
	uint32_t executed;
	uint32_t truncated;
	/* What KCOV collected: BKX_COLLECT_*. */
	uint32_t collected;
	struct call_record calls[BKP_MAX_CALLS];
	uint64_t pcs[BKX_MAX_PROGRAM_PCS];
};

static struct results *results;
static uint64_t *cover;
static int kcov_fd = -1;
/* A second KCOV handle, for the comparisons. */
static uint64_t *cmp_cover;
static int kcov_cmp_fd = -1;

static int denied(long nr)
{
	static const long list[] = {
		__NR_reboot, __NR_kexec_load, __NR_init_module, __NR_finit_module,
		__NR_delete_module, __NR_mount, __NR_umount2, __NR_pivot_root,
		__NR_chroot, __NR_swapon, __NR_swapoff, __NR_syslog, __NR_ptrace,
		__NR_kill, __NR_tkill, __NR_tgkill,
#ifdef __NR_kexec_file_load
		__NR_kexec_file_load,
#endif
#ifdef __NR_iopl
		__NR_iopl,
#endif
#ifdef __NR_ioperm
		__NR_ioperm,
#endif
#ifdef __NR_umount
		__NR_umount,
#endif
#ifdef __NR_move_mount
		__NR_move_mount, __NR_fsmount, __NR_open_tree,
#endif
#ifdef __NR_pidfd_send_signal
		__NR_pidfd_send_signal,
#endif
#ifdef __NR_process_vm_writev
		__NR_process_vm_writev,
#endif
	};
	size_t i;
	for (i = 0; i < sizeof(list) / sizeof(list[0]); i++)
		if (list[i] == nr)
			return 1;
	return 0;
}

/* The child: map the data area, copy the buffers in, run the calls. */
static void run_child(const uint8_t *in, const struct bkp_program *prog, int collect)
{
	uint64_t res[BKP_MAX_CALLS];
	uint8_t *data;
	uint32_t c, total = 0;
	pid_t self = getpid();
	setpgid(0, 0);
	prctl(PR_SET_PDEATHSIG, SIGKILL);
	prctl(PR_SET_NAME, "bhf-program", 0, 0, 0);
	/* The program's calls must not reach the host channel. */
	close(chan_in);
	if (chan_out != chan_in)
		close(chan_out);
	data = mmap((void *)BKP_DATA_ADDR, BKP_DATA_SIZE, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (data == MAP_FAILED)
		_exit(100);
	for (c = 0; c < prog->ncalls; c++) {
		uint8_t i;
		for (i = 0; i < prog->calls[c].nargs; i++) {
			const struct bkp_arg *arg = &prog->calls[c].args[i];
			if (arg->kind == BKP_DATA && arg->value != BKP_NULL)
				memcpy(data + arg->value, in + arg->src, arg->len);
		}
	}
	uint64_t *area = NULL, per = 1, max_records;
	if (collect == BKX_COLLECT_CMPS && kcov_cmp_fd >= 0 &&
	    ioctl(kcov_cmp_fd, BKX_KCOV_ENABLE, BKX_KCOV_TRACE_CMP) == 0) {
		area = cmp_cover;
		per = 4;
	} else if (collect == BKX_COLLECT_PCS && kcov_fd >= 0 &&
		   ioctl(kcov_fd, BKX_KCOV_ENABLE, BKX_KCOV_TRACE_PC) == 0) {
		area = cover;
	}
	results->collected = area ? (uint32_t)collect : BKX_COLLECT_NONE;
	max_records = (BKX_COVER_ENTRIES - 1) / per;
	for (c = 0; c < prog->ncalls; c++) {
		const struct bkp_call *call = &prog->calls[c];
		struct call_record *rec = &results->calls[c];
		uint64_t a[BKP_MAX_ARGS] = {0};
		long nr = call->sys < BKP_NSYS ? bkp_table[call->sys].nr : (long)call->nr;
		long ret;
		uint64_t n = 0, k;
		uint8_t i;
		int err = 0;
		for (i = 0; i < call->nargs; i++) {
			const struct bkp_arg *arg = &call->args[i];
			switch (arg->kind) {
			case BKP_CONST:
				a[i] = arg->value;
				break;
			case BKP_RESULT:
				a[i] = arg->value == BKP_NULL ? UINT64_MAX : res[arg->value];
				break;
			default:
				a[i] = arg->value == BKP_NULL ? 0 : BKP_DATA_ADDR + arg->value;
				break;
			}
		}
		if (call->sys == BKP_RAW && denied(nr)) {
			ret = -1;
			err = EPERM;
		} else {
			if (area)
				__atomic_store_n(&area[0], 0, __ATOMIC_RELAXED);
			errno = 0;
			ret = syscall(nr, a[0], a[1], a[2], a[3], a[4], a[5]);
			err = ret == -1 ? errno : 0;
			if (area)
				n = __atomic_load_n(&area[0], __ATOMIC_RELAXED);
			/* A process the call forked runs none of what follows. */
			if (getpid() != self)
				_exit(0);
		}
		res[c] = (uint64_t)ret;
		/* n records of `per` words, the buffer and the program's cap. */
		if (n >= max_records) {
			n = max_records;
			rec->flags |= 1;
		}
		n *= per;
		if (n > BKX_MAX_PROGRAM_PCS - total) {
			n = (BKX_MAX_PROGRAM_PCS - total) / per * per;
			rec->flags |= 1;
			results->truncated = 1;
		}
		for (k = 0; k < n; k++)
			results->pcs[total + k] = area[k + 1];
		rec->err = (uint32_t)err;
		rec->ret = ret;
		rec->npcs = (uint32_t)n;
		total += (uint32_t)n;
		__atomic_store_n(&results->executed, c + 1, __ATOMIC_RELEASE);
	}
	_exit(0);
}

static uint64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* Run `in` and send its REPLY. */
static int execute(uint64_t id, uint32_t flags, uint32_t timeout_ms, const uint8_t *in,
		   size_t len)
{
	static struct bkp_program prog;
	struct buf reply = {0, 0, 0};
	uint32_t status = BKX_STATUS_OK, detail = 0, executed, c, at = 0;
	int collect = (flags & 2)   ? BKX_COLLECT_CMPS
		      : (flags & 1) ? BKX_COLLECT_PCS
				    : BKX_COLLECT_NONE;
	int wstatus = 0, ret;
	uint64_t deadline;
	pid_t pid;

	bkp_decode(in, len, &prog);
	memset(results, 0, offsetof(struct results, pcs));
	pid = fork();
	if (pid == 0)
		run_child(in, &prog, collect);
	if (pid < 0) {
		status = BKX_STATUS_SETUP;
		detail = (uint32_t)errno;
	} else {
		deadline = now_ms() + (timeout_ms ? timeout_ms : 5000);
		for (;;) {
			pid_t done = waitpid(pid, &wstatus, WNOHANG);
			if (done == pid)
				break;
			if (done < 0 && errno != EINTR) {
				wstatus = 0;
				break;
			}
			if (now_ms() >= deadline) {
				kill(-pid, SIGKILL);
				kill(pid, SIGKILL);
				waitpid(pid, &wstatus, 0);
				status = BKX_STATUS_TIMEOUT;
				detail = timeout_ms;
				break;
			}
			usleep(200);
		}
		/* What the program forked goes too. */
		kill(-pid, SIGKILL);
		while (waitpid(-1, NULL, WNOHANG) > 0)
			;
		if (status == BKX_STATUS_OK) {
			if (WIFSIGNALED(wstatus)) {
				status = BKX_STATUS_SIGNALED;
				detail = (uint32_t)WTERMSIG(wstatus);
			} else if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 100 &&
				   results->executed == 0) {
				status = BKX_STATUS_SETUP;
				detail = ENOMEM;
			} else if (results->executed < prog.ncalls) {
				status = BKX_STATUS_EXITED;
				detail = WIFEXITED(wstatus) ? (uint32_t)WEXITSTATUS(wstatus) : 0;
			}
		}
	}
	executed = __atomic_load_n(&results->executed, __ATOMIC_ACQUIRE);
	if (executed > prog.ncalls)
		executed = prog.ncalls;
	put64(&reply, id);
	put32(&reply, status);
	put32(&reply, detail);
	put32(&reply, prog.ncalls);
	put32(&reply, executed);
	put32(&reply, (results->collected != BKX_COLLECT_NONE ? 1u : 0u) |
			      (results->truncated ? 2u : 0u) |
			      (results->collected == BKX_COLLECT_CMPS ? 4u : 0u));
	put32(&reply, 0);
	for (c = 0; c < executed; c++) {
		const struct call_record *rec = &results->calls[c];
		uint32_t k, npcs = rec->npcs;
		if (npcs > BKX_MAX_PROGRAM_PCS - at)
			npcs = BKX_MAX_PROGRAM_PCS - at;
		put32(&reply, c);
		put32(&reply, rec->err);
		put64(&reply, (uint64_t)rec->ret);
		put32(&reply, npcs);
		put32(&reply, rec->flags);
		buf_reserve(&reply, (size_t)npcs * 8);
		for (k = 0; k < npcs; k++)
			put64(&reply, results->pcs[at + k]);
		at += npcs;
	}
	ret = send_message(BKX_REPLY, &reply);
	free(reply.data);
	return ret;
}

static int send_hello(int is_init)
{
	struct buf hello = {0, 0, 0};
	struct utsname uts;
	int ret;
	memset(&uts, 0, sizeof(uts));
	uname(&uts);
	put32(&hello, BKX_PROTOCOL);
	put32(&hello, (kcov_fd >= 0 ? 1u : 0u) | (is_init ? 2u : 0u) |
			      (kcov_cmp_fd >= 0 ? 4u : 0u));
	put32(&hello, BKX_COVER_ENTRIES);
	put32(&hello, BKP_MAX_PROGRAM);
	put32(&hello, BKP_MAX_CALLS);
	put32(&hello, BKP_DATA_SIZE);
	put64(&hello, BKP_DATA_ADDR);
	put_string(&hello, uts.machine);
	put_string(&hello, uts.release);
	put_string(&hello, notes);
	ret = send_message(BKX_HELLO, &hello);
	free(hello.data);
	return ret;
}

/* Open a KCOV handle with a buffer of BKX_COVER_ENTRIES words: its fd. */
static int open_kcov_handle(uint64_t **area)
{
	int fd = open("/sys/kernel/debug/kcov", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		note("kcov: %s (no KCOV in this kernel, or debugfs is not mounted)", strerror(errno));
		return -1;
	}
	if (ioctl(fd, BKX_KCOV_INIT_TRACE, (unsigned long)BKX_COVER_ENTRIES) != 0) {
		note("kcov: KCOV_INIT_TRACE: %s", strerror(errno));
		close(fd);
		return -1;
	}
	*area = mmap(NULL, BKX_COVER_ENTRIES * sizeof(uint64_t), PROT_READ | PROT_WRITE,
		     MAP_SHARED, fd, 0);
	if (*area == MAP_FAILED) {
		note("kcov: mmap: %s", strerror(errno));
		*area = NULL;
		close(fd);
		return -1;
	}
	return fd;
}

static void open_kcov(void)
{
	pid_t pid;
	int status = 0;
	kcov_fd = open_kcov_handle(&cover);
	if (kcov_fd < 0)
		return;
	kcov_cmp_fd = open_kcov_handle(&cmp_cover);
	if (kcov_cmp_fd < 0)
		return;
	/* Comparisons need CONFIG_KCOV_ENABLE_COMPARISONS: try them once. */
	pid = fork();
	if (pid == 0)
		_exit(ioctl(kcov_cmp_fd, BKX_KCOV_ENABLE, BKX_KCOV_TRACE_CMP) == 0 ? 0 : 1);
	if (pid < 0 || waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0) {
		note("kcov: no comparisons (CONFIG_KCOV_ENABLE_COMPARISONS is off)");
		munmap(cmp_cover, BKX_COVER_ENTRIES * sizeof(uint64_t));
		cmp_cover = NULL;
		close(kcov_cmp_fd);
		kcov_cmp_fd = -1;
	}
}

/* Serve EXEC messages until the channel fails. */
static int serve(int is_init)
{
	uint8_t *program = malloc(BKP_MAX_PROGRAM);
	if (!program)
		return 1;
	for (;;) {
		uint8_t head[12], fixed[20];
		uint32_t magic, type, len, flags, timeout_ms, plen;
		uint64_t id;
		int got;
		/* A HELLO first, and again after the host went away: the write
		 * waits until a host is connected. */
		if (send_hello(is_init) != 0)
			return 1;
		for (;;) {
			got = read_all(chan_in, head, sizeof(head));
			if (got <= 0)
				break;
			magic = get32(head + 0);
			type = get32(head + 4);
			len = get32(head + 8);
			if (magic != BKX_MAGIC || type != BKX_EXEC || len < sizeof(fixed) ||
			    len - sizeof(fixed) > BKP_MAX_PROGRAM) {
				got = -1;
				break;
			}
			got = read_all(chan_in, fixed, sizeof(fixed));
			if (got <= 0)
				break;
			id = get64(fixed);
			flags = get32(fixed + 8);
			timeout_ms = get32(fixed + 12);
			plen = get32(fixed + 16);
			if (plen != len - sizeof(fixed)) {
				got = -1;
				break;
			}
			if (plen > 0) {
				got = read_all(chan_in, program, plen);
				if (got <= 0)
					break;
			}
			if (execute(id, flags, timeout_ms, program, plen) != 0) {
				got = -1;
				break;
			}
		}
		if (got < 0 && !is_init)
			return 1;
		if (got == 0 && !is_init)
			return 0;
		/* The host is gone, or sent what is not a message: wait for the
		 * next one. */
		usleep(100 * 1000);
	}
}

int main(int argc, char **argv)
{
	int is_init = getpid() == 1;
	const char *port = NULL;
	int stdio = 0, decode = 0, i;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
			port = argv[++i];
		else if (strcmp(argv[i], "--channel") == 0 && i + 1 < argc &&
			 strcmp(argv[i + 1], "stdio") == 0) {
			stdio = 1;
			i++;
		} else if (strcmp(argv[i], "--decode") == 0)
			decode = 1;
		else if (!is_init) {
			fprintf(stderr,
				"usage: %s [--port PATH | --channel stdio | --decode]\n", argv[0]);
			return 2;
		}
	}

	if (decode) {
		static uint8_t in[BKP_MAX_PROGRAM];
		static struct bkp_program prog;
		size_t len = 0;
		ssize_t n;
		while (len < sizeof(in) && (n = read(0, in + len, sizeof(in) - len)) > 0)
			len += (size_t)n;
		bkp_decode(in, len, &prog);
		bkp_dump(in, &prog, stdout);
		return 0;
	}

	signal(SIGPIPE, SIG_IGN);
	log_to_kmsg = is_init;
	if (is_init) {
		mount_or_note("devtmpfs", "/dev", "devtmpfs");
		mount_or_note("proc", "/proc", "proc");
		mount_or_note("sysfs", "/sys", "sysfs");
		mount_or_note("debugfs", "/sys/kernel/debug", "debugfs");
		load_modules();
	}
	results = mmap(NULL, sizeof(struct results), PROT_READ | PROT_WRITE,
		       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (results == MAP_FAILED) {
		note("mmap of the results area: %s", strerror(errno));
		if (is_init)
			power_off();
		return 1;
	}
	/* The stdio channel is for testing the protocol on a host. */
	if (!stdio)
		open_kcov();

	if (stdio) {
		chan_in = 0;
		chan_out = 1;
	} else {
		char found[300];
		if (!port) {
			if (find_port(found, sizeof(found)) != 0) {
				note("no virtio-serial port named %s (start qemu with -device "
				     "virtserialport,name=%s)",
				     BKX_PORT_NAME, BKX_PORT_NAME);
				if (is_init)
					power_off();
				return 1;
			}
			port = found;
		}
		chan_in = open(port, O_RDWR | O_CLOEXEC);
		if (chan_in < 0) {
			note("open %s: %s", port, strerror(errno));
			if (is_init)
				power_off();
			return 1;
		}
		chan_out = chan_in;
	}
	note("ready (kcov %s, comparisons %s)", kcov_fd >= 0 ? "on" : "off",
	     kcov_cmp_fd >= 0 ? "on" : "off");
	i = serve(is_init);
	if (is_init)
		power_off();
	return i;
}
