// SPDX-License-Identifier: Apache-2.0
//
// bhf dirty-page log: a QEMU TCG plugin for the qemu-system lane's
// `reset=fast` (the dirty-page fast snapshot).
//
// QEMU loads it with
//
//   qemu-system-<arch> ... -plugin ./libbhf_qemu_dirty_pages.so,log=/path/dirty.log
//
// and calls back on every guest memory access. Each store to RAM (not to a
// device) records the guest-physical page it touched, once, in a log file the
// plugin maps shared, so bhf can read which pages a run wrote and put back
// only those from its baseline. Stores to device registers (`is_io`) are left
// out, since the machine reset restores devices, but for a store to a bit-band
// alias: QEMU writes the RAM word it aliases itself, out of the plugin's
// sight, so the plugin records the aliased word's page. A store whose
// physical address QEMU does not report marks the log overflowed, so bhf
// restores the whole machine rather than miss the page.
//
// Arguments (all `key=value`):
//   log=PATH        the log file (required); created, or truncated, here
//   page_bits=N     log page size 2^N bytes, 6..=16 (default 8: 256 bytes)
//   capacity=N      pages the log holds between two clears, 1..=4194304
//                   (default 65536); past it the log says it overflowed
//
// Log layout, little-endian, fixed (bhf reads it with the same constants,
// crates/target_transport/src/fast_snapshot.rs):
//
//   0   u32 magic       0x50445842 ("BXDP")
//   4   u32 version     1
//   8   u32 page_bits
//   12  u32 capacity
//   16  u64 epoch       bhf adds one each time it empties the log
//   24  u32 count       pages recorded since the last clear (saturates)
//   28  u32 overflow    nonzero once a page did not fit
//   32  u64 seen        epoch + 1 of the last epoch the guest made a memory
//                       access in (0: none yet), so bhf can tell that this
//                       plugin, in the QEMU it drives, writes the log
//   40  BITBAND_WINDOWS x { u64 alias; u64 size; u64 source; }
//                       bit-band windows bhf found in QEMU's memory map: a
//                       store to [alias, alias + size) writes the RAM word at
//                       source + ((address - alias) >> 5); size 0 is unused
//   88  u64 pages[capacity]
//
// bhf only touches the log while the guest is stopped. A changed epoch tells
// the plugin the log was emptied, so its own index of recorded pages, tagged
// by epoch, needs no clearing.
//
// The plugin declares only the part of QEMU's plugin interface it calls.
// QEMU checks `qemu_plugin_version` against the range it supports: 1 fits
// QEMU 8.x; build with -DBHF_QEMU_PLUGIN_VERSION=N for another QEMU (the
// interface this file calls is the same in every version).

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef BHF_QEMU_PLUGIN_VERSION
#define BHF_QEMU_PLUGIN_VERSION 1
#endif

#define BHF_EXPORT __attribute__((visibility("default")))

typedef uint64_t qemu_plugin_id_t;
typedef uint32_t qemu_plugin_meminfo_t;
struct qemu_plugin_tb;
struct qemu_plugin_insn;
struct qemu_plugin_hwaddr;
typedef struct qemu_info_t qemu_info_t;

enum qemu_plugin_cb_flags {
  QEMU_PLUGIN_CB_NO_REGS,
  QEMU_PLUGIN_CB_R_REGS,
  QEMU_PLUGIN_CB_RW_REGS,
};

enum qemu_plugin_mem_rw {
  QEMU_PLUGIN_MEM_R = 1,
  QEMU_PLUGIN_MEM_W,
  QEMU_PLUGIN_MEM_RW,
};

typedef void (*qemu_plugin_vcpu_tb_trans_cb_t)(qemu_plugin_id_t id,
                                               struct qemu_plugin_tb *tb);
typedef void (*qemu_plugin_vcpu_mem_cb_t)(unsigned int vcpu_index,
                                          qemu_plugin_meminfo_t info,
                                          uint64_t vaddr, void *userdata);

extern void qemu_plugin_register_vcpu_tb_trans_cb(
    qemu_plugin_id_t id, qemu_plugin_vcpu_tb_trans_cb_t cb);
extern size_t qemu_plugin_tb_n_insns(const struct qemu_plugin_tb *tb);
extern struct qemu_plugin_insn *
qemu_plugin_tb_get_insn(const struct qemu_plugin_tb *tb, size_t idx);
extern void qemu_plugin_register_vcpu_mem_cb(struct qemu_plugin_insn *insn,
                                             qemu_plugin_vcpu_mem_cb_t cb,
                                             enum qemu_plugin_cb_flags flags,
                                             enum qemu_plugin_mem_rw rw,
                                             void *userdata);
extern unsigned int qemu_plugin_mem_size_shift(qemu_plugin_meminfo_t info);
extern bool qemu_plugin_mem_is_store(qemu_plugin_meminfo_t info);
extern struct qemu_plugin_hwaddr *
qemu_plugin_get_hwaddr(qemu_plugin_meminfo_t info, uint64_t vaddr);
extern bool qemu_plugin_hwaddr_is_io(const struct qemu_plugin_hwaddr *haddr);
extern uint64_t
qemu_plugin_hwaddr_phys_addr(const struct qemu_plugin_hwaddr *haddr);

BHF_EXPORT int qemu_plugin_version = BHF_QEMU_PLUGIN_VERSION;

#define LOG_MAGIC 0x50445842u
#define LOG_VERSION 1u
#define HEADER_BYTES 88u
#define BITBAND_WINDOWS 2

struct bitband_window {
  uint64_t alias;
  uint64_t size;
  uint64_t source;
};

struct log_header {
  uint32_t magic;
  uint32_t version;
  uint32_t page_bits;
  uint32_t capacity;
  uint64_t epoch;
  uint32_t count;
  uint32_t overflow;
  uint64_t seen;
  struct bitband_window bitband[BITBAND_WINDOWS];
};

_Static_assert(sizeof(struct log_header) == HEADER_BYTES, "log header layout");

static struct log_header *header;
static uint64_t *log_pages;
static unsigned page_bits = 8;
static uint32_t capacity = 65536;

/* The pages recorded in the current epoch: open addressing over twice the
 * capacity, each slot tagged with the epoch that filled it. */
static uint64_t *slot_page;
static uint64_t *slot_epoch;
static uint64_t slot_mask;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

/* Each vCPU thread skips the lock for the page it recorded last. */
static __thread uint64_t last_page = UINT64_MAX;
static __thread uint64_t last_epoch = UINT64_MAX;
/* The epoch this vCPU thread last told bhf it saw an access in. */
static __thread uint64_t seen_epoch = UINT64_MAX;

static uint64_t hash_page(uint64_t page) {
  page ^= page >> 33;
  page *= 0xff51afd7ed558ccdull;
  page ^= page >> 33;
  return page;
}

static void record(uint64_t page, uint64_t epoch) {
  pthread_mutex_lock(&lock);
  uint64_t slot = hash_page(page) & slot_mask;
  for (;;) {
    /* Slots are tagged epoch + 1, so a zeroed slot is always free. */
    if (slot_epoch[slot] != epoch + 1) {
      uint32_t count = header->count;
      if (count >= capacity) {
        __atomic_store_n(&header->overflow, 1u, __ATOMIC_RELEASE);
      } else {
        slot_epoch[slot] = epoch + 1;
        slot_page[slot] = page;
        log_pages[count] = page;
        __atomic_store_n(&header->count, count + 1, __ATOMIC_RELEASE);
      }
      break;
    }
    if (slot_page[slot] == page) {
      break;
    }
    slot = (slot + 1) & slot_mask;
  }
  pthread_mutex_unlock(&lock);
}

static void mark(uint64_t page, uint64_t epoch) {
  if (page == last_page && epoch == last_epoch) {
    return;
  }
  record(page, epoch);
  last_page = page;
  last_epoch = epoch;
}

/* Record the pages of the `size` bytes at physical `address`. */
static void mark_range(uint64_t address, uint64_t size, uint64_t epoch) {
  uint64_t last = address + size - 1;
  mark(address >> page_bits, epoch);
  if ((last >> page_bits) != (address >> page_bits)) {
    mark(last >> page_bits, epoch);
  }
}

/* A store to a device: when it is to a bit-band alias, record the RAM word
 * it writes, which QEMU's bit-band device writes without a plugin callback. */
static void mark_alias(uint64_t address, uint64_t size, uint64_t epoch) {
  for (int i = 0; i < BITBAND_WINDOWS; i++) {
    const struct bitband_window *window = &header->bitband[i];
    uint64_t alias = __atomic_load_n(&window->alias, __ATOMIC_RELAXED);
    uint64_t span = __atomic_load_n(&window->size, __ATOMIC_RELAXED);
    if (span == 0 || address - alias >= span) {
      continue;
    }
    uint64_t source = __atomic_load_n(&window->source, __ATOMIC_RELAXED);
    uint64_t offset = address - alias;
    uint64_t last = offset + size - 1;
    if (last >= span) {
      last = span - 1;
    }
    /* Each 32 bytes of alias is one byte of RAM; the device reads and
     * writes the word holding it. */
    mark_range((source + (offset >> 5)) & ~UINT64_C(3), 4, epoch);
    mark_range((source + (last >> 5)) & ~UINT64_C(3), 4, epoch);
  }
}

static void on_access(unsigned int vcpu_index, qemu_plugin_meminfo_t info,
                      uint64_t vaddr, void *userdata) {
  (void)vcpu_index;
  (void)userdata;
  uint64_t epoch = __atomic_load_n(&header->epoch, __ATOMIC_ACQUIRE);
  /* Any access shows bhf this plugin sees the guest it runs. */
  if (epoch != seen_epoch) {
    __atomic_store_n(&header->seen, epoch + 1, __ATOMIC_RELEASE);
    seen_epoch = epoch;
  }
  /* A load dirties nothing. */
  if (!qemu_plugin_mem_is_store(info)) {
    return;
  }
  struct qemu_plugin_hwaddr *hw = qemu_plugin_get_hwaddr(info, vaddr);
  if (hw == NULL) {
    /* QEMU could not say where the store went: the log cannot name the
     * page, so it says it overflowed, and bhf restores the whole machine. */
    __atomic_store_n(&header->overflow, 1u, __ATOMIC_RELEASE);
    return;
  }
  uint64_t address = qemu_plugin_hwaddr_phys_addr(hw);
  uint64_t size = UINT64_C(1) << qemu_plugin_mem_size_shift(info);
  if (qemu_plugin_hwaddr_is_io(hw)) {
    mark_alias(address, size, epoch);
    return;
  }
  mark_range(address, size, epoch);
}

static void on_translate(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
  (void)id;
  size_t count = qemu_plugin_tb_n_insns(tb);
  for (size_t i = 0; i < count; i++) {
    qemu_plugin_register_vcpu_mem_cb(qemu_plugin_tb_get_insn(tb, i), on_access,
                                     QEMU_PLUGIN_CB_NO_REGS, QEMU_PLUGIN_MEM_RW,
                                     NULL);
  }
}

static bool parse_number(const char *text, unsigned long long low,
                         unsigned long long high, unsigned long long *out) {
  char *end = NULL;
  errno = 0;
  unsigned long long value = strtoull(text, &end, 0);
  if (errno != 0 || end == text || *end != '\0' || value < low ||
      value > high) {
    return false;
  }
  *out = value;
  return true;
}

BHF_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                   const qemu_info_t *info, int argc,
                                   char **argv) {
  (void)info;
  const char *path = NULL;
  for (int i = 0; i < argc; i++) {
    const char *arg = argv[i];
    unsigned long long value = 0;
    if (strncmp(arg, "log=", 4) == 0) {
      path = arg + 4;
    } else if (strncmp(arg, "page_bits=", 10) == 0 &&
               parse_number(arg + 10, 6, 16, &value)) {
      page_bits = (unsigned)value;
    } else if (strncmp(arg, "capacity=", 9) == 0 &&
               parse_number(arg + 9, 1, 4194304, &value)) {
      capacity = (uint32_t)value;
    } else {
      fprintf(stderr, "bhf dirty-page log: bad argument %s\n", arg);
      return -1;
    }
  }
  if (path == NULL || *path == '\0') {
    fprintf(stderr, "bhf dirty-page log: log=PATH is required\n");
    return -1;
  }

  size_t bytes = HEADER_BYTES + (size_t)capacity * sizeof(uint64_t);
  int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) {
    fprintf(stderr, "bhf dirty-page log: open %s: %s\n", path, strerror(errno));
    return -1;
  }
  if (ftruncate(fd, (off_t)bytes) != 0) {
    fprintf(stderr, "bhf dirty-page log: size %s: %s\n", path, strerror(errno));
    close(fd);
    return -1;
  }
  void *map = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  close(fd);
  if (map == MAP_FAILED) {
    fprintf(stderr, "bhf dirty-page log: map %s: %s\n", path, strerror(errno));
    return -1;
  }

  uint64_t slots = 1;
  while (slots < 2 * (uint64_t)capacity) {
    slots <<= 1;
  }
  slot_page = calloc(slots, sizeof(uint64_t));
  slot_epoch = calloc(slots, sizeof(uint64_t));
  if (slot_page == NULL || slot_epoch == NULL) {
    fprintf(stderr, "bhf dirty-page log: out of memory for %llu slots\n",
            (unsigned long long)slots);
    return -1;
  }
  slot_mask = slots - 1;

  header = map;
  log_pages = (uint64_t *)((char *)map + HEADER_BYTES);
  header->version = LOG_VERSION;
  header->page_bits = page_bits;
  header->capacity = capacity;
  header->epoch = 0;
  header->count = 0;
  header->overflow = 0;
  header->seen = 0;
  memset(header->bitband, 0, sizeof(header->bitband));
  /* The magic goes last: a reader that sees it sees the rest. */
  __atomic_store_n(&header->magic, LOG_MAGIC, __ATOMIC_RELEASE);

  qemu_plugin_register_vcpu_tb_trans_cb(id, on_translate);
  return 0;
}
