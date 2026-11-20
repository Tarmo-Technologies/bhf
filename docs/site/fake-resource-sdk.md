<!-- SPDX-License-Identifier: Apache-2.0 -->

# Fake-resource SDK

bhf's runtrace shim (`bhf_runtrace_shim`) virtualises the libc boundary, so a target that depends on missing files, unreachable sockets or unset environment variables keeps running against a synthesised substitute. The fake-resource SDK is the contract for adding a new fake to the shim. See [Runtime virtualisation](runtime-virtualisation.md) for what the shim does at run time.

## Architecture

The shim is an `LD_PRELOAD` `cdylib` with strict allocation discipline: hooks use no `malloc`, `Box`, `Vec` or `String`, because the target process may already be inside its own allocator on the call path being interposed. Plugins are compile-time unit structs that implement `FakeResource`. The trait carries metadata only; the dynamic linker resolves the actual interceptors, `#[no_mangle] extern "C" fn` declarations, by symbol name.

A plain-data `ManifestEntry` slice (`MANIFEST`, defined in the `runtrace_manifest` crate, which the CLI can link, and re-exported as `manifest::MANIFEST`) mirrors the trait registry, so the CLI can list the inventory without linking the interceptors. A unit test in `registry.rs` keeps the two in sync.

## Adding a plugin

For a hypothetical `uname` plugin that fakes `uname`:

1. Create `crates/bhf_runtrace_shim/src/hooks/uname.rs` with:
   - a unit struct (`pub struct Uname;`);
   - an `impl crate::sdk::FakeResource for Uname` returning `name = "uname"`, the intercept list, an `is_enabled` that reads a `BHF_FAKE_UNAME` environment variable, and a one-line description;
   - a `#[no_mangle] extern "C" fn uname(...)` that fills a deterministic `utsname` when enabled and forwards to the real symbol otherwise.
2. Register the new module in `hooks/mod.rs`.
3. Append a matching `ManifestEntry::gated(...)` to `MANIFEST` in the `runtrace_manifest` crate, and a `&Uname` entry to `registry::REGISTRY`.
4. Run the cross-check unit test in `registry.rs`, which verifies that the two slices agree.

The `clock` plugin (`Clock` in `hooks/determinism.rs`, gated by `BHF_FAKE_CLOCK`) is a worked example of a hook that libc's own start-up and a sanitizer runtime also reach. It resolves the real functions in a load-time constructor instead of through `ResolvedFn`, and reads its gate from `environ` instead of calling `getenv`, because a lazy lookup inside that hook re-entered the dynamic loader.

## Allocation discipline

Every line of hook code runs inside an arbitrary target process on an arbitrary call path. Do not:

- allocate (`malloc`, `Box::new`, `String`, `Vec::new`, `format!`);
- acquire locks other than the shim's own `HookGuard`;
- recurse into the symbol being intercepted (use `HookGuard` to detect re-entry);
- read configuration from disk.

Do:

- read configuration from environment variables, cached in an `AtomicU8` on first access;
- emit audit events through `jsonl::Builder`, which writes to a fixed-size stack buffer and calls `libc::write` directly;
- forward to the real libc symbol through the `dlsym::ResolvedFn` helper.

## Diagnostics

`bhf auto --list-fakes` prints the inventory (output of a 0.3.0-dev build):

```
NAME                STATE        ENV_VAR                     INTERCEPTS
env                 always-on    (always-on)                 getenv secure_getenv
net                 always-on    (always-on)                 connect getaddrinfo
desocket            env-gated    BHF_DESOCKET                bind listen accept accept4 getsockname getpeername setsockopt bhf_shim_desocket_active
fs                  always-on    (always-on)                 open openat close __xstat fopen fopen64 fdopen fclose unlink unlinkat remove mkdir mkdirat rmdir rename renameat symlink symlinkat link linkat truncate
dl                  always-on    (always-on)                 dlopen dlmopen dlclose
dlsym               always-on    (always-on)                 dlsym
proc                always-on    (always-on)                 system popen execv execvp execvpe execve fexecve posix_spawn posix_spawnp
format              always-on    (always-on)                 printf fprintf sprintf snprintf dprintf asprintf vprintf vfprintf vsprintf vsnprintf vdprintf vasprintf __printf_chk __fprintf_chk __sprintf_chk __snprintf_chk __dprintf_chk __asprintf_chk __vprintf_chk __vfprintf_chk __vsprintf_chk __vsnprintf_chk __vdprintf_chk __vasprintf_chk
assertion           always-on    (always-on)                 __assert_fail __assert_perror_fail
identity            env-gated    BHF_FAKE_IDENTITY           getpid getuid getgid getppid
cmplog              env-gated    BHF_CMPLOG                  strcmp strncmp memcmp
mem                 always-on    (always-on)                 shm_open shm_unlink shmget shmat shmdt shmctl mmap mmap64
mqueue              always-on    (always-on)                 mq_open mq_receive mq_timedreceive mq_send mq_getattr mq_close mq_unlink
sql                 always-on    (always-on)                 sqlite3_exec sqlite3_prepare sqlite3_prepare_v2 sqlite3_prepare_v3 PQexec PQexecParams mysql_query mysql_real_query
determinism         env-gated    BHF_FAKE_DETERMINISM        rand srand random getrandom
clock               env-gated    BHF_FAKE_CLOCK              clock_gettime gettimeofday time clock timespec_get clock_nanosleep pthread_cond_timedwait pthread_cond_clockwait sem_timedwait sem_clockwait
ioctl               always-on    (always-on)                 ioctl
rtos                always-on    (always-on)                 msgQCreate msgQReceive msgQSend msgQDelete semBCreate semMCreate semCCreate semTake semGive semDelete xQueueCreate xQueueGenericCreate xQueueReceive xQueueGenericReceive xQueueGenericSend CFE_SB_CreatePipe CFE_SB_RcvMsg CFE_SB_ReceiveBuffer bhf_shim_mmio_fill
sched               env-gated    BHF_SCHED                   pthread_create pthread_join bhf_sched_yield
```

## Reference plugin: Identity

`hooks/identity.rs` is the reference plugin. With `BHF_FAKE_IDENTITY=1` set, the four POSIX identity calls return deterministic constants:

| Symbol    | Faked value |
| --------- | ----------- |
| `getpid`  | 4242        |
| `getuid`  | 1000        |
| `getgid`  | 1000        |
| `getppid` | 1           |

Set it when consecutive runs must look like the same process, as in differential fuzzing or reproducible replay. bhf does not set it for you.

## See also

- [Runtime virtualisation overview](runtime-virtualisation.md)
- [Architecture](architecture.md)
