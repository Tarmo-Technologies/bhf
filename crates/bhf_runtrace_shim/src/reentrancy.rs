// SPDX-License-Identifier: Apache-2.0

//! Thread-local "in_hook" flag. If a hook winds up calling another
//! libc function we've also hooked (e.g. open() inside the JSONL
//! writer's open-on-first-use path), the second hook needs to
//! short-circuit and call the real syscall without logging — else
//! we'd recurse forever.

use std::cell::Cell;

thread_local! {
    static IN_HOOK: Cell<bool> = const { Cell::new(false) };
    /// How many [`OwnWork`] marks the calling thread holds.
    static OWN_WORK: Cell<u32> = const { Cell::new(0) };
}

/// Returns true if the current thread is already inside a hook. The
/// caller is expected to short-circuit (call the real syscall, skip
/// logging) when this returns true.
pub fn entering_hook() -> bool {
    IN_HOOK.with(|f| {
        if f.get() {
            true
        } else {
            f.set(true);
            false
        }
    })
}

pub fn leaving_hook() {
    IN_HOOK.with(|f| f.set(false));
}

/// Whether the calling thread is running the shim's own code: inside one of
/// its hooks ([`HookGuard`]) or one of its own computations ([`OwnWork`]). A
/// comparison made meanwhile is the shim's, never the target's.
pub fn in_shim() -> bool {
    IN_HOOK.try_with(Cell::get).unwrap_or(false)
        || OWN_WORK.try_with(|depth| depth.get() > 0).unwrap_or(false)
}

/// Non-zero while the calling thread is running the shim's own code
/// ([`in_shim`]). bhf's C/C++ driver asks before recording a comparison: the
/// shim's own string and buffer compares reach the sanitizer's comparison
/// hooks too, and are not the target's.
#[no_mangle]
pub extern "C" fn bhf_shim_in_hook() -> libc::c_int {
    in_shim() as libc::c_int
}

/// Marks the calling thread as running the shim's own code while it lives,
/// without what a [`HookGuard`] also does: a hook entered meanwhile still
/// records its event. The shim compares paths, names and modes with slice
/// equality, which calls `memcmp`/`bcmp`; in a sanitized program those are
/// the sanitizer's interceptors, whose comparison hooks (bhf's driver) record
/// what they compare, and in any other program `memcmp` is the shim's own
/// cmplog hook. Both leave out a comparison made under this mark
/// ([`in_shim`]), so the shim's constants never reach the comparison log the
/// engine learns from. Every check of the shim that compares bytes and may
/// run outside a hook guard holds one.
pub struct OwnWork {
    entered: bool,
}

impl OwnWork {
    pub fn enter() -> Self {
        let entered = OWN_WORK
            .try_with(|depth| depth.set(depth.get().saturating_add(1)))
            .is_ok();
        OwnWork { entered }
    }
}

impl Drop for OwnWork {
    fn drop(&mut self) {
        if self.entered {
            let _ = OWN_WORK.try_with(|depth| depth.set(depth.get().saturating_sub(1)));
        }
    }
}

/// Run `f`, the shim's own computation, under an [`OwnWork`] mark.
pub fn own_work<T>(f: impl FnOnce() -> T) -> T {
    let _own = OwnWork::enter();
    f()
}

/// `a == b` without calling `memcmp` or `bcmp` and without touching
/// thread-local storage: for checks that run before a mark can be taken,
/// such as the `dlsym` lookups a sanitizer makes while it resolves its
/// interceptors (its `__tls_get_addr` interceptor has nothing to call yet),
/// and the shim's own `memcmp` hook reading whether it records at all.
pub fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // One pass with no early exit, which the compiler does not turn back
    // into a library comparison.
    a.iter().zip(b).fold(0u8, |differ, (x, y)| differ | (x ^ y)) == 0
}

/// RAII guard for the in_hook flag. Constructing this returns Err
/// when we're already inside a hook; the caller short-circuits in
/// that case. Drop clears the flag.
pub struct HookGuard;

impl HookGuard {
    pub fn acquire() -> Option<Self> {
        if entering_hook() {
            None
        } else {
            Some(HookGuard)
        }
    }
}

impl Drop for HookGuard {
    fn drop(&mut self) {
        leaving_hook();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shim's own work marks the thread as the shim's for the driver's
    /// comparison hooks, nested or not, without keeping a hook from
    /// recording; a hook guard marks it too.
    #[test]
    fn own_work_marks_the_thread_without_suppressing_hooks() {
        assert_eq!(bhf_shim_in_hook(), 0);
        {
            let _outer = OwnWork::enter();
            assert_eq!(bhf_shim_in_hook(), 1);
            assert_eq!(own_work(|| bhf_shim_in_hook()), 1);
            assert_eq!(bhf_shim_in_hook(), 1, "the inner mark leaves the outer one");
            let guard = HookGuard::acquire();
            assert!(guard.is_some(), "a hook still records under the mark");
            drop(guard);
            assert_eq!(bhf_shim_in_hook(), 1);
        }
        assert_eq!(bhf_shim_in_hook(), 0);
        let guard = HookGuard::acquire().expect("not in a hook");
        assert_eq!(bhf_shim_in_hook(), 1);
        drop(guard);
        assert_eq!(bhf_shim_in_hook(), 0);
        // Another thread's mark is its own.
        let _mark = OwnWork::enter();
        std::thread::spawn(|| assert_eq!(bhf_shim_in_hook(), 0))
            .join()
            .unwrap();
    }
}
