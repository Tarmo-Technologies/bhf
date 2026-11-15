// SPDX-License-Identifier: Apache-2.0

//! The sanitizer options bhf gives every child that must report a crash the
//! way the fuzz loop saw it: fuzz children, `bhf replay`, minimization,
//! `bhf report --backfill`, the direct harness command bhf prints, and each
//! finding's `replay.py`. One definition, so they cannot drift apart.
//!
//! bhf's keys go after the inherited value, which is kept verbatim: a
//! sanitizer takes a key's last value, so bhf's keys win and every other key
//! the operator set (a quoted suppressions path with a `:` in it too) reaches
//! the harness unchanged.

use serde_json::Value;

/// The `UBSAN_OPTIONS` keys that give a UBSan report its stack and the failed
/// check's name, as the fuzz loop records it.
pub const UBSAN_REPORT_OPTIONS: &str = "print_stacktrace=1:report_error_type=1";

/// The `ASAN_OPTIONS` keys bhf requires: the first report halts the run
/// (`abort_on_error=1`, or `abort_on_error=0` for an `emulated` child, whose
/// abort would make qemu-user dump its own address space), and it is
/// symbolized (`symbolize=1`, so the location a replay compares is not erased
/// by an inherited `symbolize=0`). A `leak` finding adds `detect_leaks=1`;
/// leak detection is never turned off.
pub fn asan_required(leak: bool, emulated: bool) -> String {
    let mut options = format!("{}:halt_on_error=1:symbolize=1", abort_on_error(emulated));
    if leak {
        options.push_str(":detect_leaks=1");
    }
    options
}

/// The `UBSAN_OPTIONS` keys bhf requires: the first report halts the run as a
/// crash (see [`asan_required`] for `emulated`), symbolized, with its stack
/// and check name ([`UBSAN_REPORT_OPTIONS`]).
pub fn ubsan_required(emulated: bool) -> String {
    format!(
        "{}:halt_on_error=1:symbolize=1:{UBSAN_REPORT_OPTIONS}",
        abort_on_error(emulated)
    )
}

fn abort_on_error(emulated: bool) -> &'static str {
    if emulated {
        "abort_on_error=0"
    } else {
        "abort_on_error=1"
    }
}

/// The inherited `<SAN>_OPTIONS` value, trimmed and otherwise verbatim, then
/// `required`: the sanitizer takes a key's last value, so bhf's keys win.
pub fn merge(inherited: Option<&str>, required: &str) -> String {
    match inherited.map(str::trim).filter(|s| !s.is_empty()) {
        Some(prefix) => format!("{prefix}:{required}"),
        None => required.to_owned(),
    }
}

/// Whether the finding record `raw` is a leak, which only reproduces with
/// leak detection on: rule BHF-208, an LSan report, or a `memory_leak`
/// exception.
pub fn is_leak_record(raw: &Value) -> bool {
    let text = |pointer: &str| {
        raw.pointer(pointer)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase()
    };
    text("/rule_id") == "bhf-208"
        || text("/exception/sanitizer") == "lsan"
        || text("/exception/name").contains("memory_leak")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn keys(options: &str) -> Vec<&str> {
        options
            .split(':')
            .map(|item| item.split_once('=').map_or(item, |(key, _)| key))
            .collect()
    }

    #[test]
    fn each_required_key_is_named_once() {
        for options in [
            asan_required(false, false),
            asan_required(true, false),
            asan_required(false, true),
            asan_required(true, true),
            ubsan_required(false),
            ubsan_required(true),
        ] {
            let keys = keys(&options);
            let mut unique = keys.clone();
            unique.sort_unstable();
            unique.dedup();
            assert_eq!(keys.len(), unique.len(), "{options}");
            assert!(options.contains("symbolize=1"), "{options}");
            assert!(options.contains("halt_on_error=1"), "{options}");
            assert!(!options.contains("detect_leaks=0"), "{options}");
        }
        assert_eq!(
            asan_required(false, false),
            "abort_on_error=1:halt_on_error=1:symbolize=1"
        );
        assert_eq!(
            asan_required(true, false),
            "abort_on_error=1:halt_on_error=1:symbolize=1:detect_leaks=1"
        );
        assert_eq!(
            ubsan_required(false),
            "abort_on_error=1:halt_on_error=1:symbolize=1:print_stacktrace=1:report_error_type=1"
        );
        assert_eq!(
            ubsan_required(true),
            "abort_on_error=0:halt_on_error=1:symbolize=1:print_stacktrace=1:report_error_type=1"
        );
    }

    #[test]
    fn an_emulated_child_does_not_abort() {
        for (native, emulated) in [
            (asan_required(false, false), asan_required(false, true)),
            (asan_required(true, false), asan_required(true, true)),
            (ubsan_required(false), ubsan_required(true)),
        ] {
            assert!(native.contains("abort_on_error=1"), "{native}");
            assert!(!native.contains("abort_on_error=0"), "{native}");
            assert_eq!(
                emulated,
                native.replace("abort_on_error=1", "abort_on_error=0")
            );
        }
    }

    #[test]
    fn the_inherited_value_is_kept_verbatim_before_the_required_keys() {
        assert_eq!(merge(None, "a=1"), "a=1");
        assert_eq!(merge(Some("  "), "a=1"), "a=1");
        assert_eq!(
            merge(Some(" suppressions='/d/sup:dir/u.supp' "), "a=1"),
            "suppressions='/d/sup:dir/u.supp':a=1"
        );
        assert_eq!(
            merge(Some("suppressions=C:\\s\\u.supp"), "a=1"),
            "suppressions=C:\\s\\u.supp:a=1"
        );
    }

    #[test]
    fn leak_records_are_recognised() {
        assert!(is_leak_record(&json!({"rule_id": "BHF-208"})));
        assert!(is_leak_record(&json!({"exception": {"sanitizer": "LSan"}})));
        assert!(is_leak_record(
            &json!({"exception": {"name": "LSAN_MEMORY_LEAK"}})
        ));
        assert!(!is_leak_record(&json!({"rule_id": "BHF-201"})));
        assert!(!is_leak_record(&Value::Null));
    }
}
