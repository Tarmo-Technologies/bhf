// SPDX-License-Identifier: Apache-2.0
//
// Source / sink / plain-English explanation + bug-class patch hints derived from
// a sanitizer crash's stack. Modeled on a real C LeakSanitizer finding (nanosvg)
// whose stack is malloc -> nsvg__createParser -> nsvgParse -> bhf harness.

use actionability::{backfill_actionability, patch_hints_for_finding, RunMode, Verdict};
use serde_json::json;

#[test]
fn runtime_message_source_prefix_backfills_sink_and_fix_location() {
    let raw = json!({
        "rule_id": "BHF-205",
        "target": { "name": "decode_index" },
        "exception": {
            "name": "UBSAN_ARRAY_INDEX_OUT_OF_BOUNDS",
            "message": "/project/src/decode.c:41:17: runtime error: index -2 out of bounds for type 'char[6]'"
        }
    });

    let record = backfill_actionability(RunMode::Reporting, &raw, None);
    let sink = record.sink.expect("message source should become the sink");
    assert_eq!(sink.file.as_deref(), Some("/project/src/decode.c"));
    assert_eq!(sink.line, Some(41));
    assert_eq!(sink.function, "decode_index");

    let fix = record
        .fix_location
        .expect("message source should be fixable");
    assert_eq!(fix.path, "/project/src/decode.c");
    assert_eq!(fix.line, Some(41));
    assert_eq!(fix.col, Some(17));
    assert_eq!(fix.reason, "exception_message_source");
}

#[test]
fn sink_skips_rust_stdlib_frame_and_resolves_in_project_frame() {
    // #32: a Rust-lane crash's top frame is the toolchain stdlib
    // (core::ptr::copy_nonoverlapping at library/core); the sink / fix_location
    // must resolve to the first IN-PROJECT frame, not the stdlib.
    let raw = json!({
        "rule_id": "BHF-203",
        "harness_id": "H-rust",
        "paths": { "testcase": "crash.bin" },
        "exception": {
            "name": "ASAN_RUST_PANIC",
            "sanitizer": "asan",
            "stack": [
                { "function": "core::ptr::copy_nonoverlapping::<u8>", "file": "/rustc/abc123/library/core/src/intrinsics.rs", "line": 3140 },
                { "function": "json::short::Short::from_slice", "file": "/proj/src/short.rs", "line": 60 }
            ]
        }
    });
    let record = backfill_actionability(RunMode::Reporting, &raw, None);
    let sink = record.sink.expect("sink");
    assert_eq!(sink.function, "json::short::Short::from_slice");
    assert_eq!(sink.file.as_deref(), Some("/proj/src/short.rs"));
    let fix = record.fix_location.expect("fix location");
    assert!(
        fix.path.contains("short.rs"),
        "fix must point at the in-project frame, got {}",
        fix.path
    );
    assert!(
        !fix.path.contains("library/core"),
        "fix must not point into the Rust stdlib: {}",
        fix.path
    );
}

#[test]
fn sink_skips_crt_start_stub_so_harness_only_stack_has_no_sink() {
    // #38: `_start` (the CRT entry stub) must be filtered like other runtime
    // frames; a harness + CRT-only stack must NOT resolve fix_location to `_start`.
    let raw = json!({
        "rule_id": "BHF-206",
        "harness_id": "H-crt",
        "exception": {
            "name": "ASAN_SEGV",
            "sanitizer": "asan",
            "stack": [
                { "function": "_start", "file": null, "line": null },
                { "function": "bhf_run_one", "file": "/w/auto/H/main.c", "line": 12 }
            ]
        }
    });
    let record = backfill_actionability(RunMode::Reporting, &raw, None);
    assert!(
        record.sink.is_none(),
        "harness+CRT-only stack has no target sink"
    );
    assert!(
        record.fix_location.is_none(),
        "fix_location must never be `_start`: {:?}",
        record.fix_location
    );
}

#[test]
fn sink_keeps_start_named_target_function_when_it_resolves_to_source() {
    // Guard: only the bare CRT `_start` stub is filtered — a real target function
    // (with a source line) below it still resolves as the sink.
    let raw = json!({
        "rule_id": "BHF-201",
        "harness_id": "H-ok",
        "exception": {
            "name": "ASAN_HEAP_BUFFER_OVERFLOW",
            "sanitizer": "asan",
            "stack": [
                { "function": "_start", "file": null, "line": null },
                { "function": "real_parse", "file": "/src/p.c", "line": 9 }
            ]
        }
    });
    let sink = backfill_actionability(RunMode::Reporting, &raw, None)
        .sink
        .expect("real target frame below _start is the sink");
    assert_eq!(sink.function, "real_parse");
}

#[test]
fn sink_skips_libc_internal_frames_and_resolves_project_frame() {
    // A glibc stdio internal (_IO_fread) is never the sink — the project caller
    // above it is. Previously the fix/sink pointed at libio internals.
    let raw = json!({
        "rule_id": "BHF-201",
        "harness_id": "H-io",
        "paths": { "testcase": "crash.bin" },
        "exception": {
            "name": "ASAN_HEAP_BUFFER_OVERFLOW",
            "sanitizer": "asan",
            "stack": [
                { "function": "_IO_fread", "file": "libio/iofread.c", "line": 38 },
                { "function": "real_parse", "file": "/src/p.c", "line": 42 }
            ]
        }
    });
    let record = backfill_actionability(RunMode::Reporting, &raw, None);
    let sink = record.sink.expect("sink");
    assert_eq!(sink.function, "real_parse");
    assert_eq!(sink.file.as_deref(), Some("/src/p.c"));
    assert_eq!(sink.line, Some(42));
}

#[test]
fn leak_in_bhf_decode_helper_is_demoted_to_lab_only() {
    // A LeakSanitizer report whose whole stack is allocator + the generated
    // `bhf_c_string` decode helper (c_runtime/bhf_decode.h) is bhf
    // scaffolding the one-shot harness drops, not a target leak.
    let raw = json!({
        "rule_id": "BHF-208",
        "harness_id": "H-leak",
        "paths": { "testcase": "t.bin" },
        "exception": {
            "name": "LSAN_MEMORY_LEAK",
            "message": "==1==ERROR: LeakSanitizer: detected memory leaks",
            "sanitizer": "lsan",
            "stack": [
                { "function": "malloc" },
                { "function": "bhf_c_string", "file": "/work/auto/H/bhf_decode.h", "line": 88 }
            ]
        }
    });
    let record = backfill_actionability(RunMode::Reporting, &raw, None);
    assert_eq!(record.verdict, Verdict::LabOnly);
}

#[test]
fn sink_keeps_anonymous_namespace_in_function_name() {
    // The "(anonymous namespace)" scope token is not an argument list, so the
    // top frame name must survive intact into the sink function.
    let raw = json!({
        "rule_id": "BHF-201",
        "harness_id": "H-pugi",
        "paths": { "testcase": "c.bin" },
        "exception": {
            "name": "ASAN_HEAP_BUFFER_OVERFLOW",
            "sanitizer": "asan",
            "stack": [
                {
                    "function": "pugi::impl::(anonymous namespace)::strlength_wide(wchar_t const*)",
                    "file": "/src/pugixml.cpp",
                    "line": 220
                }
            ]
        }
    });
    let record = backfill_actionability(RunMode::Reporting, &raw, None);
    let sink = record.sink.expect("sink");
    assert_eq!(
        sink.function,
        "pugi::impl::(anonymous namespace)::strlength_wide"
    );
}

fn nanosvg_leak() -> serde_json::Value {
    json!({
        "id": "F-0000-1028b5d3",
        "rule_id": "BHF-208",
        "harness_id": "H-X0C65-56DA8C32",
        "dialect": "unknown",
        "paths": { "testcase": "testcase.bin" },
        "exception": {
            "name": "LSAN_MEMORY_LEAK",
            "message": "==2306327==ERROR: LeakSanitizer: detected memory leaks",
            "sanitizer": "lsan",
            "stack": [
                { "function": "malloc" },
                { "function": "nsvg__createParser()", "file": "/src/nanosvg.h", "line": 646 },
                { "function": "nsvgParse", "file": "/src/nanosvg.h", "line": 3178 },
                { "function": "bhf_run_one(unsigned char const*, unsigned long)", "file": "/work/auto/H/main.cpp", "line": 39 }
            ]
        }
    })
}

#[test]
fn sink_is_top_project_frame_skipping_allocator_and_harness() {
    let record = backfill_actionability(RunMode::Reporting, &nanosvg_leak(), None);
    let sink = record.sink.expect("sink");
    // malloc (allocator) is skipped; the project allocation site is the sink.
    assert_eq!(sink.function, "nsvg__createParser");
    assert_eq!(sink.file.as_deref(), Some("/src/nanosvg.h"));
    assert_eq!(sink.line, Some(646));
}

#[test]
fn source_is_harness_entry_plus_reproducer() {
    let record = backfill_actionability(RunMode::Reporting, &nanosvg_leak(), None);
    let source = record.source.expect("source");
    assert_eq!(source.kind, "harness");
    assert_eq!(source.entry, "H-X0C65-56DA8C32");
    assert_eq!(source.testcase, "testcase.bin");
}

#[test]
fn explanation_is_plain_english_leak_naming_sink_and_reproducer() {
    let record = backfill_actionability(RunMode::Reporting, &nanosvg_leak(), None);
    let explanation = record.explanation.expect("explanation");
    assert!(explanation.contains("memory leak"), "{explanation}");
    assert!(explanation.contains("nsvg__createParser"), "{explanation}");
    assert!(explanation.contains("testcase.bin"), "{explanation}");
    // No jargon like the sanitizer's internal label.
    assert!(!explanation.contains("LSAN"), "{explanation}");
}

#[test]
fn leak_patch_hint_advises_freeing_on_every_exit_path_and_references_sink() {
    let hints = patch_hints_for_finding(&nanosvg_leak());
    assert_eq!(hints.len(), 1);
    let hint = &hints[0];
    assert!(
        hint.guidance.to_ascii_lowercase().contains("free"),
        "{}",
        hint.guidance
    );
    assert!(hint.guidance.contains("exit path"), "{}", hint.guidance);
    assert!(
        hint.guidance.contains("nsvg__createParser"),
        "{}",
        hint.guidance
    );
    // Advisory only — no fabricated diff.
    assert!(hint.diff.is_none());
}

#[test]
fn heap_overflow_explanation_and_hint_are_bug_class_specific() {
    let raw = json!({
        "rule_id": "BHF-777",
        "harness_id": "H-ovf",
        "paths": { "testcase": "crash-abc.bin" },
        "exception": {
            "name": "ASAN_HEAP_BUFFER_OVERFLOW",
            "sanitizer": "asan",
            "stack": [
                { "function": "__asan_memcpy" },
                { "function": "copy_chunk", "file": "src/io.c", "line": 88 }
            ]
        }
    });
    let record = backfill_actionability(RunMode::Reporting, &raw, None);
    let explanation = record.explanation.expect("explanation");
    assert!(explanation.contains("buffer overflow"), "{explanation}");
    assert!(explanation.contains("copy_chunk"), "{explanation}");
    assert!(explanation.contains("crash-abc.bin"), "{explanation}");

    let hints = patch_hints_for_finding(&raw);
    assert_eq!(hints.len(), 1);
    assert!(
        hints[0].guidance.to_ascii_lowercase().contains("bounds"),
        "{}",
        hints[0].guidance
    );
    assert!(
        hints[0].guidance.contains("src/io.c:88"),
        "{}",
        hints[0].guidance
    );
}

#[test]
fn null_deref_explanation_classifies_as_crash() {
    let raw = json!({
        "harness_id": "H-null",
        "exception": {
            "name": "SEGV",
            "message": "SEGV on unknown address 0x000000000000",
            "stack": [
                { "function": "deref_it", "file": "src/x.c", "line": 5 }
            ]
        }
    });
    let record = backfill_actionability(RunMode::Reporting, &raw, None);
    let explanation = record.explanation.expect("explanation");
    assert!(explanation.contains("null-pointer"), "{explanation}");
    let hints = patch_hints_for_finding(&raw);
    assert!(
        hints[0].guidance.to_ascii_lowercase().contains("null"),
        "{}",
        hints[0].guidance
    );
}

/// A UBSan report without a stack names a file and line but no function. No
/// surface may then render an empty name: no "``" in the explanation and no
/// "(``)" in the fix guidance.
#[test]
fn frameless_ubsan_finding_never_renders_an_empty_function_name() {
    let raw = json!({
        "rule_id": "BHF-210",
        "harness_id": "H-C0001",
        "paths": { "testcase": "testcase.bin" },
        "exception": {
            "name": "UBSAN_UNDEFINED_BEHAVIOR",
            "sanitizer": "ubsan",
            "message": "/src/widget/classify.c:3:5: runtime error: execution reached the end of a value-returning function without returning a value",
            "stack": []
        }
    });
    let record = backfill_actionability(RunMode::Reporting, &raw, None);
    let sink = record.sink.expect("the message location is the sink");
    assert_eq!(sink.function, "");
    let explanation = record.explanation.expect("explanation");
    assert!(!explanation.contains("``"), "{explanation}");
    assert!(explanation.contains("classify.c:3"), "{explanation}");
    for hint in patch_hints_for_finding(&raw) {
        assert!(!hint.guidance.contains("``"), "{}", hint.guidance);
        assert!(hint.guidance.contains("classify.c:3"), "{}", hint.guidance);
    }
}

/// An interceptor frame symbolized to the sanitizer runtime's own source is
/// still runtime: the sink is the project frame that called `memcmp`.
#[test]
fn sink_skips_sanitizer_interceptor_frames_that_carry_a_source_file() {
    let runtime = "/llvm/compiler-rt/lib/sanitizer_common/sanitizer_common_interceptors.inc";
    let raw = json!({
        "rule_id": "BHF-201",
        "exception": {
            "name": "ASAN_HEAP_BUFFER_OVERFLOW",
            "sanitizer": "asan",
            "stack": [
                { "function": "__memcmp_avx2_movbe", "file": "string/../sysdeps/x86_64/multiarch/memcmp-avx2-movbe.S", "line": 84 },
                { "function": "MemcmpInterceptorCommon(void*, int (*)(void const*, void const*, unsigned long), void const*, void const*, unsigned long)", "file": runtime, "line": 813 },
                { "function": "bcmp", "file": runtime, "line": 860 },
                { "function": "Widget::parse_record(unsigned char const*)", "file": "/src/widget/parser.cc", "line": 11 }
            ]
        }
    });
    let record = backfill_actionability(RunMode::Reporting, &raw, None);
    let sink = record.sink.expect("sink");
    assert_eq!(sink.function, "Widget::parse_record");
    assert_eq!(sink.line, Some(11));
}

/// A project built with its paths made relative (`-ffile-prefix-map=<src>=.`)
/// can keep its sources in directories named like glibc components (`io/`,
/// `misc/`, `posix/`). A frame there is the project's unless its function is
/// libc's own, so it stays the sink; glibc's start-up frames stay noise.
#[test]
fn sink_keeps_project_frames_in_dirs_named_like_glibc_components() {
    let raw = json!({
        "rule_id": "BHF-205",
        "exception": {
            "name": "UBSAN_SIGNED_INTEGER_OVERFLOW",
            "sanitizer": "ubsan",
            "stack": [
                { "function": "read_scaled(int)", "file": "./io/scaled_reader.cpp", "line": 4 },
                { "function": "Widget::load()", "file": "./misc/widget.cpp", "line": 9 },
                { "function": "__libc_start_call_main", "file": "../sysdeps/nptl/libc_start_call_main.h", "line": 58 },
                { "function": "__libc_start_main", "file": "csu/../csu/libc-start.c", "line": 360 }
            ]
        }
    });
    let record = backfill_actionability(RunMode::Reporting, &raw, None);
    let sink = record.sink.expect("the project frame is the sink");
    assert_eq!(sink.function, "read_scaled");
    assert_eq!(sink.file.as_deref(), Some("./io/scaled_reader.cpp"));
    assert_eq!(sink.line, Some(4));
    for (function, file) in [
        ("read_scaled(int)", "./io/scaled_reader.cpp"),
        ("Widget::load()", "misc/widget.cpp"),
        ("parse_options", "posix/options.c"),
        ("load_section", "./elf/loader.c"),
        ("walk_tree", "io/tree_walk.c"),
    ] {
        assert!(
            !actionability::is_runtime_noise_frame(function, Some(file)),
            "{function} at {file} is project code"
        );
    }
    for (function, file) in [
        (
            "__libc_start_call_main",
            "../sysdeps/nptl/libc_start_call_main.h",
        ),
        ("__libc_start_main", "csu/../csu/libc-start.c"),
        ("__GI___libc_read", "io/read.c"),
        ("raise", "signal/../sysdeps/posix/raise.c"),
        ("abort", "stdlib/abort.c"),
        ("__assert_fail", "assert/assert.c"),
        ("_dl_start_user", "elf/rtld.c"),
        ("start_thread", "nptl/pthread_create.c"),
        ("_IO_new_fopen", "libio/iofopen.c"),
        // glibc's static helpers carry no reserved prefix; their source file
        // is glibc's own.
        ("parse_expression", "posix/regcomp.c"),
        ("re_search_internal", "./posix/regexec.c"),
        ("glob_in_dir", "posix/glob.c"),
        ("call_init", "./elf/dl-init.c"),
        ("dl_open_worker", "elf/dl-open.c"),
        ("fts_build", "io/fts.c"),
        ("maybe_split_for_insert", "misc/tsearch.c"),
    ] {
        assert!(
            actionability::is_runtime_noise_frame(function, Some(file)),
            "{function} at {file} is libc"
        );
    }
}
