// SPDX-License-Identifier: Apache-2.0

//! C++ standard-library frames are not part of the root-cause key: two
//! out-of-bounds reads through the same `std::unique_ptr` accessor in two
//! project functions are two root causes. The reports are the ones clang 18
//! with libstdc++ 14 prints for a `vector<unique_ptr<Item>>` read past its end
//! in `users.cpp` and in `groups.cpp` (paths shortened).

use corpus::cluster::{cluster_for_sanitizer, normalize_frames, InputFrame};
use corpus::sanitizer::parse_sanitizer_report;

const UNIQUE_PTR_H: &str =
    "/usr/bin/../lib/gcc/x86_64-linux-gnu/14/../../../../include/c++/14/bits/unique_ptr.h";

/// The report of an out-of-bounds `vector<unique_ptr<Item>>` read in
/// `function` at `file:line`.
fn report(function: &str, file: &str, line: u32) -> String {
    format!(
        "=================================================================\n\
         ==547251==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x503000000070 at pc 0x5e484ecbe463 bp 0x7fff9dd67c20 sp 0x7fff9dd67c18\n\
         READ of size 8 at 0x503000000070 thread T0\n\
         \x20   #0 0x5e484ecbe462 in std::__uniq_ptr_impl<Item, std::default_delete<Item>>::_M_ptr() const {UNIQUE_PTR_H}:193:51\n\
         \x20   #1 0x5e484ecbe424 in std::unique_ptr<Item, std::default_delete<Item>>::get() const {UNIQUE_PTR_H}:464:21\n\
         \x20   #2 0x5e484ecbc2b4 in std::unique_ptr<Item, std::default_delete<Item>>::operator->() const {UNIQUE_PTR_H}:457:9\n\
         \x20   #3 0x5e484ecbbed2 in {function}(unsigned char const*) /src/widget/{file}:{line}:10\n\
         \x20   #4 0x5e484ecbbcef in main /src/widget/main.cpp:6:73\n\
         \x20   #5 0x7478a862a1c9 in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16\n\
         \n\
         0x503000000070 is located 16 bytes after 32-byte region [0x503000000040,0x503000000060)\n\
         allocated by thread T0 here:\n\
         \x20   #0 0x5e484ecb9841 in operator new(unsigned long) (/src/widget/stl+0x105841)\n\
         \x20   #1 0x5e484ecbdbf7 in std::__new_allocator<std::unique_ptr<Item, std::default_delete<Item>>>::allocate(unsigned long, void const*) /usr/bin/../lib/gcc/x86_64-linux-gnu/14/../../../../include/c++/14/bits/new_allocator.h:151:27\n\
         \n\
         SUMMARY: AddressSanitizer: heap-buffer-overflow {UNIQUE_PTR_H}:193:51 in std::__uniq_ptr_impl<Item, std::default_delete<Item>>::_M_ptr() const\n\
         ==547251==ABORTING\n"
    )
}

#[test]
fn stl_frames_do_not_merge_distinct_project_callers() {
    let users = parse_sanitizer_report(&report("user_lookup", "users.cpp", 8)).unwrap();
    let groups = parse_sanitizer_report(&report("group_lookup", "groups.cpp", 9)).unwrap();
    let (users_key, groups_key) = (
        cluster_for_sanitizer(&users),
        cluster_for_sanitizer(&groups),
    );
    assert_eq!(users_key.frames, ["user_lookup"]);
    assert_eq!(groups_key.frames, ["group_lookup"]);
    assert_ne!(users_key.full, groups_key.full);
    assert!(!users_key.fallback && !groups_key.fallback);
    // The same bug reached again is still one root cause.
    let again = parse_sanitizer_report(&report("user_lookup", "users.cpp", 8)).unwrap();
    assert_eq!(cluster_for_sanitizer(&again).full, users_key.full);
}

/// A frame in a C++ standard-library header is the library's whatever its
/// name: libc++'s `include/c++/v1`, a demangled template with its return
/// type first, `__gnu_cxx::` helpers, and MSVC's STL headers.
#[test]
fn stl_header_frames_are_dropped_from_the_key() {
    let frame = |function: &str, file: &str| InputFrame {
        function: function.to_owned(),
        file: Some(file.to_owned()),
        line: Some(10),
    };
    let frames = normalize_frames(&[
        frame(
            "void std::vector<Item, std::allocator<Item>>::_M_realloc_append<Item>(Item&&)",
            "/usr/include/c++/14/bits/vector.tcc",
        ),
        frame(
            "__gnu_cxx::__normal_iterator<Item*, std::vector<Item>>::operator*() const",
            "/usr/include/c++/14/bits/stl_iterator.h",
        ),
        frame(
            "std::__1::vector<int, std::__1::allocator<int>>::operator[](unsigned long)",
            "/usr/lib/llvm-18/bin/../include/c++/v1/vector",
        ),
        frame(
            "std::vector<int,std::allocator<int> >::operator[]",
            "C:\\Program Files\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Tools\\MSVC\\14.40.33807\\include\\vector",
        ),
        frame("parse_record(char const*)", "/src/widget/parse.cpp"),
        frame("Widget::copy_at(unsigned long)", "/src/widget/widget.cpp"),
    ]);
    assert_eq!(frames, ["parse_record", "Widget::copy_at"]);
}

/// A crash with no project frame among its frames keeps the standard
/// library's: they are all that tells it apart.
#[test]
fn an_all_stl_stack_keeps_its_frames() {
    let frames = normalize_frames(&[
        InputFrame {
            function: "std::__throw_out_of_range_fmt(char const*, ...)".to_owned(),
            file: None,
            line: None,
        },
        InputFrame {
            function: "std::vector<int, std::allocator<int>>::_M_range_check(unsigned long) const"
                .to_owned(),
            file: Some("/usr/include/c++/14/bits/stl_vector.h".to_owned()),
            line: Some(1160),
        },
        InputFrame::symbol("LLVMFuzzerTestOneInput"),
        InputFrame::symbol("main"),
    ]);
    assert_eq!(
        frames,
        [
            "std::__throw_out_of_range_fmt",
            "std::vector<int, std::allocator<int>>::_M_range_check"
        ]
    );
}
