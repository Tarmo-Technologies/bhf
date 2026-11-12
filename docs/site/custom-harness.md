<!-- SPDX-License-Identifier: Apache-2.0 -->

# Custom C and C++ Harnesses

`bhf auto` writes harnesses for you. When an API needs setup that a generated
harness cannot guess, or you already have a libFuzzer-style entry point, you
can write the harness yourself and still use bhf's build, fuzzing engine and
triage tools. This page describes three routes:

1. Write an `LLVMFuzzerTestOneInput` entry point and let `generate-harness`
   wrap it.
2. Let bhf generate a harness for the function or method closest to what you
   need, then edit its `bhf_run_one` body.
3. Fuzz an executable you cannot rebuild as a binary-only target.

All commands below use one work directory, `bhf_work`. Generate harnesses
into `bhf_work/harnesses/<id>/`, the layout `bhf auto` uses. `bhf build`,
`bhf fuzz`, `bhf explain` and `bhf capsule` find a harness there from the work
directory and its id, and `bhf replay` and `bhf minimize` from the finding (see
[Triage](#triage)).

## 1. Write an `LLVMFuzzerTestOneInput` entry point

Write the entry point the way you would for libFuzzer. It receives one input
per call and drives the code under test:

```cpp
// harness/drive_codec.cpp
#include <cstddef>
#include <cstdint>
#include "widgets/codec.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    widgets::Codec codec;
    codec.decode(data, size);
    return 0;
}
```

- In C++, declare it `extern "C"`.
- Return 0 and do not call `exit()`: the same process runs many inputs.
- Do not define `main`. bhf supplies the driver.
- Keep it deterministic, and reset any global state the code under test keeps
  between calls.

Wrap it with `generate-harness`. List the library sources it calls with
`--extra-source` and their header directories with `--extra-include`:

```sh
bhf generate-harness harness/drive_codec.cpp \
  --target LLVMFuzzerTestOneInput --id H-XCODEC \
  --output bhf_work/harnesses \
  --extra-source lib/src/codec.cpp --extra-source lib/src/table.cpp \
  --extra-include lib/include --extra-include lib/src
```

The generated `main.cpp` (or `main.c`) is a passthrough: bhf's own `main`,
framed fork-server driver and SanitizerCoverage runtime (edge coverage,
cmplog, value profile), forwarding each input to your entry point. It is not
built with `-fsanitize=fuzzer`.

`bhf auto` finds the same entry point. When the tree has other targets, a
driver is skipped unless you select it with `--target LLVMFuzzerTestOneInput`,
`--target-file harness/drive_codec.cpp` or its `--harness-id`; auto prints a
note naming the drivers it skipped. Pointing `bhf auto` at a directory that
holds only your driver works too:
`bhf auto harness/ --extra-source lib/src/codec.cpp --extra-include lib/include`.
Discovery skips the usual homes of a driver. It never looks in
`harnesses`, `generated_harnesses`, `bhf_work` or `build`. By default it also
skips any directory whose name contains `fuzz` or `test` (`fuzz/`, `fuzzers/`,
`my_fuzz/`, `tests/`), and directories such as `tools`, `bin`, `examples`,
`samples` and `contrib`. `--include-dir <name>` restores one of the default
skips (`--include-dir fuzzers`), or run `bhf auto` on the driver's directory
itself as above.

## 2. Generate a harness for a function or method

To call one function or method directly, name it with `--target`. For C and
C++ sources `--target` is required. These C++ spellings all select
`widgets::Codec::decode`:

| Spelling | Example |
|---|---|
| Bare name | `decode` |
| Qualified suffix | `Codec::decode` |
| Fully qualified, as `bhf list targets` prints it | `widgets::Codec::decode` |
| Any of those with a parameter list | `Codec::decode(const unsigned char *, size_t)` |

An exact spelling wins over a suffix: with a global `Codec` and a
`widgets::Codec` in the same file, `Codec::decode` names the global one and
only a spelling no definition has exactly falls back to the suffix match. A
leading `::` (`::Codec::decode`) names the global namespace only. When a
spelling matches several definitions (overloads, or two classes named `Codec`
in different namespaces), bhf picks the first, prints all of them, and
`--target-line N` picks one. A name that matches nothing fails with the
closest definitions in the file.

```sh
bhf list targets lib/src --top 20
bhf generate-harness lib/src/codec.cpp --target Codec::decode \
  --id H-XDECODE --output bhf_work/harnesses \
  --extra-source lib/src/table.cpp --extra-include lib/include
```

The harness default-constructs the receiver (or uses a supported constructor
or factory) and decodes each parameter from the input. To change how
arguments are built, edit the body of `bhf_run_one` in the generated
`main.cpp`:

```cpp
extern "C" int bhf_run_one(const uint8_t *Data, size_t Size) {
    BHF_PUBLISH_INPUT(Data, Size);
    bhf_cursor Cur = bhf_open(Data, Size);
    widgets::Codec _bhf_receiver;   // set the receiver up here
    BHF_TARGET_ENTER();
    int R = _bhf_receiver.decode(Data, Size);
    BHF_KEEP_RESULT(R);
    return 0;
}
```

Leave the rest of the file alone: it is the driver `bhf fuzz` talks to. The
`bhf_cursor` helpers in `c_runtime/bhf_decode.h` take typed values from the
input. Running `generate-harness` again overwrites your edits, so keep a copy.

## Build

```sh
bhf build bhf_work --harness H-XCODEC
```

`bhf build` runs `make main` in `bhf_work/harnesses/H-XCODEC/` and stages the
binary at `bhf_work/build/H-XCODEC/main`. It also accepts the harness
directory itself (`bhf build bhf_work/harnesses/H-XCODEC`) and prints the
equivalent command. With more than one harness and no `--harness`, or an
unknown id, it lists the ids it found.

`bhf build` has no repair loop; `bhf auto` does. When a build fails, it
prints what was missing and the exact fix:

- Undefined symbols: the in-tree source files that define them, with the
  `--extra-source` flags to add when regenerating and an `AUTO_EXTRA_SOURCES`
  command that builds without regenerating.
- Standard streams used without their header (`cerr`, `cout`, `endl`,
  `std::istream`): an `AUTO_EXTRA_INCLUDES='-include iostream'` command.
- A member declared with an extra class qualification, which only MSVC
  accepts by default: `-fms-extensions` for clang++ (`-fpermissive` for g++).

Each suggested command keeps the `AUTO_EXTRA_*`, `CXX_STD` and `C_STD` values
the build ran with. When several fixes apply, the last hint line combines them
into one command.

Add compiler and linker input through these environment variables. The
Makefile appends them to its own flags:

| Variable | Adds |
|---|---|
| `AUTO_EXTRA_SOURCES` | Space-separated source files to compile and link |
| `AUTO_EXTRA_INCLUDES` | Compile flags: `-I<dir>`, `-D<name>=<value>`, `-include <header>`, `-fms-extensions` |
| `AUTO_EXTRA_LDFLAGS` | Link flags: `-L<dir> -l<name>` |
| `CXX_STD` / `C_STD` | The language standard, such as `gnu++14` or `gnu99` |

```sh
CXX_STD=gnu++14 AUTO_EXTRA_INCLUDES="-DWIDGETS_LEGACY=1 -include iostream" \
  AUTO_EXTRA_SOURCES="$PWD/lib/src/table.cpp" bhf build bhf_work --harness H-XDECODE
```

## Fuzz

```sh
bhf fuzz bhf_work --harness H-XCODEC --time 60s --seed-file samples/record.bin
```

`--seed-file` passes the file's bytes unchanged, so binary samples are safe.
Repeat it for several seeds. `--seed-input` takes a literal text seed.

`generate-harness` writes `dictionary.txt` next to `main.cpp`, mined from the
target file and its headers: one quoted token per line, used for token
insertion. For a passthrough harness it is mined from your driver and can
contain noise such as `"C"` from `extern "C"`. Edit it and add the magic
values your format uses.

## Triage

Findings are written under `bhf_work/results/findings/<finding-id>/` with
`finding.json`, the input (`testcase.bin`) and a standalone `replay.py`.

```sh
bhf replay --finding bhf_work/results/findings/<finding-id> \
  --harness bhf_work/harnesses/H-XCODEC/main
bhf minimize --finding bhf_work/results/findings/<finding-id> \
  --harness bhf_work/harnesses/H-XCODEC/main
bhf explain --work-dir bhf_work --finding-id <finding-id>
python3 bhf_work/results/findings/<finding-id>/replay.py
```

`--harness` is optional: without it, replay and minimize run the finding's own
harness, resolved in the work directory from its `fixture_path` and
`harness_id`. The binary `bhf build` stages at `bhf_work/build/<id>/main` works
as well as the one next to `main.c` / `main.cpp`. `bhf capsule` and
`bhf verify-poc` package C and C++ findings whatever the harness id; the
language comes from the harness's `generation-metadata.json`:

```sh
bhf capsule --work-dir bhf_work --finding-id <finding-id>
bhf verify-poc bhf_work/capsules/capsule_<finding-id>
```

## 3. Binary-only targets

An executable you cannot rebuild does not speak bhf's driver protocol, so fuzz
it as a binary-only target. It receives each input as a file or on stdin.

Mutation and coverage need AFL++ with QEMU mode (`afl-fuzz -Q`). With it
installed, the default engine (`auto`) runs a coverage-guided campaign for the
`--time` budget:

```sh
bhf binary fuzz path/to/tool --work-dir bhf_work --input-mode file \
  --seed-file samples/record.bin --time 60s
```

Without AFL++ QEMU mode, `auto` falls back to the builtin engine, which only
runs the seeds and reports the ones that crash: no mutation, no coverage, and
`--time` is ignored. `--iterations` caps how many seed executions it runs.
Pass `--engine afl-qemu` to fail instead of falling back.

In a `bhf project` manifest, such an executable uses `engine = "binary"`.
`engine = "builtin"` and `engine = "afl++"` expect a bhf harness binary, built
from a harness directory bhf generated.

## Pitfalls

- Do not link your harness with `-fsanitize=fuzzer` and give it to
  `bhf fuzz`. bhf runs such a binary on one input file per process, without
  coverage guidance; the coverage-guided driver is the generated `main`.
  `make libfuzzer` in the harness directory builds a separate libFuzzer binary
  for other fuzzers; see the harness's `PORTABILITY.md`.
- Do not set `CXXFLAGS` or `CFLAGS` to add flags. They replace the
  Makefile's sanitizer and coverage flags. Use `AUTO_EXTRA_INCLUDES`.
- Leave `CC`/`CXX` unset, or set them to `clang`/`clang++`. The generated
  flags are clang's unless the harness was generated from a gcc compile
  database.
- `bhf build` takes the work directory, not the `--output` directory.
- Regenerating a harness overwrites edits to `main.cpp` and `dictionary.txt`.
