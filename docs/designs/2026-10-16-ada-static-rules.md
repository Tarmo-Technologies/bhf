<!-- SPDX-License-Identifier: Apache-2.0 -->
# Design: Ada static rules

> Status: implemented (`crates/static_analysis/src/ada_rules.rs`).

## Problem

The Ada lane of `bhf static-scan` had six line-matching rules. Four of them
reported the use of a language feature rather than a defect: every
`Unchecked_Conversion` or `Unchecked_Deallocation` instantiation (BHF-409,
BHF-410), every task, protected object, `accept` or `select` (BHF-411), and every
`Spawn` call (BHF-412). BHF-405 matched any line containing `open (` and
`path`. On the 18 permissive Ada projects listed below, main reports 979 Ada
findings, and almost none of them point at a weakness. This pack reports 131. Findings from this
pass are used as review and training data, so a finding that teaches nothing
costs reviewer time and teaches the wrong lesson.

## Approach

`ada_rules.rs` lexes Ada (string literals with `""` escapes, character literals
versus the attribute tick, comments) and splits the token stream into
statements. It tracks frames: package, subprogram, task body, protected body,
declare/begin block, and control constructs. Each frame records its declarations,
formal parameters, phase (declarative part, statements, handler) and the
exception choices of its handlers. Rules then ask structural questions, such as
"is this object declared in the enclosing subprogram", "is this argument a
constant", or "does this frame have a `when others` handler", instead of
matching text.

`ada_parser` was not used. It wraps a tree-sitter C grammar, which would add a C
build dependency to `static_analysis`, and the rules need declarations and
scopes more than a full syntax tree.

Findings go through the existing `static_finding` path, so JSON and SARIF output
(rule id, CWE, file, line, message, snippet, triage) is unchanged.

Scope exclusions that apply to every rule in the pack:

- test trees below the scan root (`test`, `tests`, `regtests`, `testsuite`,
  `testing`, `unit_tests`, `*-tests.adb`, `*_test.adb`);
- GNAT binder output (`b__*.adb`, `b~*.adb`);
- compilation units of the predefined or GNAT hierarchy (`Ada.*`, `System.*`,
  `Interfaces.*`, `GNAT.*`, including `separate` subunits of them). A runtime
  implementation has to suppress checks and forge pointers to provide them.

## Rules

Sources: ISO/IEC TR 24772-2 (Ada vulnerabilities, codes in brackets), the
GNATcheck predefined rules, and CWE.

| Rule | CWE | Reports | Source | Known false-positive patterns |
|---|---|---|---|---|
| BHF-402 | CWE-755 | An exception handler whose `others` alternative is only `null`. | TR [OYB] | Intentional "never fail" guards, such as listener loops and best-effort parsing. Not reported: `when others => null` in case statements or string templates, handlers in `Finalize`/`Adjust`, and guards around cleanup or logging calls only (Close, Delete, Free, Shutdown, Put, Log). |
| BHF-409 | CWE-843 | `Unchecked_Conversion` whose target is an access type (declared `is access` in the file, or a `*_Access`/`*_Ptr`/`chars_ptr` name not declared otherwise), or an `Address_To_Access_Conversions` instance. | TR [HFC] [AMV]; GNATcheck Unchecked_Address_Conversions | FFI glue converting C buffers, which is correct when the C contract holds. Conversions between two access types that designate the same type. |
| BHF-410 | CWE-415 | A local alias of an access value is freed after the original was freed. `Free` nulls only its own actual. | TR [XYK] | Alias copied on one branch and freed on another (no path sensitivity). |
| BHF-411 | CWE-567 | A task body assigns a package-level variable that is also used outside the task and is not protected, Atomic, Volatile or Independent. | TR [CGX] | Writes serialized by a rendezvous or an external lock. Not reported: indexed writes partitioned by a task-local or loop variable. |
| BHF-412 | CWE-78 | GNAT.OS_Lib/GNAT.Expect/Util.Processes spawn whose program is not a constant, or a shell given non-constant arguments. | CWE-78 | Programs read from trusted configuration. Not reported: literal programs, `Locate_Exec_On_Path ("lit")`, and formal parameters passed straight through (the taint engine follows those). |
| BHF-419 | CWE-89 | SQL execute/fetch/prepare whose SQL literal is joined with `&` to a non-constant, non-numeric operand, directly or through a local query variable. | CWE-89 | Identifier interpolation from internal constants (table or column names). |
| BHF-422 | CWE-327 | GNAT.MD5 or GNAT.SHA1 `Digest` of a password-named value, or inside a password-handling subprogram. | CWE-327/916 | Non-storage uses inside password-named subprograms. |
| BHF-428 | CWE-338 | `Random` on an Ada.Numerics Discrete_Random/Float_Random generator feeding a token, salt, nonce, session, key or password value. | CWE-338 | Security words in non-security names, such as a lexer `Token`. |
| BHF-436 | CWE-789 | `String'Input`, `Stream_Element_Array'Input` and similar in a unit that uses GNAT.Sockets or AWS.Net: the peer chooses the bounds. | CWE-789 | A file stream read in a networked unit. |
| BHF-437 | CWE-416 | A local alias dereferenced after the original was freed. | TR [XYK] | As BHF-410. |
| BHF-550 | CWE-401 | `New_String` held in a local, or passed inline to a call, and never freed, returned or stored. | CWE-401 | C APIs that take ownership. Not reported: calls named insert/add/append/push/store/register/attach/take/adopt. |
| BHF-564 | CWE-129 | `pragma Suppress` of Index_Check, Range_Check, Length_Check or All_Checks (or `Suppress_All`). | TR [MXB] | Performance kernels with hand-checked bounds. Not reported: subprograms that `pragma Assert`/`Assume` the invariant or have a `Pre` aspect, and SPARK units. |
| BHF-565 | CWE-190 | `pragma Suppress (Overflow_Check)`. | TR [MXB] [FIF] | Hash and checksum code that wants wrap-around but uses a signed type. |
| BHF-566 | CWE-562 | `X'Unchecked_Access`/`'Unrestricted_Access` of an object declared in the current subprogram, returned or stored in a non-local object. | TR [DCM] [SKL] | Objects whose subprogram outlives the access, such as a task wrapper. Not reported: call actuals and `.all` designations. |
| BHF-567 | CWE-843 | An object placed at another object's `'Address` by an address clause or `Address` aspect. | TR [AMV]; GNATcheck Constant_Overlays / Non_Constant_Overlays | Encoding a record into a byte buffer, and over-sized "unrestricted array" views. Not reported: same-type overlays, views sized from the target (`(1 .. X'Length)`, shared bound variable), views of types with no invalid values at a literal size (`Unsigned_8`, `Stream_Element_Array (1 .. 16)`), overlays guarded by `Compile_Time_Error`/`Assert` on `'Size`, and absolute addresses (MMIO). |
| BHF-568 | CWE-676 | `pragma Import`/`Import` aspect with C convention binding strcpy, strcat, sprintf, gets, system, popen, exec*, mktemp, tmpnam and similar. | TR [DJS] [SKL] | Bindings that are never called. |
| BHF-569 | CWE-532 | A password, secret key or credential token passed to a logger or to console Text_IO. | CWE-532 | Tools whose job is to show the user a generated secret. Lexer `Token` names are not secret words. |
| BHF-570 | CWE-248 | A subprogram exported with C convention whose body has no `when others` handler. | TR [DJS] [OYB]; GNATcheck Exception_Propagation_From_Export | Bodies that cannot raise. Not reported: `null` bodies and units with `No_Exception_Propagation`. |
| BHF-571 | CWE-460 | A `raise` (or re-raise) that can leave a controlled `Finalize (Obj : in out T)`. | TR [OYB] | None found in measurement. |

BHF-405 (path traversal) is now reported for Ada only by the taint engine's
Ada.*_IO Open/Create sinks. The line heuristic is removed. Hardcoded credentials
are already covered for Ada by the generic BHF-429 assignment detector, which
handles `:=`.

Not implemented, because they cannot be decided from source with useful
precision: modular wrap-around in size/index computations (needs type
resolution across units), unprotected shared variables accessed through
subprogram calls from several tasks (needs a call graph per task), and missing
`'Valid` after Unchecked_Conversion of input bytes.

## Measurement

Tuning and precision projects (shallow clones at the commit shown). All are
permissively licensed, and all are excluded from the evaluation panels:

- https://github.com/stcarrez/ada-util (897d197)
- https://github.com/stcarrez/ada-ado (0f35d42)
- https://github.com/stcarrez/ada-security (9ca2987)
- https://github.com/stcarrez/ada-keystore (27c007b)
- https://github.com/stcarrez/ada-asf (ec23dc6)
- https://github.com/stcarrez/ada-servlet (87c2240)
- https://github.com/stcarrez/ada-libsecret (6f85973)
- https://github.com/stcarrez/ada-lzma (e87fbc5)
- https://github.com/zertovitch/zip-ada (006a12b)
- https://github.com/zertovitch/lea (df17e64)
- https://github.com/zertovitch/ini-files (86f2604)
- https://github.com/onox/json-ada (4a04b21)
- https://github.com/onox/wayland-ada (f8a9fe0)
- https://github.com/reznikmm/matreshka (2cf5fe05)
- https://github.com/jrcarter/PragmARC (c08f98a)
- https://github.com/pmderodat/ada-toml (27a9bc9)
- https://github.com/wookey-project/ewok-kernel (ca8e2a0)
- https://github.com/vivianjia123/Password-Manager (c61523b)

Four more projects were scanned during tuning before the evaluation project
list reached this work:

- https://github.com/jrcarter/Ada_GUI
- https://github.com/ytomino/drake
- https://github.com/persan/zeromq-Ada
- https://github.com/jrmarino/libsodium-ada

drake prompted the runtime-unit skip and the `'Size`-check overlay exemption;
the other three only had their hits reviewed. All four have been dropped from
the evaluation panels, and none of them is counted below.

Every hit was read in context when a rule had 18 or fewer hits. For BHF-409
and BHF-567, 25 hits were sampled with a fixed seed. Verdicts:

- **real**: a weakness, or a high-risk instance.
- **review**: the pattern is genuine and needs a non-trivial check, but is
  probably intended.
- **noise**: misdetected or trivially safe.

Precision is (real + review) / reviewed.

| Rule | Hits | Reviewed | Real | Review | Noise | Precision |
|---|---:|---:|---:|---:|---:|---:|
| BHF-402 | 13 | 13 | 0 | 9 | 4 | 69% |
| BHF-409 | 36 | 18 | 4 | 12 | 2 | 89% |
| BHF-411 | 1 | 1 | 1 | 0 | 0 | 100% |
| BHF-412 | 4 | 4 | 3 | 1 | 0 | 100% |
| BHF-428 | 3 | 3 | 3 | 0 | 0 | 100% |
| BHF-564 | 18 | 18 | 1 | 17 | 0 | 100% |
| BHF-567 | 53 | 25 | 6 | 16 | 3 | 88% |

For BHF-409, the 25-hit sample was drawn before the four projects were dropped;
the 18 sampled hits from allowed projects are reported.

BHF-410, 419, 422, 436, 437, 550, 565, 566, 568, 569, 570 and 571 have no hits
on these projects. BHF-550, 565 and 566 had false positives that tuning
removed. The precision of these rules rests on the unit fixtures and the
labelled corpus in `benchmarks/static/corpus/ada/`. Matreshka contributes most
BHF-564/567 hits: near-duplicate string-handler kernels in portable, 32-bit,
64-bit and SSE2 variants.

Examples of real findings:

- session identifiers and WS-Security nonces generated with `Discrete_Random`
  (matreshka);
- an editor command and GPG command templates run through `/bin/sh -c`
  (ada-keystore);
- FastCGI records decoded from raw network buffers with no validity check
  (matreshka);
- kernel enum and record objects overlaid on user syscall parameters with no
  validity check (ewok-kernel).
