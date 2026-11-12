<!-- SPDX-License-Identifier: Apache-2.0 -->

# CLI

The bhf CLI is the stable operator surface for scanning, harness
generation, instrumentation, replay, minimization, reporting, and policy
checks.

## Command map

| Area | Commands |
|---|---|
| Whole-tree and manual pipeline | `auto`, `snippet`, `scan`, `list`, `generate-harness`, `build`, `fuzz`, `report` |
| Build and instrumentation support | `stub`, `instrument`, `fake-corba` |
| Corpus and crash triage | `corpus`, `minimize`, `replay`, `capsule`, `verify-poc`, `env-capsule`, `differential`, `relational`, `cmplog`, `explain`, `cartography`, `decode-args` |
| Source-unavailable binaries | `binary` (`scan`, `adapter`, `fuzz`) |
| External project profiles | `project` (`validate`, `list`, `run`) |
| Out-of-process extensions | `extension` (`validate`, `evaluate`), and `fuzz --extension` |
| Static and supply chain | `static-scan`, `sloc`, `sbom`, `license-audit`, `extract-state-machines` |
| Rules and governance | `rules`, `policy`, `audit`, `pack`, `export` |
| Optional assistance | `llm` (`status`, `test`, `prompt`, `assist`) |
| CI and operations | `ci`, `runners`, `clean`, `introspect` |

Run `bhf --help` for the live top-level inventory and `bhf <command>
--help` for the exact language scope, defaults, and accepted values. In
particular, `auto` is the sixteen-lane entry point; `scan`, `list targets`,
`generate-harness`, and the structured LLM/MCP harness helpers are narrower.

## Common Flow

```sh
bhf scan path/to/src --work-dir bhf_work
bhf static-scan path/to/src --out bhf_work/static --sarif
bhf binary scan path/to/bin-or-firmware --out bhf_work/binary
bhf --profile external-tools binary adapter path/to/bin --adapter rizin --out bhf_work/binary-adapter
bhf binary fuzz path/to/bin --work-dir bhf_work --input-mode stdin --seed-input smoke
bhf list targets path/to/pkg.adb --top 20
bhf instrument path/to/pkg.adb --output bhf_work/src_instrumented
bhf generate-harness bhf_work/src_instrumented/pkg.adb --target Pkg.Parse --output bhf_work/generated_harnesses
bhf build bhf_work --harness H-PKG-PARSE
bhf fuzz bhf_work --harness H-PKG-PARSE --iterations 1000 --seed-input smoke
bhf replay --finding findings/F-0001 --harness build/H-PKG-PARSE/main
bhf minimize --finding findings/F-0001 --harness build/H-PKG-PARSE/main
bhf report --findings findings --out reports
bhf introspect path/to/src --work-dir bhf_work
bhf clean bhf_work --build --corpus --reports
```

The replay and minimize lines show the Ada layout. A C or C++ harness replays
from the `build/<id>/main` that `bhf build` stages or from
`bhf_work/harnesses/<id>/main`; without `--harness`, both commands resolve the
finding's harness in its work dir.

`bhf report` has two modes. With no `--findings`/`--out`, it defaults to
`--work-dir bhf_work` and rebuilds `<work-dir>/results/` in place (the same
rebuild every other command triggers) — this is the normal post-hoc way to
refresh the index. `--backfill` first replays each C/C++ sanitizer finding that
has no `sanitizer.log` (findings migrated from a 0.2.x work dir, for example)
against its harness, as `bhf replay` does; when the replay is the recorded
crash it writes `sanitizer.log`, the crash frames and the memory access into
the finding (its id and signature do not change). A finding whose harness is
gone, that now crashes elsewhere, or whose replay is unsymbolized (put
`llvm-symbolizer` on `PATH` or set `ASAN_SYMBOLIZER_PATH`; the backfill puts
the LLVM toolchain `bhf auto` uses on `PATH`) is listed and left as it was. Pass `--findings <DIR>` and/or `--out <DIR>` for the
explicit mode shown above, which reports over an arbitrary findings directory
and writes a standalone Markdown/JSON/SARIF/CSV report to `--out` instead of
touching `results/`; `--sarif`/`--csv` are no-ops in work-dir mode (always
written). `--junit <PATH>`, `--baseline <PATH>`, and `--model <PATH>` write
into `<work-dir>/results/report/` (the `bhf.report.v2` snapshot baseline
comparisons need).

## Actionability Modes

`bhf auto` and `bhf fuzz` accept `--mode reporting|attacking`. The
default is `reporting`.

`reporting` mode keeps developer workflow quality first: findings are reported
with replay commands, minimized artifacts when available, source fix locations,
patch guidance, and clear labels for lab-only paths.

`attacking` mode prioritizes targets that look externally reachable and
security-relevant. It still records findings that depend on generated stubs,
fake resources, missing-environment shims, or mocks, but those findings are
classified as `lab_only` and are not included in real-reachable counts.

CI can gate on actionability:

```text
bhf ci . --fail-on-actionability likely --min-actionability-confidence medium
```

Use `real` for strict attacker-reachable gates, `likely` for security gates
that accept strong static entry/sink evidence, `lab` when lab-only findings
should fail the build, and `any` to fail on every recorded finding.

For a point-and-shoot sweep over an entire (possibly partial) source tree, use
`bhf auto` instead of running the steps individually. See [Auto](../auto/).

`bhf fuzz --structured-inputs auto|off|record|json|xml|kv|url|multipart|csv|http|ini|toml|yaml|recursive`
controls the built-in engine's structured input synthesis from loaded
dictionaries. `auto` is the default and enables record/TLV, JSON-shaped,
XML element, key/value text, URL-encoded query-string, multipart/form-data, and
CSV/table-row, raw HTTP request, INI section/key, TOML table/key, YAML
section/key, and nested-grammar/recursive-structure synthesis. `record`,
`json`, `xml`, `kv`, `url`, `multipart`, `csv`, `http`, `ini`, `toml`, `yaml`,
and `recursive` force one structured family (`recursive` forces nested-grammar /
recursive-structure synthesis, also on under `auto`); `off` preserves
byte/dictionary mutation without structured synthesis.
Generated Ada harnesses write `dictionary.txt` from enum literals and string
literals; generated C/C++ harnesses write the same artifact from source and
header constants, including C++ namespaced `enum class` members and switch case
labels (but not `#include` paths); the Rust, Go, Java, Python, Perl, C#,
JavaScript, Ruby, Lua and PHP lanes mine their string and number literals.
Each token is preceded by a `# from <file>:<line>` comment naming up to three
places it was found, files relative to the target source's directory (for
example `# from parser.c:42, include/parser.h:7`); a token bhf adds itself has
none. Each integer literal is also written as its raw little- and big-endian
bytes, under a `# raw bytes of the literal above` comment. The file is mined
from source when the harness is generated and is not runtime evidence.

Comparison operands observed while fuzzing accumulate in `cmplog.jsonl` beside
it, and after each `bhf auto` fuzz pass that recorded any, bhf rewrites
`learned_dictionary.txt` from them: each distinct operand of at most 64 bytes,
this run's first, then those an earlier run learned, at most 256 tokens, under a
header saying they were observed at runtime. The fuzz command (and the first
pass of a later `bhf auto` run) loads `dictionary.txt` and then
`learned_dictionary.txt` automatically when present, each token once; later
passes of the same `bhf auto` run also read `cmplog.jsonl` itself, and a token
already loaded is not added again. AFL++ mode passes both files with `-x`.

`bhf scan` accepts an Ada, C, or C++ source file or directory tree. It
writes `bhf_work/scan_index.json`, prints the same JSON summary to stdout,
records skipped source files with diagnostics, and exits `1` only when no
supported source file was scanned.

`bhf static-scan <PATH>` takes `--work-dir <DIR>` (default `bhf_work`) and
writes `static-report.json` and `static-report.md` to
`<work-dir>/results/static/` by default, then rebuilds `results/`. Pass
`--out <DIR>` to write elsewhere instead; that opts out of `results/` and
prints a note that it was not updated. Use `--sarif` to also
write `static-report.sarif`, `--suppressions <JSON>` for exact
rule/path/line suppressions, `--baseline <static-report.json>` to mark findings
as `new`, `unchanged`, or `resolved`, `--policy <JSON>` / `--enable-rule` /
`--disable-rule` to apply policy-as-code rule filters, and `--fail-on
low|medium|high|critical` for CI-style static gates.

`--since <rev>` restricts the scan to files changed since that git revision;
in work-dir mode this *replaces* `results/static/static-report.json` with the
diff-scoped subset, so `results/` then holds only those static findings —
run a full `static-scan` (no `--since`) afterwards to get everything back. An
explicit `--out <work>/results/static` writes into `results/` without
rebuilding the index; follow it with `bhf report` to fold the new static
report back into `findings.json`/`INDEX.md`.

Use `--jobs <N>` to bound parallel file workers and `--max-memory-mb <MB>` to
set the static process RSS ceiling. At the ceiling the Linux scanner stops
admitting new work and records an analysis gap. The default ceiling is the
smaller of 80% of host-available memory and 70% of the cgroup memory limit.
On an 8 GiB host, start with `--jobs 2 --max-memory-mb 4096`.

Use `--sloc <FILE>` to also write an accurate per-language SLOC breakdown
(`LANGUAGE`, `FILES`, `TOTAL`, `COMMENTS`, `BLANKS`, `SLOC`) as a side output of
the scan. A `.json` extension emits JSON; anything else emits an aligned text
table. A relative path is written into the `--out` report directory (beside
`static-report.json`); an absolute path is written as given. Comment counting is
language-aware (Ada `--`, C-family `//`/`/* */`, hash comments, Perl POD, Python
docstrings), and the same dependency/build-tree pruning as the scan applies, so
vendored, `node_modules`, and `.venv` code is excluded. The same `--sloc <FILE>`
flag works on `bhf auto`, where a relative path lands in `<work-dir>/auto/`.

For **pure counting with no rule scanning**, use the dedicated `bhf sloc
<PATH>...` command instead — it runs only the SLOC tree walk, so it is much
faster than `static-scan --sloc` (which pays the full parse+scan cost). It takes
one or more roots and prints a per-root table plus a grand total, to stdout by
default or to `--out` (`.json` or `--json` emits JSON with a corpus-wide
`total.code_lines`):

```sh
bhf sloc path/to/src              # text table -> stdout
bhf sloc repos/* --out sloc.json  # whole corpus -> JSON with grand total
```

The static scanner now emits:

- A lightweight cross-file interprocedural taint trace for source-to-sink
  vulnerabilities. Command execution is covered across **all eight core static
  languages**
  (Ada/C/C++/Go/Rust/Java/Python/Perl), and the same engine also confirms path
  traversal, SQL injection, SSRF, XXE, LDAP injection, unsafe reflection,
  uncontrolled allocation size, open redirect, and log injection/log forging
  where the language has modeled sinks. Findings carry proven source→sink traces
  and supersede lower-confidence pattern heuristics at the same site. Includes
  local assignment aliases, Ada named-argument taint mapping, sanitizer/constant
  taint kills (including language-standard shell quoters), C++ namespace/class-aware
  local call resolution, typed object/`this`/initialized-object member-call
  resolution, overload arity filtering, string-literal-aware comment matching,
  and explicit unresolved-call gaps when source is missing.
- CWE/CERT/MISRA-oriented seed rules for unsafe string copy, path-controlled
  file opens, environment reads, unchecked integer conversion, and nonliteral
  format strings.
- Ada structural rules (statement and scope model, not line matching):
  suppressed index/range/overflow checks, access values forged by
  Unchecked_Conversion, address overlays, local `'Unchecked_Access` escapes,
  double free and use after free through an alias, unprotected task writes,
  non-constant spawns, SQL concatenation, unsafe C imports, leaked `New_String`,
  secrets in logs, exceptions escaping C exports or `Finalize`, peer-sized
  `String'Input`, predictable random values and MD5/SHA-1 password hashes, and
  broad `when others => null` handlers. See
  the Ada rule design (`docs/designs/2026-10-16-ada-static-rules.md`).
- Framework and embedded-browser hardening checks for Django deployment
  settings (`SECURE_SSL_REDIRECT`, HSTS, proxy HTTPS state, nosniff, referrer
  policy, CSRF/session cookies), Flask host/CSRF controls, Electron renderer
  isolation, and Qt WebEngine settings such as sandboxing, mixed content,
  local file/remote URL access, plugins, clipboard, WebRTC local IP exposure,
  screen capture, canvas readback, and hyperlink auditing.
- Path predicates, blocked-path demotion, actionability metadata, triage
  states from baselines/suppressions, and SARIF related locations for trace
  steps.

The current engine is intentionally conservative and source-pattern driven.
Deeper CFG precision, richer taint modeling, and larger rule packs remain
ongoing hardening work.

`bhf binary scan <PATH>` writes `binary-inventory.json` with offline binary
metadata for ELF, PE, Mach-O, `ar` archives (static `.a` libraries and Debian
`.deb` packages), and raw firmware-style blobs. Containers are traversed
recursively: a `.deb`'s `data.tar.*` / `control.tar.*` members are decompressed
(gzip, xz, or zstd — all pure-Rust, no external tools) and walked as tar
archives, so each contained binary is inventoried with nested-container
provenance in its path (e.g. `pkg.deb!data.tar.zst!usr/bin/foo`). Decompression
is size-capped (`--max-bytes`, else 1 GiB) and nesting is depth-bounded, so a
decompression or recursion bomb is skipped rather than exhausting memory. The
inventory records format, architecture, bitness, endianness, size, SHA-256,
ELF note build IDs, producer/toolchain provenance (GCC/clang/Go/Rust version from
embedded strings), the Go module dependency tree extracted from a static Go
binary's embedded buildinfo (`go version -m`, including the Go standard-library
version as a `pkg:golang/stdlib@goX.Y.Z` component — syft parity — so version-gated
Go-stdlib CVEs match), parsed entry-point/header layout, symbol/debug-info state, exact ELF/Mach-O
symbol-table import/export names, exact PE thunk import and export-directory
names, risky import APIs, dynamic library/interpreter/RPATH evidence including
ELF `PT_INTERP`, GNU build-id notes, `DT_NEEDED`, `DT_RPATH`, `DT_RUNPATH`, PE import descriptors,
and Mach-O dylib load commands, ELF link mode (static vs dynamic, from `PT_INTERP` +
`DT_NEEDED`), entropy/packed-binary evidence, named
section/segment evidence,
exploit-mitigation posture (a `checksec`/`winchecksec`-style read: for ELF,
RELRO — Full vs Partial via `PT_GNU_RELRO` + `BIND_NOW` — stack canary,
PIE (distinguishing a PIE executable from a shared object/`DSO` by `PT_INTERP`,
matching checksec), NX/executable-stack via `PT_GNU_STACK`, and `_FORTIFY_SOURCE`; for PE,
ASLR/`DYNAMIC_BASE`, DEP/`NX_COMPAT`, Control Flow Guard/`GUARD_CF` from the
`DllCharacteristics` field, and Authenticode signing (the Security data directory);
for Mach-O, `MH_PIE`, non-executable stack via
`MH_ALLOW_STACK_EXECUTION`, and code signing via `LC_CODE_SIGNATURE`),
hardcoded credentials baked into the binary's strings (AWS access keys, GitHub /
GitLab / Slack / Stripe / Google API + OAuth / npm / PyPI / SendGrid tokens, PEM
private keys — the same provider set as the source-tree BHF-429 scan, each
carrying a CWE (`CWE-798`, or `CWE-321` for private keys), redacted in the report
and promoted to high-priority triage), infostealer malware indicators (embedded
browser credential-store filenames and Discord/Telegram exfiltration endpoints — the
compiled counterpart to the source-side supply-chain rules), triage
risk factors, container/member provenance, skipped
malformed inputs, and size-limit skips. Writable or relative RPATH/RUNPATH
entries are promoted into loader-path review triage, while high entropy,
UPX/packed section names, executable+writable sections or segments, and an
executable stack (`hardening:nx_disabled`) are
promoted into packed-binary or binary-layout review triage. Use
`--max-bytes <N>` to skip individual files or archive members above a byte
limit.

`bhf binary adapter <BINARY> --adapter mock|rizin|ghidra|angr --out <DIR>`
writes `binary-adapter-report.json` with adapter-derived functions, call-graph
hints, strings, xrefs, signatures, and errors. The command never links external
tools into BHF. The mock adapter consumes `--mock-output` JSON for contract
tests. Real adapters are subprocess smoke paths, are blocked in
`strict-permissive`, require `--profile external-tools` or `research-lab`, and
write `status: skipped` when the requested tool is absent.

`bhf binary fuzz <BINARY>` executes source-unavailable binaries through
`--input-mode stdin|file`, `--seed-input` / `--seed-file`, `--timeout-ms`, and
repeatable `--env KEY=VALUE` launch profiles. Crashes and timeouts are written
under `<work-dir>/findings/BF-NNNN/` as `kind: binary_crash` findings with the
command, input mode, testcase, environment, binary SHA-256, stderr excerpt, and
exit/timeout signature. Existing `bhf replay`, `bhf minimize`, and
`bhf ci --fail-on ...` understand these binary findings.

A manually authored binary-only harness can name a runner and fixed target
arguments: `--runner <PROG>` launches the target under an emulator/loader (e.g.
`wine`, `qemu-x86_64`) with repeatable `--runner-arg`, and repeatable
`--target-arg` passes fixed arguments to the target before the fuzz input. A
literal `@@` among the target args marks where the input-file path goes (file
mode); without one, file-mode input is appended last. So a Wine/PE harness that
loads a stock vendor DLL is expressed as:

```sh
bhf binary fuzz ./stock_dll_harness.exe --runner wine \
  --target-arg --mode --target-arg fuzz --input-mode file
```

The runner, runner args, target args, and the full `@@`-marked argv are recorded
in the finding, so `bhf replay` and `bhf minimize` reproduce the exact launch.
`--runner` is builtin-engine only (afl-qemu provides its own `-Q` runner);
`--target-arg` applies to both engines.

`--engine builtin|afl-qemu|auto` selects the execution engine: `builtin`
replays the seeds and detects crashes (no mutation/coverage); `afl-qemu` drives
coverage-guided mutation on a binary-only / foreign-arch target via AFL++'s QEMU
mode (`afl-fuzz -Q`); `auto` (the default) uses `afl-qemu` when its toolchain is
present and otherwise falls back to `builtin`. Under `afl-qemu`, `--timeout-ms`
is passed to `afl-fuzz` as the per-execution timeout (`-t`) so the mutation
campaign and the crash-replay oracle share one policy, and `--mem-mb <MiB|none>`
sets the child memory limit (`afl-fuzz -m`); it defaults to `none` because QEMU
mode maps a large virtual address space and a tight cap aborts the campaign.
Both effective limits are recorded in the run-provenance JSON.

`--runtime-oracles auto|on|off` (on `bhf fuzz` and `bhf binary fuzz`) loads the
runtrace sink oracles via the `LD_PRELOAD` shim so a **clean-exit** semantic
violation — a fuzz-controlled command execution, path escape, `dlopen`, network
egress, or SQL query — is reported even when the target exits zero, not only on a
crash. `off` is the default (crash-only, prior behaviour); `auto` enables the
oracles when the shim and platform (Linux) support it and skips otherwise; `on`
requires them and errors if unavailable. `bhf binary fuzz` publishes each input
to the shim through an inherited file descriptor so a black-box target still gets
byte-origin taint; its oracle findings are written as `kind: binary_semantic`
(with the oracle rule, API, taint evidence, and shim hash) and replay by
re-confirming the oracle rather than a crash signature. (Interpreted-language
runtime oracles and QEMU/Wine are out of scope for this flag — it is the native
Linux layer `bhf auto` already uses.)

`--collector <auto|none|PATH>` (on `bhf fuzz` and `bhf binary fuzz`) arms a
**platform-neutral runtime-event collector**: a provider that observes the
process, filesystem, and module-load effects a target performs — including effects
on a **clean exit** — and emits the versioned `bhf.collector-event.v1` JSONL
contract (JSON Schema in `schemas/`). The host attributes those events to the
testcase's descendant process tree within a bounded post-exit window
(`--collector-window-ms <MS>`, default `250`) and feeds them through the same
bug-oracle registry as the runtime oracles, so a controlled process execution
(BHF-431), a path escaping the allowed root (BHF-405), or a controlled library
load (BHF-435) becomes a `kind: binary_semantic` finding **with no crash**. Unlike
`--runtime-oracles` (the in-process Linux `LD_PRELOAD` layer), the collector is a
decoupled provider addressed by the JSONL wire format, so an out-of-repo provider
can implement it: `auto` selects the built-in provider for the platform — the
native Windows ETW provider `bhf-collector-win`, or on Linux the in-process
`LD_PRELOAD` runtrace adapter that re-expresses the shim's effect events as the
collector contract (it stays inactive only when the runtrace shim is unavailable).
A PATH runs an external sidecar that speaks the protocol, and `none` (default)
disables it, leaving behaviour unchanged. The collector is an *additional*,
collector-shaped view over the same shim events `--runtime-oracles` uses, so
enabling it does not change `--runtime-oracles` behaviour.
A collector finding stores its raw `CollectorSession` evidence next to
`finding.json` (`collector_session.jsonl`), so `bhf replay <id>` reproduces the
semantic finding **deterministically from the stored evidence** — re-evaluating the
oracle registry and surfacing the attributing event and descendant process tree,
needing no `--harness`. Event loss, platform-unsupported APIs, or a permission
denial are recorded as **fidelity limitations** that refuse a false "clean"
assurance rather than silently dropping observations, and each run and finding
records collector **provenance**: the backend name/version/hash, the process-tree
scope, the observation window, the backend's declared **supported event classes**
(kept distinct from the classes actually **observed** firing this run), and the
fidelity limitations. `bhf minimize` on a collector finding is a no-op (the provider-captured
evidence does not vary with the testcase bytes) that re-confirms reproduction.

`bhf binary fuzz` also accepts **user-defined postcondition oracles** with
per-case fixture hooks: `--setup-command` runs before each testcase (prepare a
fresh fixture), `--oracle-command` runs after it to check a security invariant,
and `--reset-command` restores state afterwards. Each case gets a fresh
`BHF_CASE_DIR`; the hooks (and the target) receive `BHF_CASE_DIR`/`BHF_TESTCASE`
in the environment, and the oracle additionally gets `BHF_TARGET_EXIT`,
`BHF_TARGET_SIGNAL`, `BHF_TARGET_TIMEOUT`, and `BHF_TARGET_STDERR`, plus the
testcase path as `$1`. The oracle's exit code is the contract: `0` = clean,
`1` = finding (its first stdout line is the stable signature/classification), any
other code = infrastructure error (not a target defect). A violation is written
as a `kind: binary_postcondition` finding (BHF-502) even when the target exited
zero, and `bhf replay`/`minimize` re-run setup → target → oracle to re-confirm
the signature. This expresses application-specific policy — "this input must not
make the target write outside the allowed root / launch an unlisted process /
perform an unauthorized operation" — that the built-in sink oracles cannot.

`bhf differential --harness-a <A> --harness-b <B> --inputs <DIR>` replays
each input through two implementations and emits BHF-301 output-divergence
findings when stdout, exit status, or timeout behavior differs. Findings land
under `<work-dir>/results/findings/F-DIFF-NNNN/` (default `--work-dir
bhf_work`; the old `--out DIR` spelling is a deprecated alias for it) and
`results/` is rebuilt. Differential
findings carry `oracle.name = "differential-output-runtime"` evidence from the
same executable-oracle registry used by runtime runtrace findings.
`bhf differential --harness <H> --metamorphic-transform append-newline
--inputs <DIR>` replays each input through one harness before and after
appending a trailing newline; mismatched stdout, exit status, or timeout
behavior emits BHF-307 `metamorphic-relation-runtime` findings with both the
original and transformed testcase bytes.

Runtrace `runtime_check` events from Ada instrumentation can promote handled
`Constraint_Error` range/index checks into BHF-102
`ada-runtime-constraint-check` oracle findings with check, handler, message,
and source evidence, handled `Storage_Error` events into BHF-103
`ada-runtime-storage-error` findings, and handled `Tasking_Error` events into
BHF-104 `ada-runtime-tasking-error` findings. Handled user-defined Ada
exceptions become BHF-105 `ada-runtime-user-exception` findings. Runtime
`dlopen` evidence for bare, relative, parent-directory, temporary-directory, or
otherwise non-system library paths can also promote to BHF-413
`dynamic-library-load-runtime` oracle findings. Successful `unlink`,
`unlinkat`, or `remove` events whose path contains a parent-directory segment
promote to BHF-414 `file-deletion-runtime` findings. Native C/C++ assertion
failures observed through the runtrace shim promote to BHF-415
`native-assertion-contract` findings with expression and source evidence. Open
paths that the runtrace shim observed carrying byte-origin taint from the fuzz
input — and that were never opened untainted across the run — promote to BHF-405
`path-controlled-open-runtime` findings carrying a `taint_path` source→sink
string (`fuzz_input[offset..] → open(path)`). These are emitted once per run
from cross-execution matching, not per input, and capped per harness.

These runtrace-derived findings — BHF-413, BHF-414, BHF-415, and BHF-405, together
with the BHF-304 command-injection, BHF-417 insecure-temp, and BHF-305
sensitive-environment behavioral/taint oracles — are produced by the LD_PRELOAD
runtrace shim. It is armed for native C/C++/Ada/Rust/Go/COBOL/Fortran harnesses
and interposes the Python/Perl/Ruby/Lua/PHP interpreter processes. It is
deliberately **not** loaded for Java, C#, or JavaScript/TypeScript and is not
armed under cross-compiled or emulated (qemu/wine) runs. Those configurations
still fuzz for their documented coverage/crash/exception signals; the
LD_PRELOAD behavioral and taint findings are the unavailable layer.

## Replaying a Finding

`bhf replay --finding <id-or-dir>` re-runs a finding's testcase against its
harness and says whether the recorded crash reproduced. The first line is still
`MATCH` (stdout, exit `0`) or `MISMATCH recorded=<rule> actual=<rule>` (stderr,
exit `3`); errors exit `1`. Under it comes a summary of what ran:

```text
MATCH
  finding    F-0003-9c1d22e0 (bhf_work/results/findings/F-0003-9c1d22e0)
  compared   rule BHF-201; kind heap-buffer-overflow; sink Widget::copy_at (widget/widget.cc:12)
  crash      BHF-201 heap-buffer-overflow (asan): ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000031 ...
  sink       Widget::copy_at (widget/widget.cc:12)
  frames     #0 Widget::copy_at(char const*, unsigned long) /src/widget/widget.cc:12
             #1 parse_record(char const*) /src/widget/parse.cc:40
  access     WRITE of size 1 at 0x602000000031; 0 bytes after a 1-byte heap region (offset 1)
  allocated  #0 malloc
             #1 parse_record(char const*) /src/widget/parse.cc:38
  exit       signal 6 (SIGABRT) after 0.05s
  harness    bhf_work/harnesses/H-C0001/main (bhf framed: ...); sha256 matches the recorded build
  testcase   .../testcase.bin, 12 bytes, sha256 0f1e2d3c4b5a6978
```

- **Matching.** A replay is a `MATCH` only when the rule, the crash kind and
  the place match: the sink (the top project frame, chosen as for
  `actionability.sink`, compared by function and `file:line`) or, for a finding
  recorded without frames (a UBSan report from an earlier release), the site
  the sanitizer printed. A crash of the same rule elsewhere is a `MISMATCH`
  whose `differs=` field and `differs` line name what differed. Rules and
  kinds earlier releases gave the same report still match. A hang is reported
  as `actual=<timeout>` after 10 s, a clean exit as `actual=<none>` with its
  exit status. A replayed report that names no function and no source position
  (an unsymbolized one) is not another site: the location shows as "not
  compared" and a `note` line says the replay looks unsymbolized. Replay puts
  the LLVM toolchain `bhf auto` uses on `PATH` (the RHEL 7 LLVM Toolset when
  the base `clang` lacks SanitizerCoverage); elsewhere put `llvm-symbolizer` on
  `PATH` or set `ASAN_SYMBOLIZER_PATH`.
- **Build identity.** When the harness's sha256 differs from the finding's
  `build.binary.sha256`, the harness line says so.
- **`--json`** prints one `bhf.replay.v1` document on stdout instead: `verdict`,
  every compared field (`compared[]` with `outcome`: `equal`, `legacy`,
  `differs`, `not_recorded` or `not_comparable`), `differences`, `notes`, the
  replayed `crash` (rule, kind, sink, frames, `access` region, allocation
  frames), `exit` (code, signal, `timed_out`, duration), `harness` (path,
  protocol and why, sha256) and `testcase`. Exit codes are unchanged.
- **`--show-output`** also prints the harness's raw stderr and stdout (the full
  sanitizer report).
- **`replay.log`.** Every replay, `MATCH` or `MISMATCH`, writes
  `<finding>/replay.log`: the verdict, what ran, the exit status, the
  harness's raw stderr and stdout (each kept to its first 256 KiB and last
  768 KiB, with the cut marked, so a sanitizer report at the end survives)
  and any `--debugger` transcript. The summary names it (`log`, and
  `replay_log` in `--json`). It is overwritten by the next replay, is not one
  of the finding's evidence files, and results/ is rebuilt after it is
  written so `attestation.json` stays current. A lane with no local harness
  (session, collector, transport, Ada event log) writes the verdict and why
  there is no output.
- **`--show-args`** runs a generated C/C++ harness with `BHF_TRACE_ARGS=1` and
  prints the value it decoded for each parameter under the summary: name,
  type, the testcase bytes it came from, its value (or a buffer's length and
  allocation size, and an output's value after the call) and a hex preview.
  When the access starts in a traced buffer, a last line names that parameter.
  With `--json` they are `arguments.traced` (with `arguments.accessed_parameter`).
  A harness generated without the trace, and the other lanes, say why there
  are no arguments. See the
  [C/C++ guide](c-cpp.md#seeing-the-decoded-arguments).
- **`--debugger [gdb|lldb|cdb]`** also re-runs the testcase under a debugger in
  batch mode (with no value, the first found: gdb, then lldb; cdb first on
  Windows) and prints its transcript under the summary (`debugger` in
  `--json`: tool, command, breakpoint, transcript, notes). The session breaks
  at the target function named by the harness's `generation-metadata.json`
  (`target_function`), prints `info args` and `bt full` (lldb: `frame
  variable`, `bt all`; cdb: `dv`, `kP`), removes the breakpoint, continues to
  the crash and prints the full stack again. The harness runs with the
  replay's environment: the finding's runtime mode, the variables it recorded
  as injected, and the runtrace shim, which is preloaded into the harness
  alone (gdb through an `env` exec-wrapper, lldb through `target.env-vars`),
  never into the debugger. AddressSanitizer runs with
  `handle_segv=0` (and the other signal handlers off) so the debugger sees a
  SEGV, `abort_on_error=1` so a report stops there, and `detect_leaks=0`
  (LeakSanitizer does not run under ptrace); UBSan aborts on its first
  report. lldb runs its crash-site commands as on-crash (`-k`) commands, since
  its batch mode stops running the others once the harness crashes, and stops
  a sanitizer report at a breakpoint on the sanitizer's report function
  (`__sanitizer::Die`, `__ubsan_handle_*`). A harness generated by an older
  bhf names no target, so the session only stops at the crash. The harness
  runs natively and outside any sandbox: `--debugger` cannot be combined with
  `--qemu-user`, `--sandbox firejail|bubblewrap` or `--sandbox-strict` (with
  the default `--sandbox auto`, a note says the session ran unsandboxed), and
  applies only to C/C++ harness replays. When
  the debugger is not installed, replay exits `1` before running anything and
  says what to install. Harnesses build with `-O1`: arguments at the target's
  entry are reliable, some locals print `<optimized out>`.
- **Other finding kinds.** Binary, session, collector and transport findings
  print the same kind of summary under their `MATCH`/`MISMATCH` line, for what
  their replay compares: a binary target's crash, oracle or postcondition
  signature with its exit status, binary sha256 and any sanitizer report; the
  session oracle verdict; the collector oracle signature re-evaluated over the
  stored evidence, with the attributing event and process tree; the transport
  fault identity (rule and fault site) or deadline predicate. `--json` prints
  the same `bhf.replay.v1` document with `lane` (`binary`, `session`,
  `collector` or `transport`) and `details`; `harness` is present only for a
  binary finding. `--show-output` prints a binary target's stderr; the other
  lanes run no local harness. An Ada (event-log) replay shows the harness exit
  status and duration, and compares event-log signatures.
- **Sanitizer options.** C/C++ replays use the fuzz child's options:
  `ASAN_OPTIONS` gets `abort_on_error=1:halt_on_error=1` (plus `detect_leaks=1`
  for a leak finding) and `UBSAN_OPTIONS` also `print_stacktrace=1` and
  `report_error_type=1`, merged after your own values. Leak detection is never
  turned off.
- **Harness resolution.** Without `--harness`, the finding's `fixture_path` is
  used. bhf records it relative to the work dir and resolves it there, never
  relative to the current directory; an absolute path from an earlier release
  is first mapped into the work dir holding the finding, so a copied or moved
  work dir runs its own harness. Then `harness_id` is looked up under
  `harnesses/`, `auto/`, `generated_harnesses/` and `build/`. Only when none of
  those exists is an absolute `fixture_path` into another work dir used as
  recorded.
- **Protocol.** `bhf fuzz`, `bhf replay` and `bhf minimize` decide how a
  harness takes its input the same way: a `harness-protocol.json` next to the
  binary (written by `bhf project run`), the `BHF_FRAMED` marker in a launcher
  script, a bhf `main.c`/`main.cpp` beside the binary or in any harness dir of
  the work dir, bhf's driver strings compiled into the binary (so a binary that
  `bhf build` staged alone into `build/<id>/main` still replays; an Ada
  harness, which also reads `BHF_FRAMED`, is told apart by the version string
  GNAT's binder puts in every Ada main), a plain libFuzzer source, or the
  libFuzzer runtime in the binary. The summary's harness line names the
  protocol and why.
- **Results stay current.** A `MATCH` stamps `last_seen` in `finding.json`; when
  the work dir has a results index, replay rebuilds it so
  `results/findings.json` and `results/attestation.json` match the files on
  disk. This holds for every kind of finding. A `MISMATCH` changes nothing.

## Crash → PoC, Explanation, and One-Shot Fuzzing

Beyond the core pipeline, these commands turn a finding into a portable proof
and explain it — all offline and deterministic (no LLM):

- `bhf snippet [INPUT]` — fuzz ONE pasted function with no project, build, or
  dependencies. It detects the language, synthesizes a one-file project, and runs
  the full `auto` pipeline against it. The fastest way to try bhf on a single
  routine.
- `bhf capsule` — package a crash into a portable, self-verifying PoC capsule:
  the generated harness, the target sources (and, for C and C++, the project
  headers they include, in their original directory layout, so
  `#include "sub/x.h"` still resolves), the stubs bhf synthesized, bhf's
  runtime for the language, the build settings the harness was actually built
  with, the dependencies an offline rebuild needs, and the crash input. What a
  capsule holds and how it rebuilds is its lane's, one per harness language
  (see the table below). The input is the finding's `min_testcase.bin` when it
  reproduces, else its `testcase.bin`; it ships as `input/testcase.bin`, and
  the output and `manifest.json` (`input_source`) say which it is. Every path
  the harness's build and launch files name is relocated into the capsule:
  `build.sh` renders those files into `build/` with the capsule's own location
  and the programs it finds on the host, builds there, and writes `./poc`, so
  the shipped files stay as packaged. The rebuilt PoC is replayed with the
  input protocol the shared detector reads off it: the input file as
  `argv[1]`, or, for an Ada harness, the input piped to stdin with the
  runtime's event log in `$BHF_EVENTS_PATH` (`manifest.json` `protocol` and
  `run`). `manifest.json` also records the programs the rebuild needs and the
  version each one printed when the capsule was made (`requires`), the
  expected crash signature, and the lane's build facts (`build_recipe`).

  For a C or C++ harness the headers that ship are the ones the compiler's
  `-M` lists for the build (when that fails, every header under the include
  roots ships, plus the project headers the sources' `#include` lines reach,
  also through `..`), and the build settings are the Makefile plus the
  language standard and extra sources/include dirs recorded in
  `harnesses/<id>/coverage-build-recipe.json`. The compiler is `$CC`/`$CXX`,
  else the family that built the harness binary (a harness bhf built with gcc
  rebuilds with gcc), and `build.sh` asks the compiler that runs it which
  family it is and passes that family's sanitizer flags, as the harness
  Makefile does. A launcher in front of the compiler (`ccache clang++`) runs as
  its words. For a C++ capsule whose compiler cannot find the C++ standard
  library itself, the scan and `build.sh` fall back to the newest installed
  libstdc++ headers and library, else (a libc++ host) to `-stdlib=libc++` or
  an installed libc++ header dir; `build.sh` probes for them on the host that
  runs it. A rebuild that fails is reported by the compiler's first `error:`
  line (or MSVC's `error C2065:` / `error LNK2019:`). The capsule is built and
  replayed in a scratch dir, then moved into place, so a refused or failed
  finding leaves nothing behind.

  A C or C++ capsule also ships `build.ps1`, its Windows build, which needs no
  POSIX shell (`powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1`,
  then `.\poc.exe input/testcase.bin`; manifest `build_windows`, `run_windows`
  and `requires_windows`). It builds the way the harness Makefile builds on
  Windows, linking bhf's driver (`runtime/bhf_driver.c`), with the compiler
  family recorded for the harness (its `bhf_toolchain.stamp`; for the MSVC
  lane, the compiler bhf's cl front end ran, recorded in
  `coverage-build-recipe.json` `msvc_compiler`): cl gets `/fsanitize=address`
  and cl's SanitizerCoverage flags (`inline-8bit-counters`, `edge`,
  `trace-cmp`, `trace-div`, linking `libsancov.lib`), spelled by the bhf-cl
  front end's translation, and bhf's weak repair stubs compile from MSVC
  copies (`stubs_msvc/`); clang-cl gets the same without `libsancov.lib`;
  clang (targeting MSVC) gets the Makefile's ASan, UBSan and coverage flags.
  `$CC`/`$CXX` names another compiler, and when it is unset and the recorded
  one is not installed, the script takes the first of cl, clang-cl and clang
  that is (manifest `build_recipe` `windows_compiler`,
  `windows_compiler_dialect`, `windows_compiler_source`). Each compile runs
  from a response file, so arguments with spaces and quotes stay whole;
  outside a Developer shell the script takes the environment cl and clang-cl
  read (`INCLUDE`, `LIB`, `PATH`) from the newest Visual Studio instance with
  the C++ toolset; and it copies the sanitizer
  runtime DLL of the compiler that ran next to `poc.exe`. On Windows, `bhf
  capsule` and `bhf verify-poc` rebuild with `build.ps1`.
- `bhf verify-poc <CAPSULE>` — rebuild a PoC capsule offline in place (or in a
  scratch copy of a `.tar.gz`) and assert the recorded crash reproduces. The
  path may be absolute or relative to the current dir. It
  needs only the programs the manifest lists under `requires` and a shell, so
  a capsule verifies on a clean machine without bhf's work dir or the scanned
  tree; it checks them first and names each missing one and the variable that
  overrides it. On Windows it rebuilds a C or C++ capsule with `build.ps1`
  and checks the programs `requires_windows` lists, so no POSIX shell is
  needed. A path that does not exist is reported as such, with the
  `bhf capsule` command that writes it.
- `bhf env-capsule` — record and replay the shim-served faked environment so an
  environment-driven crash (missing files, unset env, unreachable sockets)
  reproduces deterministically. It works on the built harness of a native lane
  (C, C++, Ada, Rust, COBOL, Fortran): the runtrace shim is preloaded into the
  harness process, so a statically linked harness (Go) and one that runs in a
  language runtime (Java, C#, Python, JavaScript, TypeScript, Ruby, Perl, PHP,
  Lua) are refused with that reason. The world is recorded under the shim mode
  the finding fired in (`finding.json` `runtime_mode.pass`: `fuzz_driven` or
  `rng`) with the environment variables the fuzz loop injected, which
  `replay.sh` sets too; an Ada harness is fed its input on stdin and its
  unhandled exception in the event log is the crash. The capsule ships the
  first input that crashes under the recorded environment: `min_testcase.bin`,
  then `testcase.bin`, then the corpus input that crashed while recording;
  `manifest.json` (`input_source`) says which.
- `bhf explain` — explain WHY a crash fired, each claim with its evidence or
  a line saying there is none:
  - the input: `min_testcase.bin` when the finding was minimized, else
    `testcase.bin`, named with its size, and whether it is one of bhf's
    built-in starting inputs (empty, `A`, `AAAAAAAA`) or a byte-identical
    copy of a seed listed in `auto/seeds.json`;
  - comparison evidence for that input: each input span that reached a
    comparison of the target, with its offset, the operand, what it was
    compared with, whether they were equal, the comparison (`cmp`, `switch`,
    `memcmp`, `strcmp`, ...) and its source position. It is recorded by
    replaying the input with the driver's comparison capture
    (`BHF_CMP_EVIDENCE`): an operand counts only when its bytes occur in the
    input and a replay with those bytes changed shows the operand change with
    them. For inputs of up to 32 bytes, flipping each byte also finds operands
    computed from input bytes, such as a folded `x == 0 || x > 32` range
    check; two replays of the unchanged input bracket the flips, and an
    operand that differs between them (a process id, a clock reading) is not
    evidence. Comparisons the harness makes before entering the target are
    discarded, and later ones in harness code are left out when
    `llvm-symbolizer` can locate them. Under AddressSanitizer a `memcmp` or
    `bcmp` gate has no source position: the interceptor reports itself as the
    call site. `bhf auto` records it after minimization (`finding.json`
    `gates`); for a finding without it, explain replays the input once (nothing
    is written). Otherwise it prints `No comparison evidence recorded:` and the
    reason, which says what was not searched (computed operands of an input
    over 32 bytes, comparisons past the driver's 8192-record limit) and that
    only instrumented code is observed. Dictionary tokens found in the input are listed only as labelled
    substring matches (at least 3 bytes, at most 3 occurrences);
  - the harness arguments: the value each parameter was decoded to, from the
    argument trace recorded with the finding. An argument whose input bytes a
    recorded comparison read is tagged `[compared at <file>:<line>]` (the
    comparison's address when it has no source position). The trace's byte
    spans index `testcase.bin`; evidence recorded on `min_testcase.bin` is
    related to the arguments through the harness's `arg-layout.json` decoded
    over that file, and without one a line says the two are not related;
  - the environment: the runtrace events of that input's own replay when the
    runtrace shim was loaded for it, else the harness's last fuzz pass (all of
    its inputs, labelled so), and `environment not observed (runtrace shim not
    loaded)` when the shim was not loaded (`finding.json`
    `runtime_mode.shim_armed`). An installed bhf without the shim beside it
    can be pointed at one with `BHF_RUNTRACE_SHIM=/path/libbhf_runtrace_shim.so`;
  - reachability: the verdict and what it rests on. A verdict inferred from the
    entry's signature says it "matches an input-taking shape, so likely
    reachable from input; not proven"; an entry with no recorded reachability
    reads "not assessed"; and an overflow of a buffer the generated harness
    sized itself for a pointer parameter it passes without a length (a decoded
    C string, or a copy of the input with no length companion in the harness
    source) reads "precondition-dependent" (verdict `lab_only`). A harness
    buffer passed together with its length, such as the buffer of a
    `(buf, len)` pair, keeps the entry's verdict;
  - the recorded memory access (direction, width, the region hit and its
    allocation site), the sink and frames, and how to fix and reproduce it.

  Each block names its harness. Findings of one root
  cause (the same `cluster_key_full`, such as one site reached through several
  harnesses) are explained once, by the first, which lists the others and
  their harnesses; `--all-members` explains each one.
- `bhf decode-args [TESTCASE] [--finding <id>] [--harness <bin-or-dir>]` —
  the value each C/C++ harness parameter receives from a testcase: from the
  harness's own argument trace (`BHF_TRACE_ARGS=1`) when its binary runs, else
  (or with `--static`) from its `arg-layout.json`, naming each parameter that
  cannot be decoded statically and why. `--json` prints a
  `bhf.decode-args.v1` document. See the
  [C/C++ guide](c-cpp.md#decoding-a-testcase-without-running-it).
- `bhf cartography` — map which input bytes control which sink operand
  (offset/size/index) by perturbation — the exploit-primitive view of a finding.
  A SEGV on a wild pointer has no region-relative offset, so its bytes are mapped
  by the faulting address instead: replays run with address-space randomization
  off, and a byte that moves the address is `controls_address` (primitive
  `controlled_address_read`/`_write`). When two identical replays fault on
  different addresses, the bytes are `unknown` (primitive `unattributed_crash`)
  rather than don't-care; a crash no byte gates is `uncontrolled_crash`, not
  `gated_crash`. Turning randomization off needs the `personality(2)` system
  call, which a container's default seccomp profile refuses (Docker's, even
  with `--cap-add=SYS_PTRACE`). There, cartography prints a warning, and a
  wild pointer's bytes show as `unknown`; run the container with
  `--security-opt seccomp=unconfined` to map them. Heap, stack and global
  overflows are mapped by their region-relative offset and are not affected.

`capsule`, `verify-poc`, `cartography` and `env-capsule` work on runtime crash
findings (`classification: unhandled`). The language comes from
`generation-metadata.json` in the harness dir (else the `H-C`/`H-X`/`H-A`...
id prefix, else the driver file the dir holds), and the harness is looked up in
`harnesses/`, `auto/`, `generated_harnesses/` and `build/`, so a harness made
by hand with `generate-harness --id <name>`, `build` and `fuzz` works too.
`capsule` and `verify-poc` take every language below; `env-capsule` the native
ones; `cartography` C and C++ (it maps AddressSanitizer reports). A finding a
command does not take (an oracle hit, a missing harness or input, a harness its
lane cannot rebuild offline) is refused with its own reason and, when there is
one, a command that does reproduce it (`python3 <finding>/replay.py`, or the
built harness run on the input with the sanitizer options `bhf replay` uses,
leak detection included for a leak finding). `bhf explain` applies the same
first check:
it offers `bhf capsule`/`bhf verify-poc` only for findings whose lane and
harness layout capsule takes, and `bhf cartography` for AddressSanitizer
crashes it can map. What capsule checks while it packages (dependencies in the
local cargo, module or NuGet cache, the size of the tree it ships, paths it
cannot relocate) can still refuse a finding explain offered; capsule then says
why.

Per-lane requirements (a capsule records what it needs in `manifest.json`
`requires`; each program can be overridden by its variable):

| Lane (id prefix) | The capsule ships | Rebuild and replay need | Crash oracle | Refused when |
|---|---|---|---|---|
| C (`H-C`) | driver, target sources and their headers, stubs, C runtime headers and bhf's driver source, `build.sh` and `build.ps1` | `clang` or the compiler that built the harness (`CC`); on Windows (`build.ps1`) the recorded cl, clang-cl or clang | ASan / UBSan report | built with a cross compiler; no `main` rule in the Makefile |
| C++ (`H-X`) | as C | `clang++` or the compiler that built the harness (`CXX`); on Windows (`build.ps1`) the recorded cl, clang-cl or clang++ | ASan / UBSan report | as C |
| Ada (`H-A`) | `bhf_build.gpr`, `adafuzz_runtime.gpr` and the runtime sources, `src_instrumented/`, the generated harness, the stub packages, the operator projects it extends or `with`s (with the scanned tree) | `gprbuild` (`GPRBUILD`) and GNAT (`GNAT`) | unhandled exception in the event log, or a sanitizer report | never built (no `build/<id>/bhf_build.gpr`); built for another target; a project file it names lies outside the scanned tree |
| Rust (`H-R`) | harness crate, bhf's driver, the `rust_runtime` crate, the scanned tree, `vendor/` (`cargo vendor --offline`) when the lock file names crates.io or git packages | `cargo +nightly` through rustup (`BHF_CARGO`; `BHF_RUST_NIGHTLY` names the nightly) and `clang` (`CC`) | the panic, or an ASan report | a package not in the local cargo cache |
| Go (`H-G`) | harness module, the scanned tree, `vendor/` when the module needs modules from outside it | `go` (`GO`) | the recovered panic (`== bhf go finding:`) | a module not in the local module cache |
| Java (`H-J`) | launcher, harness source, bhf's JVM agent jar, the scanned tree, dependency jars on the classpath | `javac` (`JAVAC`) and `java` (`JAVA`) | `== bhf JVM finding:` | target classes built by Maven or Gradle |
| C# (`H-S`) | harness project, bhf's .NET driver, the entry, the scanned tree, `SharpFuzz.Common.dll`, the NuGet packages the restore resolved | the .NET SDK, `dotnet` (`DOTNET`) | `== bhf csharp finding:` | a NuGet package not in the local package cache |
| Python (`H-P`) | launcher, bhf's driver, decoder and coverage helpers, the generated harness, the scanned tree | `python3` (`PYTHON`) | `== bhf python finding:` | the run recorded no scanned tree |
| JavaScript (`H-N`) | launcher, bhf's driver, the scanned tree (with `node_modules`) | `node` (`NODE`) | `== bhf js finding:` | as Python |
| TypeScript (`H-T`) | as JavaScript, plus the transpiled target | `node` (`NODE`) | `== bhf js finding:` | as Python |
| Ruby (`H-U`) | launcher, bhf's driver, the generated harness, the scanned tree | `ruby` (`RUBY`) | `== bhf ruby finding:` | as Python |
| Perl (`H-L`) | launcher, bhf's driver and coverage module, the generated harness, the scanned tree | `perl` (`PERL`) | `== bhf perl finding:` | as Python |
| PHP (`H-W`) | launcher, bhf's driver, the generated harness, the scanned tree | `php` (`PHP`) | `== bhf php finding:` | as Python |
| Lua (`H-V`) | launcher, bhf's driver, the generated harness, the scanned tree | `lua`, `lua5.4`, `lua5.3` or `luajit` (`LUA`) | `== bhf lua finding:` | as Python |
| COBOL (`H-B`) | as C, with the `cobc -C` translation and the COBOL source | `clang` (`CC`) and the GnuCOBOL runtime (`cob-config --libs`, else `-lcob -lm`) | libcob's runtime check (`libcob: ... error:`) | as C |
| Fortran (`H-F`) | as C, with the Fortran sources (`harnesses/<id>/fortran-build.json` records how each object was compiled) | `clang` (`CC`) and `gfortran` (`FC`) | ASan report | as C |

The lanes that relocate their harness (all but C, C++, COBOL and Fortran)
refuse a tree they would have to copy that holds more than 20,000 files or
256 MiB, and a build file `build.sh` renders that still names the work dir or
the scanned tree after relocation. A text file they ship unchanged (a target
source, say) that names them is reported in a warning when the capsule is
written. The C, C++, COBOL and Fortran lanes ship the sources and headers the
build reads instead; the header copy stops at 10,000 files or 128 MiB, with a
warning.

A program `build.sh` finds under several names is met by any of them: the Lua
capsule records the interpreter it was packaged with and the others
(`requires[].alternatives`), so a capsule made where `lua` is installed
verifies where only `lua5.4` is. Setting the override variable checks that
program alone.

An Ada exception finding is checked against the exception the finding
recorded (manifest `finding_signature`), not only against the replay seen when
the capsule was packaged: a rebuilt PoC raising another exception is not
counted as reproducing (`reproduced: false`, `reproduced_other_crash: true`),
and `verify-poc` reports `MISMATCH` with the expected exception.

Exit codes: each of the four exits non-zero when a requested `--finding-id` is
refused (or cannot be packaged, mapped or captured, or its capsule did not
reproduce), and when a run without `--finding-id` writes nothing although the
work dir has runtime findings. A work dir with no runtime findings exits 0.

## Optional LLM and agent assistance

`bhf llm` is an advisory sidecar, not an `auto` stage:

```sh
bhf llm status --json
bhf llm test --provider codex
bhf llm prompt --task diagnose-error --input bhf_work/auto/run.json
bhf llm assist --provider local --model '<served-model>' \
  --task analyze-findings --input bhf_work/findings/F-0001/finding.json
```

Task names are `plan-run`, `generate-harness`, `analyze-findings`,
`explain-code`, and `diagnose-error`. `generate-harness` requires
`--target-symbol`; its structured `--language` option is Ada/C/C++ only. The
provider choices are cached Codex/Claude CLI sessions, explicit-model OpenAI or
Anthropic APIs, and an explicit-model local OpenAI-compatible endpoint. API
keys are accepted only through environment variables.

For interactive agent work, `bhf-daemon --mcp` exposes five read-only tools
for bounded deterministic evidence, prompt preparation, and Ada/C/C++ harness
preflight. It does not expose shell execution or long-running/mutating pipeline
steps. See [LLM Assistance](../llm/) for exact schemas, registration, provider
privacy, root-cause workflows, memory controls, and the deterministic checks
that must accept or reject model suggestions.

## Enterprise Operations

BHF provides offline governance commands for enclaves and CI systems:

```sh
bhf policy validate bhf-policy.json --out bhf_work/policy-summary.json
bhf runners validate runners.json --out bhf_work/runner-summary.json
bhf runners plan runners.json --queue runner-queue.json --policy bhf-policy.json --out bhf_work/runner-plan.json
bhf pack keygen --private-key keys/offline-root.der --public-key keys/offline-root.pub
bhf pack create --root packs/current --pack-id rules-2026-06 --item rules:rules/static.json --signing-key keys/offline-root.der --key-id offline-root --out packs/current/update-pack.json
bhf pack verify update-pack.json --root packs/current --out bhf_work/pack-verify.json
bhf sbom path/to/src --out bhf_work/sbom --vuln-db packs/current/cve-db.json --policy bhf-policy.json
bhf ci . --work-dir bhf_work --policy bhf-policy.json --runner-plan bhf_work/runner-plan.json --dashboard-out bhf_work/ci-dashboard.json
bhf export --work-dir bhf_work --out bhf_work/export-manifest.json --bundle-dir bhf_work/export-bundle --policy bhf-policy.json --update-pack update-pack.json --runner-plan bhf_work/runner-plan.json
```

`policy validate` checks the policy-as-code document and emits a deterministic
summary of enabled languages, rule counts, runner requirements, CI thresholds,
and allowed update-pack kinds.

`runners validate` checks an offline runner capability manifest and emits the
runner ids, kinds, languages, engines, sandbox settings, and target triples
declared by the enclave.

`runners plan` reads a queue of offline fuzz/static/binary jobs, applies
policy runner allow-lists, sandbox requirements, target triples, capabilities,
and runner capacity, then writes a deterministic assignment plan. Jobs blocked
by policy or capacity remain in `unassigned` with diagnostics, and the command
exits non-zero unless every job is assigned.

`pack create` builds a deterministic air-gapped update pack manifest from
`kind:path` items under `--root` and computes item SHA-256 hashes. Use
`pack keygen` and `--signing-key` with `--key-id` to authenticate the whole
manifest with Ed25519. The verifying policy must independently supply the
matching public key in `update_packs.trusted_public_keys`; it can revoke an
ID through `update_packs.revoked_keys`. The deprecated `--sign-key` option
only adds a `sha256-items-v1` integrity digest and never authenticates a
publisher. `pack verify` recomputes hashes under `--root` and enforces
update-pack policy constraints, including publisher authentication.
Tampered or missing items make verification exit non-zero.
The source-tree document `docs/enterprise-pack-authentication.md` specifies
canonical bytes and key rotation.

`sbom` takes `--work-dir <DIR>` (default `bhf_work`); without `--out` it
writes under `<work-dir>/results/sbom/` and rebuilds `results/` (each
vulnerability match becomes an `sca` finding in `findings.json`). Pass
`--out <DIR>` to write elsewhere instead, which opts out of `results/`.
`sbom` writes `sbom.json`, `cyclonedx.json`, `vulnerabilities.json`,
`openvex.json`, and — under the `csv` kind — both a flat one-row-per-component
`sbom.csv` inventory and a one-row-per-CVE-match `vulnerabilities.csv`
offline (select a subset with `--emit cyclonedx,sbom,vulnerabilities,openvex,csv,cyclonedx-vex`).
The `sbom.csv` projection carries name, version, ecosystem, type, supplier,
license, purl, cpe, sha256, identity confidence, matching method, usage, runtime
harnesses, and evidence — RFC-4180 escaped for spreadsheet/procurement ingestion.
The `vulnerabilities.csv` projection carries component, version, purl, cve,
severity, cvss_score, cwe, kev, reachability, and advisory — one row per offline
CVE match, with the CWE pulled from the same normalized field as
`vulnerabilities.json` and the CycloneDX `vulnerabilities` entries.
It detects local component manifests (`Cargo.toml`, `package.json`,
declared component JSON, and vendored `VERSION` directories), can ingest
`--binary-inventory` evidence, and also folds runtime `dlopen` observations
from `auto/run.json` into `runtime-dlopen` components. It emits CycloneDX 1.6
JSON with component purls, declared component CPEs, hashes, dependency
relationships, declared component supplier/license metadata, BHF evidence
properties, and BHF tool metadata including supplier, license, and package
URL, then matches against an offline
`--vuln-db` from an update pack. Vulnerability entries can identify packages by
`package.ecosystem`/`package.name` plus `affected_versions`, or by
`package.purl` or `package.cpe` plus `affected_versions`; PURL and CPE matches
are reported as high-confidence `matching_method: "purl"` or
`matching_method: "cpe"` findings. Identifiers are compared structurally
rather than as exact strings: comparison is case-insensitive, both CPE 2.2
URIs and 2.3 formatted strings are accepted with `*` fields treated as
wildcards, and an advisory purl without a version matches any component
version covered by `affected_versions` — while an advisory purl or CPE that
contradicts the component's identifier vetoes a name/version match.
Declared component JSON may set `supplier`, `license`, and `sha256` strings to
populate the corresponding BHF SBOM and CycloneDX component fields.
Vulnerability entries can carry
`kev` metadata (`known_exploited`, `date_added`, `due_date`,
`required_action`), CVSS metadata (`version`, `score`, `vector`), and CWE
metadata (`cwe` or `cwes`), plus advisory/reference URLs, which are preserved
in `vulnerabilities.json` and counted under `counts.kev_matches`. The same
offline matches are also emitted in CycloneDX `vulnerabilities` entries with
affected component refs, CVSS ratings, CWE ids, `advisories`, and BHF
properties for match method, confidence, reachability, and KEV status. When an
`auto/run.json` is present under the
scanned root or sibling work directory, CVE matches whose source/binary
component evidence overlaps a built-and-fuzzed target, or whose runtime-dlopen
component was observed by a built-and-fuzzed harness, are annotated with
`reachability.status: "reached_by_fuzz"` and counted under
`counts.reached_matches`. Use `--fail-on
low|medium|high|critical` for a direct gate, or `--policy` to read
`/ci/fail_on_vulnerability_severity` from policy-as-code. `bhf ci` forwards
the `auto` budget knobs so a CI run can be bounded the same way: `--per-target-time`
(per-target total fuzz wall), `--per-target-finding-count N` (stop a target after
N distinct findings; `1` ≈ stop-on-first-crash), and `--campaign-time` (whole-run
cap, or an even split across targets when paired with `--min-target-time`).

`export` bundles `results/` (`INDEX.md`, `findings.{json,csv,sarif}`,
`manifest.json`, `attestation.json`, `static/`, `sbom/`) alongside the other
handoff artifacts it already collects.

`export` writes a deterministic manifest for handoff artifacts already present
under the work directory, including report JSON/Markdown/SARIF/JUnit/CSV, static
reports, SPDX-style SBOM, CycloneDX SBOM, vulnerability reports, `auto` run
metadata, policy files, and update-pack manifests. Pass `--runner-plan` to include assignment evidence in
the export and governance summary. `bhf ci --runner-plan` uses the same plan
to populate dashboard budget allocation counts, and policies can set
`/ci/require_runner_plan` plus `/ci/require_full_runner_assignment` to fail CI
when scheduling evidence is missing or jobs remain unassigned. Pass
`--bundle-dir` to copy all exported artifacts into a deterministic
`artifacts/<kind>/...` tree and write a bundle-local `export-manifest.json` for
air-gapped handoff.

`bhf list targets` prints each candidate's stable `harness_id` in table and
JSON output. Use that id with `bhf auto --harness-id <ID>` to rerun one
specific target when names collide across files.

`bhf fuzz` runs the built-in engine against a built harness under
`bhf_work/build/<harness-id>/`. It accepts literal `--seed-input` values
(their UTF-8 bytes), `--seed-file` bytes (used byte for byte, so binary seeds
belong there), or prototype `--symbolic-seed-source` Ada files whose
guarded string literals are mined into seed bytes. A C/C++ harness that
decodes fixed-width parameters before its buffer also gets each
`--seed-input`/`--seed-file` seed behind that many zero bytes (from its
`arg-layout.json`), so the buffer starts with it; with `--workers`, the
campaign makes these once and its workers add none. It writes corpus entries under
`bhf_work/corpus/` (with the harness input format in
`corpus/<harness-id>/metadata.json`), emits findings under `bhf_work/findings/`, and stores
the latest run metadata in `bhf_work/fuzz_runs/<harness-id>-latest.json`.
Fuzz run summaries and finding records include `sandbox` metadata so reports
distinguish sandboxed and unsandboxed executions.

A crash whose root cause is already recorded for the harness (a finding under
`results/findings/` from an earlier run) is not recorded again. The summary
lists those findings under `duplicates_of_existing`, counts the matching
executions in `duplicate_crashes_of_existing`, and stderr gets a one-line note,
so a run whose crashes were all known does not read as clean.

`bhf fuzz` flags (libFuzzer-parity knobs and engine controls):

- `--engine <builtin|afl++>` — engine to run. Default `builtin`.
- `--afl-mode <native|qemu|frida>` — AFL++ execution mode for `--engine afl++`. `native` (default) uses compile-time instrumentation; `qemu` (`afl-fuzz -Q`) and `frida` (`afl-fuzz -O`) add coverage inside a stripped, source-less dependency the harness loads, without rebuilding it. Ignored by the builtin engine.
- `--afl-path <DIR>` — AFL++ install directory. Sets `AFL_PATH` and locates `afl-fuzz`, so QEMU/Frida mode finds `afl-qemu-trace` / `afl-frida-trace.so` from a build that is not on `PATH`.
- `--afl-inst-range <RANGE>` — scope binary-only instrumentation to a module or address range (e.g. `target.so` or `0x555000-0x556000`). Repeatable; joined into `AFL_QEMU_INST_RANGES` (`--afl-mode qemu`) or `AFL_FRIDA_INST_RANGES` (`--afl-mode frida`). Requires a binary-only `--afl-mode`.
- `--iterations <N>` — execution cap. Defaults to `256` when neither this nor `--time` is set; with `--time` set and this omitted, the run is bounded only by the time budget.
- `--time <DURATION>` — whole-campaign wall-clock budget (e.g. `30s`, `5m`, `1h`).
- `--max-len <BYTES>` — maximum generated input length (libFuzzer `-max_len`). Default `4096`. With adaptive length control on this is the ceiling.
- `--len-control <N>` — adaptive length control (libFuzzer `-len_control`): executions without a new corpus signature before the effective length doubles toward `--max-len`. Default `100`; `0` disables it.
- `--timeout <DURATION>` — per-input timeout (libFuzzer `-timeout`): a single C/C++ harness execution longer than this is killed and the slow unit reported. Distinct from `--time`. Default `10s`. (Ada bounds runaway inputs via CPU rlimits.)
- `--deadline <DURATION>` — real-time response deadline, the **timing oracle** (off by default). Unlike `--timeout` (which discards a slow unit), any input whose wall-clock execution exceeds the deadline is recorded as a *finding* (BHF-555, a CWE-400 timing/availability failure). For watchdog / RTOS / radar targets where overrunning a budget is a fault, not just a hang. Whole-second spec (e.g. `1s`); use `BHF_DEADLINE_MS` for sub-second budgets. See [On-Target & Embedded](./on-target-fuzzing.md).
- `--rss-limit-mb <MB>` — per-execution resident-memory ceiling for a C/C++ harness (libFuzzer `-rss_limit_mb`); an execution over budget is killed and reported as an OOM finding. `0` (default) disables it.
- `--print-final-stats` — print a final-stats line (libFuzzer `-print_final_stats`): executions, exec/s, new vs duplicate corpus signatures, findings, elapsed time.
- `--workers <N|auto>` — run multiple fuzz workers. When the campaign ends, their findings move into `<work-dir>/results/findings` under fresh ids, one per crash cluster; duplicates stay in the worker dirs while the finding they duplicate is in `results/findings`. Once that finding is removed (or `results/` is wiped), the next campaign drops them instead of merging them back.
- `--fork-server` / `--no-fork-server` — persistent framed execution is the default for the builtin engine. Native drivers and the Java, Python, Perl, Go, C#, JavaScript/TypeScript, Ruby, Lua, and PHP launchers each keep one target runtime alive and feed it inputs over the same protocol. Every finding is replay-validated in a fresh process so a global-state artifact never escapes (#416). `--no-fork-server` runs a fresh process per input — use it for a target that intentionally carries fuzz-relevant global state across calls.
- `--cmplog-log <PATH>` — replay a runtrace audit log captured with `BHF_CMPLOG=1`; recovered cmplog operands seed both the mutator dictionary and an offset-aware RedQueen-style splice that replaces `operand_a` with `operand_b` at the offset it appears in the current input (#400).
- `--sanitizers <asan,msan,ubsan,tsan,lsan|none>` — native C/C++ sanitizer campaign matrix; other lanes own their instrumentation.
- `--target-transport <SPEC>` — run the loop against an off-host / on-target backend instead of the host lane (additive; absent = host path unchanged). Spec forms: `agent:tcp:HOST:PORT`, `agent:serial:/dev/ttyX`, `gdb:HOST:PORT`, `qemu-system:qmp=…,gdb=…[,snapshot=TAG]`. On-device agent, debug-probe/emulator gdbstub, or full-system `qemu-system` snapshot. See [On-Target & Embedded](./on-target-fuzzing.md).
- `--transport-coverage-map <SPEC>` — for the memory-read transports (`gdb`, `qemu-system`), locate the on-target coverage ring: `input=<addr>,ring=<addr>,write=<addr>,wrapped=<addr>,cap=<n>` (decimal or `0x`-hex). The `agent` transport carries coverage over its protocol and rejects this.
- `--protocol-profile <PATH>` — load a versioned protocol profile (TOML, `bhf.protocol.v1`) and fuzz the target as a **response-dependent, multi-message session** instead of single opaque inputs (additive; absent = the paths above are unchanged). Presence routes to the session lane, which needs `--session-transport`. See [Stateful protocol sessions](#stateful-protocol-sessions-hdf-7) below.
- `--session-transport <SPEC>` — request/response backend for the session lane. `tcp:HOST:PORT` connects a socket per session. Required with `--protocol-profile`.
- `--session-reset <reconnect|none>` — how a session is reset between testcases: `reconnect` (default; a fresh connection gives fresh per-session target state, so a new handle/id/nonce is captured each run) or `none` (keep one connection). Recorded as the run's reset fidelity.
- `--max-session-messages <N>` — bounded cap on messages per session (default `64`); a sequence mutation that would exceed it fails with a diagnostic rather than growing unbounded.
- `--rng-seed <N>` — deterministic RNG seed for built-in mutation.

Multi-worker campaigns (`--workers N` with N > 1, or `--sanitizers` with more
than one sanitizer, one worker per sanitizer) resolve the harness executable in
the parent, as a single run does. Each harness dir the lookup reads
(`build/<id>/` and the `bhf auto` layouts `harnesses/<id>/`, `auto/<id>/`,
`generated_harnesses/<id>/`) in each `worker-<id>-N/` dir is made an exact copy
of the parent's: the worker's copy of a dir the parent does not have is removed,
and a copy that differs from the parent's (a file added, missing, resized or
rewritten) is copied again. A worker therefore runs the executable the parent
resolved, never one left by an earlier campaign. Without a built harness the
campaign exits `3` before starting any worker. Each worker's stderr goes to
`worker-<id>-N/worker-stderr.log`; for a worker that did not complete, the
summary's `per_worker[].stderr_tail` and stderr show its last lines, and
`per_worker[].stopped_at_deadline` marks a worker stopped at the time limit.
When every worker exits non-zero (or is killed by a signal), `bhf fuzz` exits
non-zero (the workers' shared exit code, else `1`). Workers stopped at the time
limit fuzzed until then: when they recorded findings, the campaign keeps its
usual exit code and stderr says they were stopped; when none recorded anything,
it exits `1`.

`bhf fuzz --engine` accepts only `builtin` (the default) and `afl++`;
`libfuzzer`, `libafl`, and `nyx` are **not** valid `--engine` values and clap
rejects them. C/C++ generated harnesses expose `LLVMFuzzerTestOneInput`, but
their default `main` binary is bhf's own framed fork-server driver, not a
libFuzzer binary, so BHF can normalize sanitizer findings; there is no separate
`libfuzzer` runtime path through this flag (`make libfuzzer` builds a libFuzzer
binary for other fuzzers). A binary you compiled yourself with
`-fsanitize=fuzzer` and placed at `build/<id>/main` is recognised by the
libFuzzer runtime in it and run on one input file per process, so a crash it
finds is recorded with the input that caused it. It gets no coverage guidance
without bhf's runtime, and `bhf fuzz` says so: wrap the fuzz target with
`bhf generate-harness <fuzz_target.cc> --target LLVMFuzzerTestOneInput`, build
that harness and fuzz it instead. The standalone libFuzzer/LibAFL/Nyx adapters
are not reachable through `bhf fuzz --engine`, and the Ada libFuzzer adapter
remains deferred until users have a viable Ada/LLVM/libFuzzer toolchain.

Replay, minimize, and built-in fuzzing accept `--sandbox none|auto|firejail|bubblewrap`.
Use `--sandbox-tool` to point at a specific wrapper and `--sandbox-strict` to
fail instead of falling back when the requested wrapper is missing.

### Stateful protocol sessions (HDF-7)

`bhf fuzz --protocol-profile <PATH>` drives the target through a
**response-dependent, multi-message session** rather than single opaque inputs: a
later message echoes a per-session value (a handle / id / nonce) that an earlier
message's reply returned, while both messages carry computed length/CRC fields.
A testcase is a *sequence* of structured messages; mutation edits field values
AND sequence structure, then a repair pass recomputes the derived fields and
re-resolves the response back-references before each frame is sent. The security
violation it looks for **exits cleanly** (no crash) — it is flagged by a
profile-declared oracle (a sentinel response field, or arrival in a declared
violation state).

The profile (TOML, `schema = "bhf.protocol.v1"`) declares the message types and
their typed fields (byte order / width / enums / bounded variable-length data /
optional fields), the computed fields (`length(..)`, `crc32(..)`/`crc16(..)`/
`sum8(..)`/`xor8(..)`, `offset(..)`, TLV) and response back-references
(`ref = "OPEN.response.handle"`), the legal message ordering as transitions, the
response captures a reply exposes, the session `reset`, and the `[[oracle]]`
that marks the clean-exit finding. The seed session is synthesized from the
profile (a legal, reference-satisfying walk).

```sh
bhf fuzz bhf_work --harness H-PROTO \
  --protocol-profile profiles/toy-open-write.toml \
  --session-transport tcp:127.0.0.1:9000 \
  --session-reset reconnect --iterations 2000
```

The run reports the two novelty channels **separately** — code-coverage novelty
(`coverage_edges` / `coverage_blocks`) and protocol-state/transition novelty
(`states_covered` / `transitions_covered`) are distinct fields, never merged. A
plain request/response transport reports no code edges, so the code channel is
zero on such targets while the state channel carries the novelty;
richer code coverage arrives when a backend supplies edges. The run and every
finding record the profile SHA-256 and the effective transport/reset fidelity
(e.g. `tcp;reset=reconnect`).

A finding is written through the usual `results/` layout for importers / SARIF /
vulnerability-management tools, with a `session.json` artifact (the structured
message sequence, the state path, the per-step captured replies, and the
response-derived bindings) plus a self-contained `session_meta.json` sidecar
(the profile inline + the transport spec). `bhf replay <finding>` and
`bhf minimize <finding>` detect that artifact automatically: replay re-drives the
recorded session against a **fresh reset** (re-capturing a different handle and
re-resolving the reference, so it still reproduces), and minimize shrinks the
sequence and bytes fields while re-repairing the computed fields and keeping the
dynamic bindings live.

Every bound is explicit and surfaced as a bounded diagnostic rather than a panic
or an unbounded loop: a malformed profile or an unresolved reference, a truncated
response, an excessive message count (`--max-session-messages`), and an oversized
frame each fail with a descriptive, named error.

For real project layouts where the target body depends on parent package specs
outside its directory, pass each additional source root to harness generation:

```sh
bhf generate-harness src/base/dates/util-dates-iso8601.adb --target Value --source-root src/core --source-root src/base/dates
```

For C and C++ manual runs, `--target` is required. For C++ it accepts the bare
name, a `::`-qualified suffix (`Parser::parse`), the fully qualified name as
`bhf list targets` prints it, or any of those with a parameter list. An
exact spelling wins over a suffix, a leading `::` names the global namespace
only, and a miss lists the closest definitions. The generated harness is Makefile-based, so
`bhf build` runs `make` and stages `build/<harness-id>/main`.

```sh
bhf generate-harness src/parser.cpp --target Parser::parse --output bhf_work/harnesses
bhf build bhf_work --harness H-CPP000A
bhf fuzz bhf_work --harness H-CPP000A --iterations 1000 --seed-input smoke
```

`bhf build` takes the work directory (it also accepts a harness directory
`bhf_work/harnesses/<id>` and says so). When the lookup fails it names the
harness ids it found, and when the link fails it names the in-tree sources
that define the missing symbols, with the `--extra-source` flags and an
`AUTO_EXTRA_SOURCES` command to add them.

`bhf build` takes the toolchain from `--cc`/`--cxx`, `--target <triple>` (or
`--toolchain <prefix>`: `<prefix>-gcc`/`<prefix>-g++`), `--sysroot`, `--cflags`,
`--cxxflags`, `--ldflags`, `--define` and `--toolchain-include`, or from the
`[toolchain]` table of `--config <file>` (the same table `bhf auto --config`
reads; there the compilers come from `target` or `cc`/`cxx`, since
`toolchain.ada.prefix` applies to Ada harnesses only). Flags are appended to
bhf's coverage and sanitizer flags, and the compilers in use are announced.
`--runtime`, `--probe-backend` and the `--ada-*` flags are Ada-only and refused
for a C/C++ harness. See
[Cross-Compilation](../cross-compilation/).

```sh
bhf build bhf_work --harness H-CPP000A --target aarch64-linux-gnu
bhf build bhf_work --harness H-CPP000A --cxx g++ --define BOARD=3
```

Use `--extra-source`, `--extra-include`, and `--cleanup` when the target needs
additional translation units, include directories, or return-value cleanup. See
[C and C++ Fuzzing](../c-cpp/) for supported parameter shapes and limits, and
[Custom C and C++ Harnesses](../custom-harness/) for writing your own harness.

For AFL++ on a generated C/C++ harness:

```sh
bhf build bhf_work --harness H-CPP000A --c-engine afl++
bhf fuzz bhf_work --harness H-CPP000A --engine afl++ --time 30s --seed-input smoke
```

To add coverage inside a stripped, source-less library the harness loads, run
AFL++ in QEMU (or Frida) binary-only mode and scope instrumentation to that
module so the campaign sees edges in the dependency, not just the harness:

```sh
bhf build bhf_work --harness H-CPP000A --c-engine afl++
bhf fuzz bhf_work --harness H-CPP000A --engine afl++ \
  --afl-mode qemu --afl-inst-range libtarget.so --time 30s --seed-input smoke
```

`bhf clean` is conservative when no scope is selected. Use `--compact` to
remove disposable compiler caches and scratch files while preserving findings,
reports, corpora, checkpoints, generated source, and replay binaries. Use
`--build`, `--corpus`, `--reports`, `--findings`, or `--all` for explicit deletion
scopes under the work directory. `--findings` removes `results/` (findings,
indexes, `static/` and `sbom/` reports) plus any legacy `findings/`/
`FINDINGS.md`/`findings.csv` paths; `--reports` removes only `results/report/`
(the `bhf report` snapshots), leaving the rest of `results/` intact.

## Auto

`bhf auto <PATH>` sweeps a source tree in any of the sixteen supported
languages (Ada, C, C++, Rust, Java, Python, Perl, Go, COBOL, Fortran, C#,
JavaScript, TypeScript, Ruby, Lua, and PHP), including
definition-bearing C/C++ headers, generates one harness per fuzzable function,
auto-stubs missing headers and undefined symbols so previously-unbuildable code
builds, runs a three-pass fuzz cascade against each built harness with the
runtime virtualisation shim loaded on supported Linux targets (not
Java/C#/JavaScript/TypeScript or cross/emulated targets), and writes a
persistent fuzz lab. Findings go into `<work>/results/`: start with
`results/INDEX.md`, use `results/findings.csv` / `findings.json` for the
machine-readable index, and inspect `results/findings/` for evidence bundles.
Campaign mechanics, coverage, and the `needed_for_build` ledger remain under
`<work>/auto/` in `run.md` and `run.json`.

```sh
bhf auto path/to/src --work-dir bhf_work --per-target-time 60
```

Flags:

- `--work-dir <DIR>` — output root. Default `./bhf_work/`.
- `--max-work-dir-mb <MiB>` — stop starting new targets when the allocated work-directory size reaches this ceiling. Default `4096`; `0` disables. Findings are preserved, and parallel in-flight targets may finish past the ceiling.
- `--max-corpus-mb <MiB>` — per-target retained corpus ceiling for memory and disk. Default `64`; finding testcases are separate and are not discarded.
- `--per-target-time <SECS>` — the **total** per-target fuzz wall, split evenly across the passes (`auto` runs empty / rng / fuzz-driven) under one shared deadline, so the per-target wall ≈ this regardless of pass count. Default `60`. libFuzzer `-max_total_time` / AFL `-V` parity (#402). When more than one engine runs for a target (see `--engine`), this budget splits evenly across the engines too.
- `--engine <builtin[,afl++]>` — fuzz engine(s) for the per-target fuzz phase, comma-separated. `builtin` (default) is the in-process coverage-guided engine. `afl++` drives AFL++ on the **auto-recovered** build — `auto` runs `make afl` to produce the afl-instrumented `main_afl`, then `afl-fuzz`; crashes fold into the same findings pipeline and the pass is attributed to `afl++` in `run.json`. `--engine builtin,afl++` runs BOTH per target, splitting `--per-target-time` evenly. AFL applies to **native C/C++ targets only** (Ada/Rust/Java, and cross-compiled C/C++, fall back to the builtin engine, logged — never a silent skip). If `afl-fuzz`/`afl-clang-fast` are not on PATH, the run warns once and falls back to builtin. Unlike `bhf build`/`fuzz --engine afl++`, this needs no separate steps and works on trees that don't build as-is, because `auto` recovers the build first.
- `--per-target-finding-count <N>` — stop a target's cascade as soon as it has produced N *distinct* findings (crash signatures), or when `--per-target-time` is spent, whichever first. Checked mid-pass (stops the instant the Nth lands; remaining passes skipped). `1` ≈ libFuzzer stop-on-first-crash. Unset by default (collect every finding).
- `--total-time <SECS>` — **deprecated** alias of `--per-target-time` (overrides it when set); retained for existing benchmark/parity invocations. Hidden from `--help`.
- `--iterations <N>` — per-pass execution cap (libFuzzer `-runs`); unset (or `0`) lets `--per-target-time` govern depth. The old hardcoded 1024 cap is retired.
- `--rss-limit-mb <MB>` — per-harness resident-set memory cap; a test case over budget is killed and reported as a BHF-209 OOM finding instead of OOM-killing the host (libFuzzer `-rss_limit_mb`). Defaults to one quarter of available host/cgroup memory, clamped to 512..8192 MiB; pass an exact value or `0` to disable.
- `--max-targets <N>` — keep only the top-N highest-scored targets after ranking, before the build/fuzz sweep; `--dry-run` prints this bounded plan, while `--list-targets` still prints the full ranked list. The kept-vs-total count is logged (never a silent truncation). Bounds *which* targets a huge tree attempts. Unset by default.
- `--campaign-time <SECS>` — whole-*run* budget across all targets. Default: an OUTER wall-clock cap — once exceeded, `auto` stops STARTING new (ranked) targets and reports how many of the N discovered were reached. With `--min-target-time`, switches to SPLIT mode (below). Unset by default.
- `--min-target-time <SECS>` — SPLIT-mode floor, used only with `--campaign-time` (errors otherwise): divide the campaign budget across the N attempted targets — each gets `max(min, campaign / N)` of fuzz time, and only the top `floor(campaign / per_target)` ranked targets are attempted (the rest logged unfuzzed), never below this floor. Overrides `--per-target-time`. Unset by default.
- `--jobs <N>` / `-j <N>` — build+fuzz up to N targets concurrently via a bounded worker pool. `jobs × --rss-limit-mb` is only the child allowance; also reserve RAM for the parent declaration index/results, compiler processes, and the OS. Results aggregate deterministically regardless of completion order. Default `1` (serial).
- `--passes <SET>` — restrict the per-target cascade to a comma list of passes (`empty`, `rng`, `fuzz`); e.g. `--passes fuzz` runs only the fuzz-driven pass (~3× the 3-pass throughput). Mutually exclusive with `--single-pass`. Default: all passes.
- `--single-pass` — convenience for `--passes fuzz`: run only the fuzz-driven pass per target.
- `--max-repair-rounds <N>` — ceiling on build-fail → repair → retry rounds per target; the default covers all 95 successful clean/damaged samples in the strengthened 53-repository matrix (p95 6, p99/max 14 rounds). The no-progress early-break still applies, so it is a cap, not a fixed cost. Default `16`.
- Discovery cache (**on by default**) — a re-run reuses the prior discovery from `<work>/discovery-cache.json` when a **build-stable** content fingerprint of the target source (file paths + sizes + content hashes + dir-filter) is unchanged, skipping the tree-sitter re-parse + re-rank. The fingerprint depends only on the fuzzed code, not on which bhf build computed it, so rebuilding bhf does not invalidate it. A mismatch recomputes and rewrites the cache; a stale cache is never used silently.
- `--fresh-discovery` — force a fresh discovery this run (ignore any cache), then overwrite the cache.
- `--no-discovery-cache` — disable the discovery cache entirely (never read or write it).
- `--resume` — resume a prior sweep over the same work-dir: reload targets that already completed (a per-target `harnesses/<id>/result.json` is written as each target finishes, so an interrupted run is resumable) and re-run only the rest. Reloaded targets are FULLY re-integrated into the new report (outcome buckets, repair manifest, findings, pass detail), with a `resumed` count of how many were carried over. Requires the discovery cache to hit (target source unchanged).
- `--reuse-discovery` — deprecated no-op (caching is now the default); accepted for back-compat.
- `--sanitizers <asan,ubsan,msan,tsan,lsan|none>` — arm the native C/C++ sanitizer matrix on the auto build; other lanes own their instrumentation.
- `--languages <LIST>` (alias `--lang`) — restrict the sweep to a comma-separated subset of the sixteen fuzzable source languages (`ada`, `c`, `cpp`, `rust`, `java`, `python`, `perl`, `go`, `cobol`, `fortran`, `csharp`, `javascript`, `typescript`, `ruby`, `lua`, `php`). Candidates in other languages are dropped after discovery and before `--list-targets`/`--max-targets`, so the ranked list and the top-N reflect the filter. Common spellings accepted (`c++`/`cxx`/`cc`→cpp, `rs`→rust, `py`→python, `pl`→perl, `golang`→go); case-insensitive. Unset = fuzz every language found. The SBOM/SCA pass is unaffected.
- `--target <NAME>` — target-name filter: the full discovered name, the bare name, or a qualified suffix such as `Class::method`, optionally with the parameter list. An exact spelling wins: the suffix match applies only when no target has exactly that name. Repeat to run a small named subset. A name that selects nothing prints the closest discovered names. A project fuzz driver (`LLVMFuzzerTestOneInput`) is skipped when the tree has other targets unless `--target`, `--target-file`, or `--harness-id` selects it.
- `--target-file <PATH>` — exact source-file filter. Accepts absolute paths or paths relative to the sweep root.
- `--harness-id <ID>` — exact stable harness-id filter from a prior auto report.
- `--exclude-path <TEXT>` — drop targets whose normalized relative source path contains `TEXT`. Repeatable.
- `--exclude <tests,tools,examples>` — drop common project areas before attempts run.
- `--no-stubs` — skip the build-time repair planner (diagnostics mode).
- `--mode reporting|attacking` — actionability profile and, in attacking mode, target scheduling.
- `--seed-file <PATH>` / `--seed-dir <DIR>` — seed bytes bootstrapped into every target's corpus (a real `.zip`, `.bz2`, sample document) so parsers reach deep code. Used byte for byte. Repeatable. Without them, auto mines seeds from the tree's own test data.
- `--no-seed-mining` — do not mine seeds from the tree's test data (config key `seed-mining = false`). Every run lists the seeds it used in `auto/seeds.json`; `-v` prints them.
- `--extra-include <DIR>` — extra C/C++ include dirs for dependency headers outside the swept tree (cFE OSAL/PSP, a vendored SDK's `include/`). Read from local disk only. Repeatable.
- `--max-decode-depth <N>` — C decoder synthesis: max recursion depth for nested struct/union/array decoders; past it a field is left zeroed. Default `4`.
- `--max-array-elems <N>` — C decoder synthesis: max elements decoded per fixed array (a larger array fuzzes its fill count `0..cap` instead of every slot). Default `64`.
- `--max-decl-bytes <BYTES>` — C decoder synthesis: byte ceiling on a single parameter's decoder body; a larger body rejects the parameter. Default `65536`. C++ has the parallel `--container-size-max`, `--bitset-max-size`, and `--array-max-size` caps.
- `--ada-deps <DIR>` — local Ada dependency-source dirs to put on the build path (offline, never fetched). Repeatable; locally-cached Alire deps are picked up automatically.
- `--comparison-progress` — enable laf-intel comparison-progress coverage for multi-byte magic / format gates (#421). Alias `--cmp-progress`. Off by default.
- `--probe-build` — run the project's own build offline (CMake configure / `make` under a compiler-interposing wrapper) to recover real compile flags and generated headers before harnessing. Executes untrusted build scripts (sandboxed when bwrap/firejail present). Off by default.
- `--run-untrusted` — consent gate for running the project's own untrusted build/codegen; the umbrella for `--probe-build` plus an Ada (`alr build` / `gprbuild`) build probe. Implies `--probe-build`. Off by default.
- `--deps-only` — build each target as far as possible (stubbing what is missing) and emit the missing-dependency manifest (`<work>/auto/missing-deps.txt`), but SKIP fuzzing.
- `--install-deps` — after the sweep, fetch the still-blocking dependencies (apt-get for known headers/libs, `alr get` for Ada units). Opt-in and ONLINE — the only part of `auto` that touches the network.
- `--msbuild-solution <PATH>` / `--msbuild-config <CONFIG|PLATFORM>` / `--no-msbuild-import` — the Visual Studio project import, on by default for a tree with a solution or project and no compile database or CMake/Meson build (off Windows, only when the solution is the tree's only build description): which solution (relative to the scanned tree; a missing file is an error) and configuration it reads, or turning it off. It runs nothing; see [c-cpp.md](c-cpp.md).
- `--msbuild-evaluate` — let an installed MSBuild evaluate the imported projects instead of the static reading (it runs their property functions; `--probe-build` implies it).
- `--no-vs-env` / `--vs-arch <ARCH>` (global, Windows) — turn off Visual Studio/SDK discovery, or pick its target architecture; see [windows.md](windows.md).
- `--build-command <CMD>` — recover flags from any CUSTOM build (a `build.sh`, Waf, a vendor RTOS build) by running `<CMD>` under a compiler-interposing shim; the universal escape hatch when `--probe-build`'s auto-detected tiers (CMake/Meson/Make/Ninja/Visual Studio) don't cover the project. Executes the command (sandboxed when available).
- `--static` — run the static analyzer over the WHOLE tree in addition to fuzzing (not only as a build/fuzz fallback). Findings (`static_scan`, ids `F-STATIC-*`) merge into the unified report next to the fuzz findings. Same engine as `bhf static-scan`.
- `--force` / `--force-fuzz` — force-fuzz mode: attempt EVERY discovered C/C++/Ada function even when a parameter can't be driven or a symbol is undefined, stubbing until the harness builds. Findings from a forced/stub-heavy build are floored to **Low** confidence with a `forced` note and counted separately.
- `--differential <A:B>` — two-compiler differential fuzzing for C/C++ (e.g. `clang:gcc`): after the run, rebuild each C/C++ harness under both compilers, replay the corpus through both, and flag any input whose exit/crash behavior diverges as a BHF-301 finding.
- `--no-minimize` — skip the post-fuzz minimization pass (default: `auto` minimizes the representative finding of each root-cause group into `min_testcase.bin`, bounded at 30s per group / 5min total; groups not reached within budget are listed in `results/INDEX.md`).
- `--list-fakes` — print the fake-resource plugin inventory and exit.
- `--verbose` / `-v` — print an extra indented line per target: skip/fail reason, repairs applied, and per-pass execution/finding counts.

Exit codes: `0` at least one target built and ran, `1` discovery found
candidates but none built, `2` no candidates discovered.

The runtime audit and the shim's faking modes are Linux-only. On other hosts
`bhf auto` still runs the build-time sweep but prints a one-line notice
that runtime audit is disabled.

See [Auto](../auto/) for the full pipeline and
[Runtime Virtualisation](../runtime-virtualisation/) for the LD_PRELOAD shim,
three-pass cascade, and replay env vars.

## Fake CORBA And IDL Dictionaries

`bhf fake-corba <work-dir> --idl <file.idl>` emits Ada mapping packages for
the IDL model and writes `fake_corba/dictionary.txt` when the IDL or translated
ROS interfaces contain reusable tokens. The dictionary includes module,
interface, operation, struct, enum, exception, typedef, constant, union, and
case-label names plus constant values. `bhf fuzz` automatically falls back
to this work-dir dictionary when a harness-specific dictionary is not present;
the built-in engine uses the tokens as insertions and as ingredients for
record/TLV-, JSON-, XML element-, key/value-, URL-encoded query-shaped,
multipart/form-data, CSV/table-row, raw HTTP request, INI section/key, TOML
table/key, or YAML section/key structured inputs.

## Introspection

`bhf introspect <PATH>` inventories discovered fuzz targets across the supported languages
and compares them with a prior `bhf auto` run when
`<work-dir>/auto/run.json` exists. The report highlights targets that were
already fuzzed, built but not fuzzed, build/link blocked, unsupported, or newly
discovered since the prior run.

The command also builds a lightweight static call graph from the scanned source
tree. The first Ada slices resolve simple local calls, package-qualified
package-body calls such as `Helpers.Helper;`, parenthesized calls whose
argument count matches the discovered callee, grouped formal parameter lists
such as `procedure Helper (Left, Right : in String)`, defaulted formals such as
`procedure Helper (Required : in String; Optional : in String := "fallback")`,
multi-line subprogram body headers where the profile and `is` are split across
lines, and parameterless procedure statements such as `Helper;`, alongside the
C/C++ call graph. When a previously
fuzzed target reaches another discovered target that was not present in the
prior auto run, either directly or through a call chain, `introspect` reports a
`static_reachability_gap` coverage blocker and recommends adding or rerunning a
harness for the blocked callee. Static reachability blockers include depth
evidence and a `call_chain` such as
`parse_packet -> parse_header -> parse_magic` when the path crosses multiple
targets.
When a discovered public target was absent from the prior run and is not
already explained by a fuzzed static caller, the top-level
`coverage_blockers` list includes `unreached_public_target` with a direct
"add or run a harness" recommendation for the per-tree gap. When a fuzzed
target has a project-local call that the static graph cannot resolve, including
a missing Ada statement call such as `Missing_Helper;` or an Ada arity mismatch
such as `Helper (Input);` when only `Helper;` exists, it reports an
`unresolved_static_call` blocker and recommends adding source roots, headers, or
wrappers so reachable code is visible. JSON output includes the per-target
`static_reachability` object with direct callees, uncovered direct callees,
reachable callees, uncovered reachable callees, and unresolved calls.
The top-level `coverage_blockers` array is priority ordered: direct static
callee gaps rank ahead of deeper static paths, unresolved static calls, dynamic
comparison gates, and orphan not-run public targets.

If a prior built-in fuzz run wrote `<work-dir>/fuzz_runs/<harness>-latest.json`
with CmpLog evidence, `introspect` also reports per-target `dynamic_coverage`.
When CmpLog observed comparison operands but no seed splice candidates existed,
the top-level `coverage_blockers` list includes a `comparison_gate` blocker
with suggested operand tokens to add to seeds or dictionaries.

```sh
bhf introspect path/to/src --work-dir bhf_work
bhf introspect path/to/src --work-dir bhf_work --format json --top 50
```

Use it after `auto` to decide where coverage is missing, or before the first
run to see the highest-priority discovered targets.

## Policy Profiles

`--profile strict-permissive` is the default and rejects probes or dependency
license expressions outside the project allow-list. Use
`--profile external-tools` only when an environment intentionally permits
external tool probes such as GNAT compiler-action experiments (FSF GNAT,
GPRbuild, AFL++, and the rizin/Ghidra/angr binary adapters as subprocesses).

`--profile research-lab` is the broadest profile: it permits every external-tool
probe and any subprocess, including GPL research tooling (Libadalang, GnatFuzz,
GNATcoverage, PolyORB) on top of the `external-tools` set. Use it only in a lab
where running arbitrary external analysis tools is acceptable; it never relaxes
the link-license allow-list (linked code still must be Apache-2.0/MIT/BSD).

## External Project Profiles

`bhf project` defines, validates, and runs an external project/target-profile
manifest (`bhf.project.v1`, TOML) kept entirely **outside** the bhf source tree.
One manifest composes a private harness (source or prebuilt binary) with its
corpora, layered dictionaries, grammar, and launch settings under one or more
stable target ids, so a private campaign is reproducible without vendoring it
into bhf. A `builtin` or `afl++` target's `binary` must be a bhf harness binary,
built from a harness directory bhf generated (for C/C++, its `make main` or
`make afl`), because `bhf fuzz` drives it through bhf's harness protocol and
coverage map. Any other executable belongs on `engine = "binary"`. `run`
reuses the existing engines — `builtin`/`afl++` go through the
`bhf fuzz` lane, `binary` through the `bhf binary fuzz` lane — and adds no new
execution path.

```sh
# Type-check every target: resolve + hash each asset, catch missing assets,
# duplicate ids, unsupported schema/bhf version, invalid relative paths, and
# unsafe secret interpolation — without running a campaign or the build command.
bhf project validate --manifest path/to/bhf-project.toml

# List the declared targets with their engine, input mode, and asset summary.
bhf project list --manifest path/to/bhf-project.toml

# Materialize an isolated work dir, resolve + hash assets, write provenance, and
# run one target. The build command runs by default (explicit load = trusted);
# --skip-build reuses a prebuilt binary.
bhf project run --manifest path/to/bhf-project.toml --target alpha
```

Every path in the manifest is resolved relative to the manifest's own directory.
By default a path may not escape that directory (`..`) or be absolute; pass
`--allow-external-paths` to opt in. `--json` emits a machine-readable
validation/provenance report on any of the three subcommands.

**Input mode.** A `builtin` target's binary is staged into
`<work>/build/<id>/main` with a `harness-protocol.json` beside it declaring the
target's input mode (`framed`). `bhf fuzz` (and later `bhf replay` and
`bhf minimize`) use it instead of re-detecting the protocol from the binary, so
a prebuilt bhf harness gets the framed protocol and its coverage map.

**Trust boundary.** The manifest is only ever loaded through an explicit
`--manifest` path — there is no auto-discovery. `validate` and `list` never
execute a target's `build-command`; only `run` does, because naming the manifest
is the operator's act of trust. `--skip-build` reuses a prebuilt binary and runs
nothing.

**Provenance.** `run` writes `results/project.json` (the project id, version,
schema, manifest SHA-256, resolved+redacted launch, and every asset's SHA-256)
and stamps a `project-provenance.json` sidecar onto each finding and the native
run-summary directory, so findings, replay, and minimization retain
project/target identity for importers (SARIF / vulnerability-management tools).
Secret env values are resolved from `${secret:NAME}` → `BHF_SECRET_<NAME>` and
`${env:NAME}` → the process environment; only the **handle** is ever recorded —
the resolved value never appears in provenance.

**Example manifest.**

```toml
schema = "bhf.project.v1"

[project]
id = "my-project"
version = "1.0.0"
requires-bhf = ">=0.2.0"

[[target]]
id = "parser"
engine = "builtin"                       # builtin | afl++ | binary
binary = "prebuilt/harness"              # resolved relative to this manifest
build-command = ["make", "harness"]      # trusted; run only by `bhf project run`
seeds = ["corpus/parser"]                # files and/or directories
dictionaries = ["dict/base.dict", "dict/parser.dict"]  # layered, merged in order
grammar = "grammar/parser.json"

[target.env]
PROFILE = "release"
TOKEN = "${secret:API_TOKEN}"            # resolved from BHF_SECRET_API_TOKEN, redacted
```

**Composition fields.** A target composes the engines' launch features:

- `runner` / `runner-args` / `target-args` (#47) — launch the target under a
  runner/emulator (e.g. `wine`, `qemu-x86_64`) with fixed argv. A literal `@@`
  in `target-args` marks the input-file position (file mode). **Binary engine
  only** (a native harness uses BHF's framed fork-server protocol, which has no
  per-launch argv); declaring any of them on a native target is rejected.
  `arguments` is an accepted alias for `target-args` (setting both is rejected),
  and `runner-args` requires `runner`. A target that names a `runner` runs on the
  binary **builtin** engine (afl-qemu provides its own `-Q` runner).
- `runtime-oracles` (#59) — `"auto"`, `"on"`, or `"off"` (default). Loads the
  runtrace sink oracles so a clean-exit semantic violation becomes a finding.
  Applies to **both** lanes.
- `[target.postcondition]` (#55) — `setup-command` / `oracle-command` /
  `reset-command` user-defined postcondition hooks run around each testcase. The
  `oracle-command` is **required** (a postcondition with no oracle asserts
  nothing). **Binary engine only**, and pins the binary builtin engine.

```toml
[[target]]
id = "channel-parser"
engine = "binary"
binary = "harnesses/parser"
input-mode = "file"
runner = "wine"                          # #47: launch under an emulator/loader
runner-args = ["--mode", "fuzz"]
target-args = ["@@"]                     # @@ = fuzz input-file position
runtime-oracles = "auto"                 # #59: clean-exit sink oracles

[target.postcondition]                   # #55: user security postcondition
setup-command = "./prepare-case"
oracle-command = "./check-postcondition" # required; exit 0=clean / 1=finding
reset-command = "./reset-case"
```

Any unknown field (a typo) is still rejected at parse time by
`deny-unknown-fields`, keeping the on-disk format strict.

## Out-of-Process Extensions

`bhf extension` drives an explicitly-trusted, **out-of-process** extension that
speaks the versioned `bhf.extension.v1` protocol (length-framed JSON over
stdin/stdout). An extension lets a *private* semantic oracle judge whether a
clean-exiting input violates a contract a crash-only fuzzer cannot see — without
vendoring that oracle into bhf and in any language (see
[`docs/extension-protocol.md`](../extension-protocol.md) and the Python
reference extension under `crates/extension_host/tests/fixtures/`).

```sh
# Spawn the extension, negotiate the protocol + capabilities, and print the
# negotiated protocol version, required/negotiated capabilities, and the
# executable/config SHA-256 — without driving any case.
bhf extension validate --manifest path/to/extension.toml

# Drive oracle.evaluate over one input: a clean-exit semantic violation becomes a
# replayable finding under <work>/results/findings/; a crash/timeout/oversized/
# malformed/unsupported reply is a bounded infrastructure result, never a finding.
bhf extension evaluate --manifest path/to/extension.toml --input case.bin --work bhf_work

# Drive a full multi-message session: lifecycle.reset a fresh root, pull each
# scenario.next message, optionally extension-mutate (--mutate SEED) and
# codec.repair it before it reaches the target, bind each response into a later
# message (scenario.observe-response), then oracle.evaluate the clean-exit outcome.
bhf extension session --manifest path/to/extension.toml --input seed.bin --work bhf_work \
  --mutate 42 --repair true

# Drive the just-retained corpus of a fuzz campaign through the extension oracle
# after the run (not in the hot mutation loop); when the extension provides
# codec.repair, a recognized frame is repaired before the oracle sees it (a raw
# corpus entry the extension rejects is evaluated verbatim). An extension fault
# never aborts the campaign nor becomes a target finding.
bhf fuzz bhf_work --harness H-0001 --extension path/to/extension.toml
```

`bhf extension evaluate` / `session` exit `0` for a benign input, `1` when a
semantic finding is emitted, `2` for a manifest/usage error, and `4` for a bounded
extension-side infrastructure failure (so a fault is never confused with a clean
run or a finding). `--json` emits a machine-readable report.

**Capabilities.** The host drives the full `bhf.extension.v1` surface —
`oracle.evaluate`, `codec.decode`/`encode`/`repair`, `mutator.mutate`,
`scenario.next`/`observe-response`, and `lifecycle.setup`/`reset`/`teardown`.
Negotiation advertises them all as optional on top of the manifest's
`required-capabilities`, so an extension that implements only a subset still
works. See [`docs/extension-protocol.md`](../extension-protocol.md) for the wire
shapes.

**Trust boundary.** The manifest is only ever loaded through an explicit
`--manifest` path — there is no auto-discovery, and naming the manifest is the
operator's act of trust. The child runs with a cleared, explicitly allow-listed
environment (only the **names** of passed/dropped variables are recorded), and on
unix with `setrlimit(RLIMIT_AS/RLIMIT_CPU)` caps.

**Bounded by construction.** Every extension crash, per-call timeout, oversized
or malformed response, mismatched case identity, or `unsupported` reply is mapped
to a bounded **infrastructure** result that can never masquerade as a target
vulnerability; a crash/timeout triggers the restart policy, and an exhausted
restart budget is recorded as a terminal loss event.

**Provenance.** A finding carries an `extension` block (the extension
executable/config SHA-256, the negotiated protocol version, and the negotiated
capabilities), and `evaluate` writes a run-level `extension.json` so a consumer
can audit which trusted extension produced a result. `bhf fuzz --extension`
attaches an additive `extension` block to the run summary (the summary
`schema_version` is unchanged).

**Example manifest.**

```toml
schema = "bhf.extension-manifest.v1"
id = "path-oracle"
executable = "./path-oracle"             # resolved relative to this manifest
args = ["--serve"]
required-capabilities = ["oracle.evaluate"]
env-passthrough = ["ACME_MODE"]          # only these host vars reach the child

[limits]
call-timeout-ms = 5000
max-frame-bytes = 1048576
max-restarts = 1
address-space-bytes = 1073741824         # RLIMIT_AS (unix)
cpu-seconds = 30                          # RLIMIT_CPU (unix)
```

By default the `executable` may not be absolute or escape the manifest directory
(`..`); set `allow-external-paths = true` to opt in. A `requires-bhf = ">=X.Y[.Z]"`
bound fails closed on an older bhf.

The full capability set is implemented: `oracle.evaluate`, `codec.decode` /
`codec.encode` / `codec.repair`, `mutator.mutate`, `scenario.next` /
`scenario.observe-response`, and `lifecycle.setup` / `lifecycle.reset` /
`lifecycle.teardown`. A `bhf.project.v1` profile can declare the same extension
inline via an `[[extension]]` section, which `bhf project run` materializes as a
trusted `bhf.extension-manifest.v1` and loads for its native-engine campaigns.
CBOR wire encoding remains an optional, negotiated-but-unused format (the host
speaks JSON only).

```toml
# In a bhf.project.v1 manifest: declare a trusted extension the run loads.
[[extension]]
id = "path-oracle"
executable = "./path-oracle"             # resolved relative to the manifest
args = ["--serve"]
required-capabilities = ["oracle.evaluate"]
optional-capabilities = ["codec.repair", "scenario.next"]
env-passthrough = ["ACME_MODE"]

[extension.limits]
call-timeout-ms = 5000
max-restarts = 1
```

## Coverage-Guided Relational Policy Fuzzing

`bhf relational` runs **one** generated testcase across several named
launch/session **profiles** (differing in runner, args, environment, declared
target allowlist and secret references) and evaluates declarative relational
**predicates** over each profile's observed behaviour. It catches both unexpected
*divergence* and unexpected *equivalence* against an explicit policy — a class of
authorization bug a crash-only or single-harness output-diff oracle cannot see,
because the offending runs can exit `0` with byte-identical stdout. The signal is
the *effect* (what each profile launched, reached, or decided), not the output.

```sh
# Coverage-guided campaign: mutate a shared testcase, run it under every profile,
# retain inputs that reach new code in any profile or a new cross-profile outcome,
# and emit a finding when a policy relation breaks. Findings land under
# <out>/results/findings/F-REL-*.
bhf relational run --config policy.toml --seeds corpus/ --out findings_relational

# Re-run every profile the finding requires and re-confirm the violated relation
# (exit 0 when it still reproduces, non-zero when it no longer does). Resolved
# secrets stay redacted; a replay.json bundle is written beside the finding.
bhf relational replay --finding findings_relational/results/findings/F-REL-0000

# Shrink the finding's testcase while the relation still holds and reduce the
# required profile set to the minimum that still proves it.
bhf relational minimize --finding findings_relational/results/findings/F-REL-0000
```

**Policy (`bhf.relational.v1`).** A TOML file declares the profiles and the
relational predicates:

```toml
schema = "bhf.relational.v1"

[status_map]                              # exit-code -> authorization status
allowed = [0]
denied = [77]
auth_failure = [66]                       # a failed session/auth bootstrap

[[profiles]]
name = "administrator"
runner = "/bin/sh"
args = ["launcher.sh", "administrator"]
allowlist = ["administrator-helper", "viewer-helper"]
collector = "runtrace"                    # auto | runtrace | none
[profiles.env]
TOKEN = "lab:admin-token"                 # a secret reference, never a value

[[profiles]]
name = "viewer"
runner = "/bin/sh"
args = ["launcher.sh", "viewer"]
allowlist = ["viewer-helper"]
collector = "runtrace"

# viewer must stay denied whenever administrator is allowed (BHF-308)
[[predicates]]
rule = "viewer must stay denied when administrator is allowed"
require = { kind = "status_relation", profile = "viewer", status = "denied" }
when = { kind = "status_is", profile = "administrator", status = "allowed" }

# viewer may only launch targets in its declared allowlist (BHF-309)
[[predicates]]
rule = "viewer spawned targets must be a subset of its allowlist"
require = { kind = "subset", set = "viewer.spawned", of = "viewer.allowlist" }
```

Predicate relations: `status_relation` (a profile's derived status must match),
`subset` (an observed target set must be within a declared allowlist),
`equal` / `differ` (selector values across profiles must be equal / must differ),
and `external` (a trusted out-of-process comparator decides the relation over the
whole cross-profile observation bundle). Selectors read `profile.field` where
field is one of `spawned`, `allowlist`, `status`, `response`, `edges`.

**External comparator.** An `external` predicate names a comparator by the path of
a `bhf.extension-manifest.v1` manifest — the same explicit-load trust boundary as
`bhf extension` and `bhf project` (there is no auto-discovery):

```toml
[[predicates]]
rule = "a trusted comparator decides the cross-profile relation"
require = { kind = "external", comparator = "comparators/authz.toml" }
```

The driver spawns and negotiates the comparator up front (a manifest that does not
load fails the run), then for each testcase serializes the **secret-redacted**
cross-profile observation bundle and drives `oracle.evaluate` over the `bhf.extension.v1`
protocol. The comparator's verdict maps to a real outcome: `ok → compliant`,
`finding → violation` (a `BHF-312` finding that carries the comparator's own
signature and classification plus the comparator executable/config SHA-256 and
protocol version as provenance), and `unsupported` / `reject` / any bounded
infrastructure fault → `policy_unknown` — never a fabricated verdict, and always
distinct from a setup/auth/missing-observation outcome. Resolved secrets are
scrubbed before the bundle is sent and never appear in a finding or replay bundle.

**What a finding records.** Each violation becomes a finding
(`BHF-308` unexpected authorization, `BHF-309` allowlist escape,
`BHF-310` unexpected equivalence, `BHF-311` unexpected divergence,
`BHF-312` external-comparator violation) carrying the
violated relation, the involved profiles, each profile's normalized observation,
the testcase, the evidence event(s), and the policy + per-profile hashes. The
persisted shape mirrors every other finding kind, so SARIF /
vulnerability-management importers read relational findings with the same reader.

**Per-profile isolation.** Every profile runs with a **distinct** coverage-shm
file (`BHF_COV_SHM`), runtime-trace log (`BHF_RUNTRACE_LOG`) and scratch dir, so
one profile's coverage or effect events can never contaminate another's. Per-case
novelty is bucketed per profile, so an input that is novel in only one profile is
still retained. Effect events come from the runtime-trace collector; the
platform-neutral `bhf.collector-event.v1` source feeds the same seam where it is
active. A target that emits its own trace stream (or must not be instrumented)
sets `BHF_RUNTRACE_SHIM=off` to skip the LD_PRELOAD shim.

**Secrets.** A profile env value with the `lab:` prefix is a *reference*; the
driver resolves it locally from `BHF_SECRET_<NAME>` (name upper-cased,
non-alphanumerics mapped to `_`) only in-process, and the resolved value is
redacted out of every finding and replay bundle before anything is persisted —
only the stable reference id survives (it lives in the policy, not in a resolved
value).

## Release Commands

`bhf-daemon` is distributed beside `bhf` in release archives. Use the
CLI for batch workflows, default daemon mode for editor JSON-RPC integrations,
and `bhf-daemon --mcp` for the five read-only agent tools.
