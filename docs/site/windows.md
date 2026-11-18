<!-- SPDX-License-Identifier: Apache-2.0 -->

# Running bhf on Windows

bhf builds and runs natively on Windows in addition to Linux. This page is
the full install + run guide for native Windows. (To fuzz Windows targets *from
Linux* without a Windows host, see the wine cross-fuzzing path in
[cross-compilation.md](./cross-compilation.md).)

## Supported Windows versions

The published release supports 64-bit Windows 11 Enterprise 25H2, Windows 11
Enterprise LTSC 2024 (the 24H2 codebase), Windows Server 2019, Windows Server
2022, and Windows Server 2025. The compatibility floor is Windows Server 2019;
Windows Server 2022 and Windows Server 2025 are continuously exercised by
native CI jobs, while both Windows 11 client baselines and Windows Server 2019
are covered by Proxmox VM validation. Windows 10 and Windows Server 2016 are not
in the supported matrix.

Microsoft lists Windows 11 26H1 only for select new-device silicon and says it
is not a feature update for existing 24H2/25H2 devices. It also does not provide
a general-purpose x64 Enterprise evaluation ISO for that hardware-specific
release. BHF therefore treats 25H2 as the latest broadly deployable Windows
11 Enterprise release and states the tested versions explicitly; see
[Microsoft's Windows 11 release information](https://learn.microsoft.com/windows/release-health/windows11-release-information).

The Windows package contains native MSVC CLI and daemon executables. The
PowerShell installer installs those executables, but it does not install target
language toolchains. For native C/C++ scan/build/fuzz coverage, install all three
items in the prerequisite table below: LLVM, VS Build Tools/Windows SDK, and GNU
make.

## Prerequisites

Install these (e.g. with [Chocolatey](https://chocolatey.org), `winget`, or the
direct installers linked below):

| Tool | Why | Install |
|------|-----|---------|
| **VS Build Tools (MSVC + Windows SDK)** | The CRT, linker and SDK every harness links against; `cl.exe` for the MSVC lane; MSBuild for solutions. | [`vs_buildtools.exe`](https://aka.ms/vs/17/release/vs_buildtools.exe) `--quiet --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended` |
| **clang** | The default harness compiler (edge coverage + cmplog + ASan). Either Visual Studio's "C++ Clang tools for Windows" component (`Microsoft.VisualStudio.Component.VC.Llvm.Clang`) or a standalone LLVM. | `--add Microsoft.VisualStudio.Component.VC.Llvm.Clang` on the Build Tools installer, or `choco install llvm` / the [LLVM release](https://github.com/llvm/llvm-project/releases) (`LLVM-*-win64.exe`). |
| **GNU make** | bhf builds each C/C++ harness through a generated Makefile (same as Linux). | [w64devkit](https://github.com/skeeto/w64devkit/releases) unpacked to `C:\w64devkit`, or `choco install make`. |
| **git** | Cloning target projects (optional). | `choco install git` or [Git for Windows](https://gitforwindows.org). |
| **Rust** (optional) | Only to build bhf from source; you can also use a prebuilt `bhf.exe`. | [rustup](https://rustup.rs). |

**No Developer shell is needed.** When `INCLUDE` and `LIB` are not already set,
bhf finds the newest Visual Studio or Build Tools instance with the C++
toolset (`vswhere -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64`),
runs its `VsDevCmd.bat -arch=x64` once, and applies the environment it sets
(`PATH`, `INCLUDE`, `LIB`, `LIBPATH`, `VCToolsInstallDir`, `WindowsSdkDir`, ...)
to its own process before any build starts; every `make`, harness and
reproducer bhf starts inherits it. Only what VsDevCmd changed (the variables
it set and the `PATH` directories it added) is cached, per instance, version
and architecture, in `%LOCALAPPDATA%\bhf\vs-env\`, and later runs apply that
change onto their own environment, so a variable or `PATH` entry you changed
since is kept, and nothing else from the first run's environment is written to
disk. A Visual Studio update causes a new capture. bhf then locates the tools it needs
when they are not on `PATH`: clang (a clang on `PATH` wins, then
`%ProgramFiles%\LLVM\bin`, then Visual Studio's bundled
`VC\Tools\Llvm\x64\bin`) and make (`C:\w64devkit\bin`,
`%USERPROFILE%\w64devkit\bin`, Chocolatey's `bin`, GnuWin32, MSYS2). Every
command prints one line saying what it used:

```text
bhf: build environment: Visual Studio Build Tools 2022 17.14.37906.3 (x64, cached); clang C:\Program Files\LLVM\bin\clang.exe; cl C:\...\cl.exe; make C:\w64devkit\bin\make.exe; msbuild C:\...\MSBuild.exe
```

`bhf auto` records the same in `run.json` (`build_environment`) and in its
`--dry-run` plan. Inside a Developer shell (`INCLUDE`/`LIB` set) the shell's
environment is used as it is. `--no-vs-env` (or `BHF_NO_VS_ENV=1`) turns
discovery off; `--vs-arch x86|x64|arm64` picks another target architecture.
For one that is not this machine's, clang is given `--target=` for it
(`i686-pc-windows-msvc` for x86) and must carry that architecture's
AddressSanitizer runtime: the standalone LLVM and Visual Studio's x64 clang
have only x64's, so for `--vs-arch x86` bhf puts Visual Studio's x86 clang
(`VC\Tools\Llvm\bin`, from the "C++ Clang tools" component) ahead of a
`PATH` clang without it, and the build-environment line says so. Give
`capsule` and `verify-poc` of such a finding the same `--vs-arch`: a capsule
rebuilds the harness, which needs that architecture's toolset. The
discovered directories reach builds only through `PATH`/`INCLUDE`/`LIB`,
never as recipe text, so `Program Files (x86)` needs no quoting.

### One-shot setup on a stock Windows 11 VM

Windows 11 ships [`winget`](https://learn.microsoft.com/windows/package-manager/),
so from a fresh VM (an elevated PowerShell):

```powershell
winget install --id Microsoft.VisualStudio.2022.BuildTools -e `
  --override "--quiet --add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.VC.Llvm.Clang --includeRecommended"
winget install --id Git.Git -e                          # optional: clone targets
winget install --id Rustlang.Rustup -e                  # build bhf from source
# GNU make: w64devkit is not in winget — download the release zip and unpack it
# to C:\w64devkit (bhf finds C:\w64devkit\bin\make.exe itself):
#   https://github.com/skeeto/w64devkit/releases
```

Optional per-lane toolchains are needed only for a lane you actually run. See
the limitations below before installing them: several managed/interpreted lanes
currently emit POSIX launchers and should be run under WSL/Linux rather than
native Windows.

## Getting `bhf.exe`

Download the `bhf-x86_64-pc-windows-msvc.zip` archive from the GitHub
release and verify its `.sha256` sidecar, or use the release's PowerShell
installer:

- For normal terminal use, install only `bhf`. The installer downloads the
  CLI ZIP automatically, so you do not need both files.
- Add `bhf-daemon-installer.ps1` (or the daemon ZIP and sidecar) only for
  IDE, JSON-RPC, or read-only MCP use. The CLI does not require the daemon.
- Ignore `bhf_runtrace_shim-*` and `bhf_cc_intercept-*`; those are
  Linux-only `LD_PRELOAD` components and have no Windows archives.
- `source.tar.gz`, `dist-manifest.json`, and checksum files are for source audit,
  automation, or manual verification—not additional programs to install.

```powershell
$Version = "0.3.0"
irm "https://github.com/Tarmo-Technologies/bhf/releases/download/$Version/bhf-installer.ps1" | iex
bhf.exe --version
```

The PowerShell installer is also safe to run through Windows OpenSSH:
it suppresses `Expand-Archive`'s console progress access, which otherwise fails
in a non-interactive Server 2019 session. The installer adds
`%USERPROFILE%\.cargo\bin` to the user `PATH`; start a new shell if the command
is not visible immediately.

The release binary does not require Rust. Alternatively, build it natively:

```powershell
rustup target add x86_64-pc-windows-msvc   # or -gnu
cargo build --release -p bhf
# -> target\release\bhf.exe
```

…or cross-build it on Linux and copy it over (see cross-compilation.md):

```sh
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu -p bhf
```

## Running

From any PowerShell (no Developer shell, no PATH edits for the standard
install locations), point `auto` at a source tree:

```powershell
bhf.exe auto C:\path\to\source --work-dir C:\Temp\bhf-work `
  --jobs 1 --max-targets 1 --per-target-time 10
```

`auto` discovers fuzzable functions, generates typed harnesses, builds them with
clang (edge coverage + cmplog + ASan), fuzzes with the built-in engine, and
writes JSON/Markdown findings — the same core fuzzing pipeline as on Linux. A harness fault is
detected through ASan or the driver's unhandled-exception filter (Windows has no
POSIX signals).

### Verify the install

Check the installed binary, then run the command above on your source tree:

```powershell
bhf.exe --version
bhf.exe --help
bhf.exe auto --help
```

The run should report at least one built+fuzzed target and a positive execution
count. Read `C:\Temp\bhf-work\results\INDEX.md` for findings and
`C:\Temp\bhf-work\auto\summary.txt` for skipped or blocked targets.

### Reproducing a finding

A sanitized harness needs the AddressSanitizer runtime DLL
(`clang_rt.asan_dynamic-x86_64.dll`), which lives outside `PATH` (in clang's
resource directory, or beside `cl.exe` for the MSVC lane). After each harness
build bhf puts that DLL — the one from the toolchain that built the harness —
next to `main.exe`, where Windows looks first, and lists its directories in
`harnesses\<id>\bhf-runtime-path.txt`. So `main.exe testcase.bin`,
`bhf replay --finding ...` and the finding's reproducer work from any shell:

```powershell
python C:\Temp\bhf-work\results\findings\<id>\replay.py
```

`replay.py` also puts the recorded directories on `PATH` (falling back to
`clang -print-resource-dir`). `results\INDEX.md` names `python` rather than
`python3` on Windows, and `bhf explain` prints its commands for PowerShell
(each path a single-quoted literal) and the direct run as PowerShell lines:
`$env:Path = '<runtime dirs>;' + $env:Path`, then the sanitizer options and
`& '...\harnesses\<id>\main.exe' '...\results\findings\<id>\testcase.bin'`,
on the recorded testcase. A harness that reads stdin (Ada's) runs through
`cmd --% /c ""<harness>" < "<testcase>""`, and the extensionless binary of a
work dir built before binaries had the suffix through `Start-Process`. Every
harness binary is named with `.exe` (`main.exe`, `main_cov.exe`,
`main_afl.exe`), so cmd and PowerShell run it by its path; `make main`,
`make cov` and `make main_afl` in a harness dir still build them.

A C or C++ finding packages into a capsule that rebuilds natively, with no
POSIX shell: `bhf capsule` writes `build.ps1` beside `build.sh`, and on
Windows both `bhf capsule` and `bhf verify-poc` rebuild with it. It compiles
with the compiler family the harness was built with (cl for `--cc cl`,
clang-cl for `--cc clang-cl`, clang otherwise); cl gets `/fsanitize=address`
and the same SanitizerCoverage flags as the cl lane, spelled by the bhf-cl
front end's translation, and bhf's weak repair stubs compile from MSVC copies.
`$env:CC`/`$env:CXX` names another compiler. Outside a Developer shell the
script takes the environment cl and clang-cl read from Visual Studio itself,
and it copies the
sanitizer runtime DLL next to `poc.exe`, so a capsule rebuilds and replays
from a plain PowerShell on a machine without bhf:

```powershell
bhf.exe capsule --work-dir C:\Temp\bhf-work --finding-id <id>
bhf.exe verify-poc C:\Temp\bhf-work\capsules\capsule_<id>
# or by hand, in a copy of the capsule:
powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1
.\poc.exe input/testcase.bin
```

`bhf explain` quotes the work dir and capsule paths it prints, so a path
with spaces (`C:\Users\a b\work`) pastes as one argument.

## WinAFL engine (`--engine winafl`)

[WinAFL](https://github.com/googleprojectzero/winafl) is a third engine for
C/C++ targets on native Windows, beside the builtin engine and AFL++.
`--engine winafl` is refused on any other host before anything is built.

```powershell
bhf.exe auto C:\path\to\source --engine winafl `
  --winafl-path C:\tools\winafl-src\build64\bin\Release `
  --dynamorio-path C:\tools\DynamoRIO-Windows-11.91.20763 `
  --per-target-time 120
# or with the builtin engine sharing each target's budget:
bhf.exe auto C:\path\to\source --engine builtin,winafl --per-target-time 240
```

### Installing WinAFL and DynamoRIO

WinAFL no longer ships prebuilt binaries, so build it with CMake against a
DynamoRIO package. The versions bhf is validated with (Windows Server 2022, VS
2022 Build Tools 17.14):

| Tool | Version | Where |
|------|---------|-------|
| DynamoRIO | 11.91.20763 (weekly build `cronbuild-11.91.20763`, 2026-11-07), `DynamoRIO-Windows-11.91.20763.zip`, SHA-256 `EA3DAD4AE6E39228FE87B5D4D7BC3A53FAFDB6161EE5BA6A2E98FB64F8A7E0D4` | [DynamoRIO releases](https://github.com/DynamoRIO/dynamorio/releases/tag/cronbuild-11.91.20763) |
| WinAFL | master `fd85f38548` (WinAFL 1.17, AFL 2.43b), built x64 with `-DINTELPT=1 -DUSE_COLOR=1` and x86 (`-A Win32`) with `-DUSE_COLOR=1` | [googleprojectzero/winafl](https://github.com/googleprojectzero/winafl) |

WinAFL master calls `drmgr_register_exit_event`, which DynamoRIO's last
release, 11.3.0, does not have: linking `winafl.dll` against 11.3.0 fails with
LNK2019. Use a DynamoRIO weekly build of 11.90 or later with master (as above),
or build WinAFL at `c362747159`, the commit before that change, against
DynamoRIO 11.3.0.

From a VS 2022 x64 developer prompt:

```powershell
# DynamoRIO: unpack the zip, e.g. to C:\tools\DynamoRIO-Windows-11.91.20763
git clone https://github.com/googleprojectzero/winafl C:\tools\winafl-src
cd C:\tools\winafl-src
git submodule update --init --recursive    # Intel PT support (third_party)
mkdir build64; cd build64
cmake -G "Visual Studio 17 2022" -A x64 .. `
  -DDynamoRIO_DIR=C:\tools\DynamoRIO-Windows-11.91.20763\cmake -DINTELPT=1 -DUSE_COLOR=1
cmake --build . --config Release
# -> build64\bin\Release\afl-fuzz.exe, winafl.dll, winaflpt-debug.exe
```

`scripts/ci/build-winafl.ps1 -Root C:\tools\bhf-winafl` does all of this at
the pinned versions, x64 (`build64`) and x86 (`build32`, without Intel PT),
checking the DynamoRIO zip's SHA-256, and leaves
`<Root>\DynamoRIO-Windows-11.91.20763` and the `<Root>\winafl` checkout for
`BHF_DYNAMORIO_PATH` and `BHF_WINAFL_PATH`; run again, it skips what is built.

bhf finds them from `--winafl-path` (the directory holding `afl-fuzz.exe` and
`winafl.dll`, or the checkout holding `build64\bin\Release`), then
`BHF_WINAFL_PATH`, then `afl-fuzz.exe` on `PATH`; and DynamoRIO from
`--dynamorio-path` (its install root, or its `bin64`), then
`BHF_DYNAMORIO_PATH`, then DynamoRIO's own `DYNAMORIO_HOME`, then `drrun.exe`
on `PATH`. In `bhf auto` a `--config` file can hold them as `winafl-path` and
`dynamorio-path`; like the `[toolchain]` table they name programs bhf runs, so
an auto-loaded `.bhf.toml` cannot set them. A missing tool stops the run before
the sweep with an error naming it and how to install it (`WinAFL not found:
...`, `WinAFL at ... has afl-fuzz.exe but no winafl.dll ...`, `DynamoRIO not
found: ...`). An x86 harness (`--vs-arch x86`) uses DynamoRIO's `bin32` and
needs a 32-bit WinAFL build: bhf reads the architecture of each `winafl.dll` it
finds (in a checkout, `build32\bin\Release` for x86) and refuses one that does
not match the harness. An ARM64 target (`--vs-arch arm64`, or the default on
an ARM64 machine) is refused, since WinAFL fuzzes x86 and x64 harnesses. In
`bhf auto` these checks run before the sweep, and it exits `2` when one fails,
as for an unusable toolchain. `bhf fuzz` exits `1` for a missing or unusable
WinAFL or DynamoRIO, a refused `--winafl-coverage-module` or an ARM64 harness,
as for a missing `afl-fuzz`; it exits `3` on a host other than native Windows,
for `--winafl-page-heap` in a shell that is not elevated, and for
`--target-transport` or `--protocol-profile`.

### How a target is fuzzed

- **The WinAFL build.** `bhf auto` runs `make winafl`, which builds
  `main_winafl.exe` beside `main.exe` from the same translation units, without
  AddressSanitizer or SanitizerCoverage (`WINAFL_CFLAGS`, default `-O1 -g`;
  `bhf build --c-engine winafl` builds it for `bhf fuzz`). Like `main.exe` it
  is named with `$(EXEEXT)`; its export also leaves `main_winafl.lib` and
  `main_winafl.exp`, which `make clean` removes with `main_winafl.pdb` and the
  run copies `--winafl-page-heap` left. An extensionless
  `main_winafl` an earlier build left is still found. WinAFL measures
  coverage itself, with DynamoRIO.
- **Persistent entry.** bhf's driver has an exported, never-inlined
  `int bhf_winafl_fuzz(const char *path)` that opens, reads and closes the input
  file and runs it, as WinAFL's persistent mode requires; `main` calls it for
  its argument. WinAFL runs it as `-target_method`:

  ```text
  afl-fuzz.exe -i <seeds> -o <out> -D <DynamoRIO>\bin64 -w <winafl.dll> -t 2000+ -I 30000 -m <MiB|none> -d [-x dictionary.txt] --
    -coverage_module main_winafl.exe [-coverage_module <dll>...] -target_module main_winafl.exe
    -target_method bhf_winafl_fuzz -nargs 1 -fuzz_iterations 5000 -covtype edge -- <dir>\main_winafl.exe @@
  ```

  `-t` is `--timeout` (default 2000 ms per iteration; `+` skips seeds that time
  out), `-I` gives the first iteration of each process its start-up time under
  DynamoRIO (ten times `-t`, at least 30 s; without it a slow start reads as a
  hang), `-m` is `--rss-limit-mb` plus 1024 MiB for DynamoRIO (`-m none` for
  `0`; WinAFL caps the committed memory of drrun and the target with a job
  object). For an x86 harness, whose 32-bit afl-fuzz computes that cap in 32
  bits, `-m` is passed only while it is below what the process can address
  (2 GiB, or 4 GiB when linked `/LARGEADDRESSAWARE`), and is `-m none`
  otherwise, which bhf notes. `-fuzz_iterations` is `--winafl-iterations`, and
  `--winafl-coverage-module` adds a DLL of the target the harness loads (a
  name with a space or a quote is refused, since WinAFL passes it on
  unquoted). `-d` skips AFL's deterministic stages, as AFL++ does by default;
  on a campaign of minutes they spend the budget on the first queue entries.
- **Seeds and dictionary.** The seeds are the ones the other engines get (mined,
  `--seed-file`/`--seed-dir`, the corpus earlier passes grew), written byte for
  byte; WinAFL skips an empty file and refuses one over 1 MiB, so an empty seed
  is left out and a larger one cut to 1 MiB. AFL 2.x takes one `-x`, so the
  harness's `dictionary.txt` and `learned_dictionary.txt` are merged into one
  file in WinAFL's syntax, each token once (tokens over 128 bytes, WinAFL's
  limit, are left out). WinAFL's queue is handed back to the harness's corpus
  (`corpus/<id>/queue/`) at the end.
- **Time budget.** WinAFL has no time limit and no graceful stop, so bhf stops
  it at the budget, killing afl-fuzz, drrun and the target together through a
  job object. When WinAFL stops early on its own (it aborts when it cannot stop
  a hung target), bhf starts it again on the queue it reached for the time left,
  up to 8 sessions. When the last session stops early, what it saved is still
  replayed and its queue still kept, with a warning (`stopped_early` in
  `run.json`); the run fails only when WinAFL saved nothing at all.
- **A run stopped before its replay.** On Ctrl-C, Ctrl-Break or a closed
  console bhf stops WinAFL and the target and ends the run without replaying
  what WinAFL saved, printing where those inputs are and how to run one by
  hand:

  ```text
  bhf: the WinAFL run of H-1 stopped (Ctrl-C, Ctrl-Break or a closed console) before it replayed what WinAFL saved: those inputs stay under C:\work\winafl_out\H-1, and the next `bhf fuzz --engine winafl` or `bhf auto --engine winafl` run of H-1 in this work dir replays them into findings (to run one by hand: C:\work\build\H-1\main.exe <file>)
  ```

  They stay in `<work>\winafl_out\<id>\out*\crashes` and `hangs` (a
  run killed outright leaves them there too). The next WinAFL run of that
  harness in the same work dir keeps such output under
  `winafl_out\<id>\earlier\<n>` (the last 8 such runs) and replays it with its
  own saved inputs, so it becomes findings like any other (`earlier_inputs` in
  `run.json`). Output a run did replay is cleared by the next run. Running the
  sanitized `main.exe` on one file prints its report, but records no finding.
- **Coverage and statistics.** `coverage.edges` is WinAFL's own: the map bytes
  `fuzz_bitmap` shows hit, or, before its first write (once a minute), the map
  density in `plot_data` (every 5 s) times the 64 KiB map. The executions come
  from `fuzzer_stats`, or are added up from `plot_data`'s rates when that is
  fresher. `run.json` keeps them under `winafl` with the tools, the two
  binaries, the sessions and how each saved input replayed.
- **Findings.** The crashes and hangs WinAFL saves, and the seeds its dry run
  found crashing, are replayed through the sanitized `main.exe`: first one
  crash of each exception name, then the other crashes, the crashing seeds and
  the hangs. Inputs with the same bytes are replayed once, and the replay ends
  after half the time budget (at least 30 s, at most 10 min). Half of that is
  kept for the hangs: while hangs wait, the crashes stop at it, and the ones
  left over are replayed after the hangs in the time that remains. Hangs stop
  being replayed after 8 of them time out again with no report in between
  (WinAFL keeps up to 500, and each that still times out costs a replay
  timeout); a hang that replays clean costs only its run and does not count,
  so the one real hang after many load-induced ones is still replayed. An
  input that cannot be read or replayed is a warning, and the rest are still
  replayed. `run.json` counts the inputs left
  out (`replay_duplicates`, `replay_skipped`, `replay_errors`); they stay
  under `<work>\winafl_out\<id>`. An input that
  produces a sanitizer or exception report becomes a finding through the same
  root-cause dedupe and `results/` flow as an AFL++ crash, so `bhf replay`,
  `bhf explain`, `bhf capsule` and `bhf verify-poc` work on it as on a builtin
  finding. Its `finding.json` has a `discovery` block (`engine: winafl`, the
  binary and its empty sanitizer list, `saved_as` `crash`/`hang`/
  `crashing-seed`, WinAFL's exception name), and in `bhf auto` its fidelity
  record says it was found by WinAFL in a build without sanitizers and
  confirmed by the sanitized replay. A hang that replays clean, or still times
  out, is counted (`replay_clean`, `replay_timed_out`), not reported.

### AddressSanitizer and DynamoRIO

An AddressSanitizer harness does not run under DynamoRIO, which is why WinAFL
gets its own build. Measured on the validation VM (clang 23 `-fsanitize=address`,
DynamoRIO 11.3.0 and 11.91.20763): the ASan binary hangs at start-up under
`drrun` even with no client, while the same source without ASan runs WinAFL's
persistent loop at 1,500 to 4,600 executions a second. And WinAFL's client
treats every first-chance access violation as a crash, while 64-bit Windows
ASan commits its shadow memory on demand from access violations.

Without ASan, WinAFL sees a memory error only when it faults. A heap overflow
that corrupts the heap is ended by Windows with a fail-fast
(`STATUS_HEAP_CORRUPTION`), which WinAFL's DynamoRIO client never sees, so WinAFL
saves the input as a hang, or the process takes the next inputs down with it;
bhf replays hangs through `main.exe` too, which reports the overflow. The WinAFL
build checks the process heap after every input (`HeapValidate`), so a corrupted
heap ends that input's iteration rather than a later one's.
`--winafl-page-heap` makes heap errors fault at once instead. Every allocation
then ends at a guard page and a freed one is decommitted, so an overflow or a
use after free is an access violation WinAFL saves as a crash. It needs memory
for a page or two per allocation.

PageHeap is set per image name, machine-wide, by an Image File Execution
Options key (the one `gflags /p /enable <image> /full` writes). So that no
other run, campaign or `--jobs` worker sees it, WinAFL fuzzes a copy of
`main_winafl.exe` under a name only this run uses,
`main_winafl-<pid>-<n>-<stamp>.exe` beside the build, and bhf sets the key for
that name only and prints it:

```text
bhf: full PageHeap: WinAFL fuzzes C:\work\build\H-1\main_winafl-4321-0-6935c1a2.exe (a copy of C:\work\build\H-1\main_winafl.exe) with PageHeap set under HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\main_winafl-4321-0-6935c1a2.exe until the run ends
```

The key holds a `BhfPageHeapOwner` value naming the bhf process (its id and
start time), and the copy has a marker file beside it,
`main_winafl-<pid>-<n>-<stamp>.exe.bhf-run`, naming the same process. When the
run ends, bhf deletes the `GlobalFlag`, `PageHeapFlags` and owner values it
wrote, then the key (which it created, if nothing else is in it), then the copy
and its marker. On Ctrl-C, Ctrl-Break or a closed console it does the same from
a console control handler: it removes the key, stops afl-fuzz, drrun and the
target through their job object, deletes the copy and its marker once the
target has exited (waiting up to 2 s), and starts no replay (the next run
replays what WinAFL saved; see "A run stopped before its replay" above). A run killed
outright (`taskkill /F`, a crash of bhf) cannot do any of that, so every WinAFL
run first removes the keys (from an elevated shell) of owners that are no
longer running, and the copies in that harness directory whose marker names
such an owner; `make clean` in the harness directory removes every marked copy
too. Until then the stale key names only that run's copy, which nothing else
runs. bhf deletes only what its owner value or marker proves a bhf run made: a
`main_winafl-*.exe` without a marker, or a key without the owner value, is left
alone, and so is one whose key bhf cannot read.
To remove one by hand, from an elevated PowerShell (bhf prints the line when it
cannot remove a key itself):

```powershell
reg delete 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\main_winafl-<...>.exe' /f
```

Writing the key needs an elevated shell: without one, `--winafl-page-heap` is
refused before anything is built (`bhf auto` exits `2`, `bhf fuzz` `3`). The
`page_heap` recorded in `run.json` and in each finding's `discovery` block is
the PageHeap the key had in effect: `true` for a run without the flag too when
someone set PageHeap for `main_winafl.exe` outside bhf, which bhf then notes.
A memory error that faults in neither way (an overflow into allocation padding,
an uninitialized read) is left to the builtin and AFL++ engines, which run
ASan.

### Intel PT

`--winafl-instrumentation intel-pt` runs WinAFL with `-P` (Intel Processor
Trace) instead of DynamoRIO. It needs a WinAFL built with `-DINTELPT=1` (bhf
checks for `winaflpt-debug.exe` beside `afl-fuzz.exe`), an Intel CPU with PT,
and no hypervisor in between unless it passes PT through; on the KVM validation
VM afl-fuzz stops with `Unable to start IPT Service (err=50)` and `No IPT`,
which bhf reports with a hint to use DynamoRIO. DynamoRIO is not needed in that
mode.

### Limits

- One WinAFL instance per target: `bhf fuzz --engine winafl` refuses
  `--workers` and a sanitizer matrix.
- No cmplog or value profile: WinAFL solves comparisons only through coverage
  and the dictionary. Pair it with the builtin engine (`--engine builtin,winafl`)
  for magic values.
- Only native targets: a cross-compiled harness runs the builtin engine.
- `--target-transport` and `--protocol-profile` run the builtin engine's own
  loops, so `bhf fuzz` refuses them with `--engine winafl` (or `afl++`).
- The end-to-end tests (`crates/cli/tests/winafl_engine.rs`: `bhf auto
  --engine winafl` on a planted heap overflow, with and without PageHeap and
  as an x86 harness (`--vs-arch x86`), nonzero WinAFL coverage, then `replay`,
  `explain`, `capsule` and `verify-poc`) need WinAFL and DynamoRIO, which the
  GitHub Windows runners do not have, so they are `#[ignore]`d; PR CI runs the
  test's refusal checks and an x86 smoke (`--vs-arch x86` with the builtin
  engine finds the overflow, and it replays). The nightly's `Integration
  tests (bhf) (WinAFL, Windows)` job builds the pinned pair with
  `scripts/ci/build-winafl.ps1`, caches it under the pinned versions and the
  script's hash (a cache hit skips the build), and runs them. Locally, run
  them from an elevated shell with `BHF_WINAFL_PATH` and `BHF_DYNAMORIO_PATH`
  set: `cargo test -p bhf --test winafl_engine -- --ignored`. Without the
  tools they fail instead of passing.

## Visual Studio solutions (.sln / .vcxproj)

`bhf auto` imports a Visual Studio solution by default — no flag — when the
tree has a `.sln`, `.slnx` or `.vcxproj` and no `compile_commands.json` or
CMake/Meson build. On a Linux host it does so only when the solution is the
tree's only build description: a tree that also ships a Makefile, autotools
inputs (`configure.ac`, `Makefile.am`, `autogen.sh`), Ninja, SCons or Bazel
files, at its root or in a directory on the way to the solution, is built the
way that build says, unless `--msbuild-solution` names the solution:

```powershell
bhf.exe auto C:\path\to\solution-tree --per-target-time 30
```
```text
bhf auto: read 12 ClCompile entries from build\vs2022\proj.sln (config Debug|x64, static evaluation)
```

The import runs nothing. It reads the solution (scanning a few directory
levels: `build\VS2022\`, `msvc\`, ...; with several solutions it takes the
shallowest, then by path, and says so) and each referenced `.vcxproj`, and
evaluates them the way MSBuild would for one configuration:

- `$(SolutionDir)` is the solution's directory, `$(ProjectDir)` the project's;
  `$(MSBuildThisFileDirectory)` is the directory of the file it appears in.
- Local `<Import>`s and `ImportGroup` property sheets (`.props`) are followed.
  The nearest `Directory.Build.props` above each project is read where
  MSBuild's toolset imports it (at `Microsoft.Cpp.Default.props`) and the
  nearest `Directory.Build.targets` at `Microsoft.Cpp.targets`, with
  `$(MSBuildThisFileDirectory)` their own directory; `ImportDirectoryBuildProps`
  / `ImportDirectoryBuildTargets` set to `false` turn them off, as in MSBuild.
  The search stops at the scanned tree's root: such a file above it is named
  on the console and not read. The rest of the Visual Studio
  toolset's standard imports (`$(VCTargetsPath)\Microsoft.Cpp.props`) carry the
  toolset's defaults, which the compiler supplies; any other toolset import
  (`$(VCTargetsPath)\BuildCustomizations\...`, `$(MSBuildExtensionsPath)\...`)
  is named on the console as not read.
- `Condition=` is evaluated (`'$(Configuration)|$(Platform)'=='Debug|x64'`,
  `Exists(...)`, `and`/`or`/`!`, version comparisons) for the chosen
  configuration: the first one the solution lists for x64, else the first,
  or `--msbuild-config Release|x64`. Only that configuration's settings apply,
  so `_DEBUG` and `NDEBUG` never meet.
- `$(...)` resolves from the solution and project macros, properties the
  project files define, and environment variables (MSBuild reads them as
  properties). An include dir or define built on a `$(...)` with no value is
  left out and named on the console; the toolset's own include macros
  (`$(VC_IncludePath)`, `$(WindowsSDK_IncludePath)`) are left out silently,
  since the compiler finds those through `INCLUDE`.
- Each `ClCompile` item contributes `AdditionalIncludeDirectories`,
  `PreprocessorDefinitions`, `UndefinePreprocessorDefinitions`,
  `ForcedIncludeFiles`, `LanguageStandard`/`LanguageStandard_C`,
  `AdditionalOptions` (cl options translated to clang's), `StructMemberAlignment`
  and `TreatWChar_tAsBuiltInType`; `CharacterSet` adds `UNICODE;_UNICODE` or
  `_MBCS`; items `ExcludedFromBuild` in that configuration are skipped; `\`
  separators are read as separators on every host.
- A project's link (or lib) `AdditionalDependencies` reach the harnesses of
  that project's own sources only, and only as Windows import libraries found
  in a `LIB` directory (`ws2_32.lib`), which bhf prints
  (`its harnesses link ws2_32.lib`) and the harness Makefile links as
  `BUILD_CONTEXT_LDFLAGS = -lws2_32`. Everything else is named and left out:
  a library not in `LIB` (an output of the solution's own build, which may not
  be built yet and whose sources the harness compiles, or a third-party
  library), a resolved path, and C runtime libraries (`libcmt.lib`; the harness
  picks its own runtime). To link one of those, use forward slashes, since the
  recipe runs through `sh`:
  `$env:AUTO_EXTRA_LDFLAGS = "C:/src/proj/x64/Debug/proj.lib"`.

The database is written to `<work>\auto\msbuild\compile_commands.json`, never
into the tree, and harnesses build with the project's real `-I`/`-D` flags.
`--msbuild-solution vs\Other.sln` picks a solution (a relative path is
resolved against the scanned tree; the solution may also lie outside it, and a
path that names no file is an error), `--no-msbuild-import` turns the import
off.

The project files are untrusted input, so the reader is bounded: a file over
16 MiB, elements nested more than 256 deep, a property value that expands past
256 KiB, and expansion past 64 MiB per project are refused or left out as
unresolved, with a note on the console.

The default import is the static reading above, on every host; it runs nothing.
MSBuild itself evaluates each project when it is installed
(`msbuild <proj> -getItem:ClCompile`, MSBuild 17.8+) with `--msbuild-evaluate`
(config key `msbuild-evaluate`, honoured only from an explicit `--config`),
`--probe-build` or `--run-untrusted`. Evaluation also covers whatever the
static reading cannot (property functions, NuGet-imported targets); a
project MSBuild cannot evaluate falls back to the static reading. The import
then prints `msbuild evaluation` instead of `static evaluation`; under
`--probe-build` it writes `compile_commands.json` to the work dir's probe home
(`<work>\probe\<tree>-<hash>\.bhf-build\`) like the other probe tiers.

Why evaluation is opt-in: evaluating a project runs code the scanned tree
chooses. MSBuild calls the property functions the project files contain
(`$([System.IO.File]::ReadAllText(...))`, `$([MSBuild]::...)`, and more),
reads and evaluates every file they import (a `Directory.Build.props` or
`.targets` anywhere above the project, NuGet package targets), and can
resolve and load SDKs. A tree under analysis is untrusted, so bhf runs none
of that unless you ask it to with one of the flags above. The static reading
only parses the files, with the bounds described above.

A harness whose build still needed a placeholder header or a made-up macro
value is reported as such: its findings are low confidence and carry a
`build.fidelity` record and caveat (see [c-cpp.md](c-cpp.md)).

Example (lz4's bundled solution): `bhf.exe auto C:\src\lz4` imports
`build\VS2022\lz4.sln`, then builds and fuzzes the `LZ4_decompress_*` parsers.

Notes:
- Headers produced by a custom pre-build/codegen step are not materialized by
  the import — run that step first, use `--build-command` (below), or use the
  CMake probe if the project also ships CMake.
- Coverage is instrumented by compiling the target's sources with bhf's
  harness compiler (not the project's cl-built objects), so findings carry real
  edge coverage.
- A target whose signature bhf cannot yet auto-harness is skipped/reported as
  a failed build; the rest of the solution still fuzzes.

## Software that only builds on Windows (MSVC / Win32)

This is the reason to run bhf on a Windows host rather than cross-fuzzing from
Linux: a target that calls Win32 APIs (`<windows.h>`, `CreateFileW`, sockets via
`ws2_32`), uses MSVC-only language constructs (`__declspec`, `__try/__except` SEH,
MSVC intrinsics), or only ships a Visual Studio build cannot be built anywhere but
Windows. bhf harnesses it natively there.

**MSVC-only source compiles.** On Windows clang defaults to the
`x86_64-pc-windows-msvc` target, so it accepts the MSVC dialect: `__declspec`,
`__try/__except`, calling-convention attributes, and MSVC intrinsics all compile,
and the harness links against the same MSVC CRT + Windows SDK that `cl` uses (this
is why VS Build Tools is a hard prerequisite even though clang is the default
compiler).

**Building with `cl.exe` (the MSVC lane).** For code only MSVC compiles, or to
fuzz the compiler the product ships with, build the harnesses with Visual
Studio's own compiler:

```powershell
bhf.exe auto C:\path\to\solution-tree --cc cl --per-target-time 30
```

(`[toolchain] cc = "cl"` in a `--config` file does the same; `--cc clang-cl`
selects LLVM's cl-compatible driver.) The generated Makefiles keep their
GCC-style command lines; `CC`/`CXX` point at `bhf-cl.exe`, bhf's front end for
cl (a hard link of `bhf.exe` under `%LOCALAPPDATA%\bhf\multicall\`, reused
only while its bytes are this `bhf.exe`'s), which
runs `cl.exe` with the equivalent options: `-I`/`-iquote` -> `/I`, `-include`
-> `/FI`, `-std=c11` -> `/std:c11`, `-o` -> `/Fe:`/`/Fo:`, `-g` -> `/Z7` with
`/DEBUG`, `-ffunction-sections`/`-Wl,--gc-sections` -> `/Gy`/`/OPT:REF`,
`-lfoo` -> `foo.lib`. A harness is built with `/fsanitize=address` and MSVC's
SanitizerCoverage (`/fsanitize-coverage=inline-8bit-counters`, `edge`,
`trace-cmp`, `trace-div`); `libsancov.lib` hands the inline counters to the
driver, which folds them into the same edge and hit-count maps after every
input, so the engine sees coverage and comparison operands as with clang. cl's
diagnostics are passed through with their clang spelling added, so the repair
loop handles missing headers, undeclared identifiers and unresolved externals
(`LNK2019`) the same way; weak repair stubs become MSVC alternate names. cl's
own ASan runtime DLL is put first on `PATH` and next to each `main.exe`. To
rebuild a harness by hand, name the front end: `make CC=<path>/bhf-cl.exe
CXX=<path>/bhf-cl.exe` (it runs the `cl.exe` on `PATH`, or `BHF_MSVC_CL`). Limits:
cl has no UBSan, MSan or TSan (those lanes stay clang's, or are skipped), the
`-idirafter` fallback dirs are appended to `INCLUDE`, and an `-iquote` dir is a
plain `/I` (cl has no quote-only search path).

**Link libraries.** clang and cl honour in-source `#pragma comment(lib,
"ws2_32")` directives, and the default Win32 import libs are linked without any
flags. Import libraries a project names in its link's
`<AdditionalDependencies>` are linked into that project's harnesses by the
project import (above). Anything else, such as the project's own prebuilt
`.lib`, goes in `AUTO_EXTRA_LDFLAGS`, with forward slashes since the recipe
runs through `sh`:

```powershell
$env:AUTO_EXTRA_LDFLAGS = "C:/src/proj/x64/Release/proj.lib"
bhf.exe auto C:\path\to\solution-tree --per-target-time 30
```

…or recover the full compile context from the real build (below).

**Recovering the real MSVC build (`--build-command`).** When the project's
compile flags are too complex to read from its project files, run its actual
build under bhf's compiler capture, so each `cl` invocation is recorded into a
`compile_commands.json`:

```powershell
bhf.exe auto C:\src\proj --build-command "msbuild proj.sln /p:Configuration=Release /p:Platform=x64" --per-target-time 30
```

No Native Tools prompt is needed: the discovered Visual Studio environment puts
MSBuild and cl on `PATH`. The command runs through `cmd.exe`. Each compiler on
`PATH` (`cl`, `clang-cl`, `clang`, `gcc`, ...) gets an executable shim in
`<work>\probe\<tree>-<hash>\.bhf-build\intercept\` that records its arguments (with MSBuild's
response files expanded) and runs the real compiler unchanged. MSBuild starts
cl from the toolset directory by absolute path, so the CL task is pointed at the
`cl.exe` shim through the `CLToolPath`/`CLToolExe` properties (with
`TrackFileAccess` and `UseMultiToolTask` off, both of which assume the real
cl); the build itself is not altered. Each cl run compiles several sources, and
each becomes its own row. The rows are cl-style and are read as described in
[c-cpp.md](c-cpp.md). A tool that starts a compiler by absolute path without
going through MSBuild's CL task is not captured (the Linux-only `LD_PRELOAD`
exec shim has no Windows equivalent). `--build-command` executes the project's
own (untrusted) build — only run trees you trust.

**Generated headers.** If the build generates headers via a codegen/pre-build step
(`midl`, a `.tt` template, a custom tool), run that step (or a full `msbuild`) once
first so the headers exist on disk; the project import (with or without
`--probe-build`) evaluates the projects but does not build them.
`--build-command` runs the real build and so materializes them.

**Out-of-tree headers / sibling sources.** `--extra-include C:\sdk\include` adds
`-I` paths for dependency headers outside the swept tree; `--extra-source
C:\src\proj\helpers.c` compiles+links a sibling translation unit whose symbols the
target needs (instead of blind-stubbing them). Both are repeatable.

**Paths with spaces.** The source tree, the work directory, the compiler and
`--extra-include`/`--extra-source` paths may contain spaces, parentheses,
apostrophes, `&` and `^` (`C:\Program Files (x86)\...`, `C:\R&D\...`, a user
profile, a OneDrive folder). bhf double-quotes them in the generated Makefile,
where `cmd` and `sh` take them literally, and keeps them out of make
prerequisites. A path containing `$`, `#`, `%`, a backtick, a double quote or
another shell operator (`;`, `|`, `<`, `>`) is still refused, and the message
names the character. The Visual Studio environment bhf applies (or a Developer
PowerShell) sets `INCLUDE` and `LIB`, which clang and cl read, so the Visual
Studio and Windows SDK system include dirs never need `--extra-include` — and
should not be passed that way.

**What you give up vs. Linux.** Only the LD_PRELOAD behavioral/taint oracles (see
the limitations below) — they are Linux-only. Crash detection (a fault becomes a
distinctive exit via the driver's structured-exception handler), edge coverage,
cmplog, and ASan all work natively on Windows.

## Notes / current limitations

- bhf itself runs on Linux and Windows; macOS is not yet a target.
- The **C/C++ lane** (including Visual Studio solutions) is the primary,
  most-exercised native-Windows path. It builds with clang or cl: GCC
  (MinGW-w64's, Cygwin's, MSYS2's) ships no AddressSanitizer or UBSan runtime
  on Windows, and the harness links both, so a C or C++ target whose `CC` or
  `CXX` is gcc is refused there, naming the compiler, and reported static-only
  (discovered and statically analyzed, not fuzzed), unless `--sanitizers none`
  asks for a crash-only build without them. Go emits a native binary
  and works with `go` installed; a Go capsule rebuilds through `build.sh`, so
  `bhf verify-poc` needs a POSIX `sh` on `PATH` (Git for Windows' will do).
  Ada and COBOL also produce native binaries but their Windows toolchain
  combinations are less exercised; validate them on a representative target
  before relying on a campaign. The Rust lane builds its harness as a Unix
  static archive (`lib*.a`, linked with `libpthread` and `libdl`) and does not
  build on native Windows yet; run it under WSL/Linux. The Fortran lane's
  crash oracle is gfortran's AddressSanitizer, and MinGW-w64's GCC, the
  Windows gfortran, ships no sanitizer runtime; run it under WSL/Linux.
- The Python lane runs on native Windows with a Python 3 on `PATH` (`python`
  or `python3`). Its `main` is a POSIX launcher, so it also writes
  `main.launch.json` beside it: the interpreter, the driver and the environment
  the launcher sets, which the engine, `bhf replay` and `bhf minimize` run on
  Windows in its place.
- The C# lane runs on native Windows with the .NET 8 SDK and SharpFuzz (the
  `sharpfuzz` tool and its NuGet package, as on Linux). Its `main` and
  `main_symbols` launchers have launch specs (`dotnet` on the harness
  assembly), and its driver maps the coverage file and speaks the framed
  protocol through .NET's own file mapping and console streams there.
- The Java lane runs on native Windows with a JDK (`java`, `javac`, `jar`) on
  `PATH`: its launch spec runs `java` with the agent and a `;`-separated
  classpath, and the agent jar is built by `java_runtime\build-agent.ps1`
  (ASM 9.7 from Maven Central, checked against its pinned SHA-256, or from
  `ASM_JAR_DIR`), cached in `%LOCALAPPDATA%\bhf\jvm` unless `BHF_JVM_CACHE`
  names another place.
- The JavaScript and TypeScript lanes run on native Windows with Node (and
  esbuild for TypeScript): their launch spec runs `node` on the driver.
- Perl, Ruby, Lua, and PHP currently emit POSIX `main` launchers even though
  discovery is portable. Run those lanes under WSL/Linux for now; installing
  only the interpreter on native Windows is not sufficient.
- On native Windows `bhf auto` refuses the lanes that run under WSL (those
  above, Rust and Fortran) whatever is installed: its toolchain check marks
  each one `NOT ON NATIVE WINDOWS` with the reason, and their targets are
  reported static-only with that reason, pointing at WSL.
- The persistent fork-server + coverage-guided engine run on Windows the same as
  on Linux (shared-memory coverage via Win32 file mapping).
- Microsoft Defender's real-time scanning does not slow fuzzing down, and a
  Defender exclusion for the work dir is not needed for speed. Measured on a
  Windows Server 2022 VM (6 cores) with a small C harness under `bhf fuzz`:
  2483 executions/s with the work dir scanned and 2432 with it excluded
  (persistent fork server); 7.0 and 7.2/s when every input starts a new
  process (`--no-fork-server`, about 140 ms per ASan process start). Defender
  adds about 100 ms to the first start of a newly built binary, once. What
  does slow a run down is an oversubscribed CPU: with twice as many busy
  processes as cores the same harness ran 0.4 executions/s, and with four
  times as many its first start took over 2 s, past the fork-server
  handshake, so the run fell back to one process per input. Give a campaign
  the cores it fuzzes with (`--jobs`), and do not share them with builds.
- The LD_PRELOAD runtrace shim is Linux-only (an empty stub on Windows), so the
  behavioral and taint oracles (BHF-405 path control, BHF-304 command injection,
  BHF-417 insecure temp, BHF-305 sensitive env) do not fire on native Windows via
  that path. Crash detection and coverage-guided fuzzing are unaffected.
- The **runtime-event collector** (`--collector`, #60) is the native-Windows path
  to clean-exit semantic findings. `--collector auto` selects the native ETW
  provider (`bhf-collector-win`). It starts a BHF-owned system-logger real-time
  session (never the global NT Kernel Logger) with the process, file-I/O and
  image-load flags, runs `ProcessTrace` over it, and emits the
  platform-neutral `bhf.collector-event.v1` JSONL contract.
  - **Decoding.** Each live `EVENT_RECORD` is decoded by the pure
    `win_etw_decode` module, the MOF decode of the three kernel providers:
    - process creation and the descendant tree (a `ShellExecuteEx` call shows
      up as the process it creates);
    - file create, open, write, rename and delete, with resolved paths;
    - image load.
  - **Replay.** `bhf binary fuzz --collector auto` replays the retained inputs
    under the sidecar one by one: the input behind each of the run's findings,
    then (with `--engine afl-qemu`) the AFL++ queue entries that found new
    coverage, then the seeds, at most 16 (`replays_dropped` in the run's
    `collector` block counts the rest). `collector.replays` lists each replay
    with its input's SHA-256, the PID it ran as and its findings, and a finding
    keeps the input whose replay produced it. The run is a clean assurance only
    when every replay was observed clean. For each replay:
    1. The host waits for the sidecar's readiness ack.
    2. It launches the target and writes its PID to the file
       `BHF_COLLECTOR_TARGET_PID` names.
    3. When the target has exited and the post-exit window has passed, it
       creates `BHF_COLLECTOR_DONE`.

    The sidecar holds every event until the PID arrives, then attributes the
    events of that process and its descendants, those received before the
    handoff included. It traces until `BHF_COLLECTOR_DONE` (at most 300 s), not
    for a fixed window. A sidecar that never gets the PID records
    `target_pid_not_received` and attributes nothing.
  - **What the live controls show.** These run on the Windows CI runner under
    `BHF_WIN_LIVE=1` (`collector_win_live`):
    - a target that runs `cmd.exe` through `ShellExecuteEx` with its input in
      the command line gets a controlled-process-execution finding (BHF-431);
    - the same target with a constant command line is observed and gets none.

    The file and image-load classes are decoded and unit-tested against
    ETW-shaped records, but no live control covers a BHF-405 or BHF-435
    finding yet. `bhf fuzz --collector` replays the harness the same way, on
    each of the campaign's retained inputs (its crash findings, then its
    persisted corpus, at most 16), launched as `bhf replay` runs the harness.
  - **Rights.** Starting an ETW session needs session rights (an elevated
    prompt). Without them the provider records `fidelity.permission_denied`
    instead of reporting a silent clean run.
- The native-Windows harness build uses GNU `make` + clang (same as Linux), or
  cl through `bhf-cl` with `--cc cl`; the drive-letter colon + backslash quirks
  are handled by emitting forward-slash paths into the recipe.
- GNU make runs a harness recipe through `sh` when one is on `PATH`
  (w64devkit, MSYS2) and through `cmd` otherwise, so a compile flag that needs
  quoting there (a space, parenthesis, apostrophe or shell operator, as in
  `-DBAR=(x)`) is double-quoted, which both honour. Such a flag that also holds
  `%`, `#`, `"` or a backtick is refused, since one of the two shells (or
  `make`, for `#`) acts on it even inside double quotes (a `[toolchain]`
  flag, which `make` takes from the environment, may hold `#`). The
  exception is a quoted string-macro define (`-DNAME="value"`), which is
  double-quoted whole with its own quotes escaped (`"-DNAME=\"value\""`), so
  the compiler receives them; `cmd` reads those escaped quotes as the end and
  the restart of its own quoting, so such a define is refused when it holds a
  backslash or its value holds one of `& | < > ^ ( ) % !`.
- Each lane's link discards unreferenced code in the spelling of its linker:
  `/OPT:REF` when the lane's compiler links with link.exe or lld-link (clang's
  default `*-windows-msvc` target, or `--cc cl`), `--gc-sections` for MinGW's
  gcc. Setting `SECTION_LDFLAGS` (even to nothing) replaces it for every lane.
  The line-coverage lane links no Unix runtime library (`-lm`, `-ldl`,
  `-lpthread`), which the Windows C runtime already holds.
- A harness for a function that takes a `FILE *` gets its input through a
  temporary file deleted on close, since the Windows C runtime has no
  `fmemopen`.
- `bhf corpus export --to afl` names entries `id_000000,sig_...`: Windows
  allows no `:` in a file name. `bhf corpus import` and `merge` read both that
  and AFL's usual `id:000000,...` spelling.
- SARIF reports name Windows files as `file:///C:/...` URIs, and the Markdown
  and CSV reports show paths under the scanned tree relative to it, whether
  the build spelled them `C:\src\...` or `C:/src/...`.
