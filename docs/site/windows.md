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
The discovered directories reach builds only through `PATH`/`INCLUDE`/`LIB`,
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
`python3` on Windows, and `bhf explain` prints the `$env:Path` line for a direct
run.

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
- Local `<Import>`s and `ImportGroup` property sheets (`.props`) are followed;
  the Visual Studio toolset imports (`$(VCTargetsPath)\...`) are not needed.
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
`--probe-build` it writes `<tree>\.bhf-build\compile_commands.json` like the
other probe tiers.

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
`<tree>\.bhf-build\intercept\` that records its arguments (with MSBuild's
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
  most-exercised native-Windows path. Go emits a native binary and works with
  `go` installed. Rust, Ada, COBOL, and Fortran also produce native binaries but
  their Windows toolchain combinations are less exercised; validate them on a
  representative target before relying on a campaign.
- Java, Python, Perl, C#, JavaScript/TypeScript, Ruby, Lua, and PHP currently
  emit POSIX `main` launchers even though discovery is portable. Run those lanes
  under WSL/Linux for now; installing only the interpreter/JDK on native Windows
  is not sufficient. A missing toolchain still skips cleanly.
- The persistent fork-server + coverage-guided engine run on Windows the same as
  on Linux (shared-memory coverage via Win32 file mapping).
- The LD_PRELOAD runtrace shim is Linux-only (an empty stub on Windows), so the
  behavioral and taint oracles (BHF-405 path control, BHF-304 command injection,
  BHF-417 insecure temp, BHF-305 sensitive env) do not fire on native Windows via
  that path. Crash detection and coverage-guided fuzzing are unaffected.
- The **runtime-event collector** (`--collector`, #60) is the native-Windows path
  to clean-exit semantic findings. `--collector auto` selects the native ETW
  provider (`bhf-collector-win`), which starts the NT Kernel Logger real-time
  session with the process / file-I/O / image-load flags and runs `ProcessTrace`
  over it, emitting the platform-neutral `bhf.collector-event.v1` JSONL contract.
  Each live `EVENT_RECORD` is decoded by the pure `win_etw_decode` module — the
  **complete** MOF decode of the three kernel providers (pointer-size and event-
  version aware, with `FileObject → path` matching for read/write/rename/delete,
  create-vs-open disposition classification, and `UserSID` rendering):
    - `CreateProcess*` process creation (`Process_TypeGroup1`) and the descendant
      tree — a `ShellExecuteEx` call surfaces at the kernel level as the resulting
      process creation, which the descendant-tree attribution captures;
    - file create/open/write/rename/delete with resolved paths (`FileIo_Create`,
      `FileIo_Name`/rundown mapping, `FileIo_ReadWrite`, `FileIo_Info`);
    - `LoadLibrary*`/image-load (`Image_Load`).
  Each event is attributed to the testcase's descendant process tree, so a
  controlled process execution (BHF-431), a path escaping the allowed root
  (BHF-405), or a controlled library load (BHF-435) becomes a `binary_semantic`
  finding even on a clean exit, feeding the same oracle registry as the Linux shim.
  Starting an ETW session needs session rights; when the provider lacks them it
  records `fidelity.permission_denied` rather than reporting a silent clean run. The
  full decode logic is unit-tested on every platform against synthetic ETW-shaped
  records (`win_etw_decode` covers all five classes and their fields); the live ETW
  run is validated on the Windows CI runner under `BHF_WIN_LIVE=1`.
- The native-Windows harness build uses GNU `make` + clang (same as Linux), or
  cl through `bhf-cl` with `--cc cl`; the drive-letter colon + backslash quirks
  are handled by emitting forward-slash paths into the recipe.
- GNU make runs a harness recipe through `sh` when one is on `PATH`
  (w64devkit, MSYS2) and through `cmd` otherwise, so a compile flag that needs
  quoting there (a space, parenthesis, apostrophe or shell operator, as in
  `-DBAR=(x)`) is double-quoted, which both honour. Such a flag that also holds
  `%`, `"` or a backtick is refused, since one of the two shells acts on it
  even inside double quotes.
- A harness for a function that takes a `FILE *` gets its input through a
  temporary file deleted on close, since the Windows C runtime has no
  `fmemopen`.
- `bhf corpus export --to afl` names entries `id_000000,sig_...`: Windows
  allows no `:` in a file name. `bhf corpus import` and `merge` read both that
  and AFL's usual `id:000000,...` spelling.
- SARIF reports name Windows files as `file:///C:/...` URIs, and the Markdown
  and CSV reports show paths under the scanned tree relative to it, whether
  the build spelled them `C:\src\...` or `C:/src/...`.
