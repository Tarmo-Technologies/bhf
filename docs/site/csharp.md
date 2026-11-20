<!-- SPDX-License-Identifier: Apache-2.0 -->
# Fuzzing C# / .NET with bhf

Point bhf at a .NET source tree and it discovers fuzzable methods, generates
the harness, builds the target with `dotnet`, instruments it and fuzzes it,
coverage-guided. You write no harness.

```sh
bhf auto path/to/dotnet-src --languages csharp
```

## How it works

The fuzzable unit is a `public` method that takes a byte buffer (`byte[]`,
`ReadOnlySpan<byte>`, `Memory<byte>`), a `string` or a `System.IO.Stream`.
For each one, bhf:

1. **Discovers** the method, tracking the namespace and enclosing type by
   brace depth, and types every parameter. Constructors, properties, local
   functions, generic methods and interface or enum members are excluded. A
   method is fuzzed when it has exactly one input parameter plus only scalar
   parameters bhf can synthesize (an `int` length). bhf never invents a
   reference-type argument, which would make the resulting
   `NullReferenceException` look like a bug.
2. **Builds** the target with `dotnet build -c Release` through a
   `ProjectReference` to the owning `.csproj`, together with a generated
   `BhfEntry.Run(byte[])` shim. The shim decodes the fuzz bytes to the
   parameter's static type: `byte[]` as is, `string` via UTF-8, `Stream` via
   a `MemoryStream`, and spans via the matching wrapper. Every project of
   that build, the target's own included, writes its `obj/` and `bin/` under
   the harness (`harnesses/<id>/build/`), through a props file passed as
   `DirectoryBuildPropsPath` that imports the project's own
   `Directory.Build.props` first. The source tree is left unchanged, and the
   harnesses of one project build side by side under any `--jobs`.
3. **Instruments** the target assembly's IL with
   [SharpFuzz](https://github.com/Metalnem/sharpfuzz) (`sharpfuzz <dll>`,
   Apache-2.0), which rewrites every basic block to record edge coverage. The
   rewritten assembly has no debug symbols, so its stack frames name no
   source line. bhf therefore keeps the build from before instrumentation,
   with its pdbs, in `harnesses/<id>/build/symbols/` (run by `main_symbols`),
   and re-runs a finding's input through it, so `finding.json` and SARIF
   name the `.cs` file and line.
4. **Fuzzes** it on bhf's own coverage-guided fork-server engine. The driver
   `mmap`s bhf's file-backed `BHF_COV_SHM` edge bitmap (64 KiB, the AFL map
   size SharpFuzz targets) into `SharpFuzz.Common.Trace.SharedMem`, so the
   instrumented target writes coverage straight into bhf's bitmap. The
   driver speaks bhf's framed fork-server protocol and keeps one warm CLR
   alive across all inputs, which saves the JIT and assembly-load startup per
   input. No AFL fork-server, libFuzzer or `afl-fuzz` process is involved.

### Oracle

The finding signal is an uncaught exception that is not input rejection. The
driver stops with exit code 86 and prints a `== bhf csharp finding:` marker.
The .NET exception type maps to a bhf rule and CWE:

| Exception | Rule | CWE |
|---|---|---|
| `IndexOutOfRangeException` | BHF-201 | CWE-125/787 (out-of-bounds) |
| `NullReferenceException` | BHF-206 | CWE-476 (null dereference) |
| `DivideByZeroException`, `OverflowException`, `ArithmeticException` | BHF-205 | CWE-369/190 |
| `StackOverflowException`, `InsufficientExecutionStackException` | BHF-207 | CWE-674 (uncontrolled recursion) |
| `OutOfMemoryException` | BHF-209 | CWE-789 |
| any other or custom exception | BHF-210 | reachable crash |

These exceptions count as the library rejecting bad input and are not
reported: `ArgumentException` and its subclasses, `FormatException`,
`NotSupportedException`, `NotImplementedException`,
`InvalidOperationException`, `IOException` and its subclasses,
`UnauthorizedAccessException`, `KeyNotFoundException`, `TimeoutException`,
`XmlException` and `OperationCanceledException`. Exceptions declared in the
target's own namespace count as rejection too. A `NullReferenceException`
raised too close to bhf's entry shim to involve the target's own code is
treated as a harness artifact.

The C# lane runs without the runtime-virtualisation shim. The .NET host's own
startup file I/O (resolving `libhostfxr.so` through `access()` then `open()`,
loading assemblies) would trip the shim's TOCTOU and file-open oracles.
Coverage comes from SharpFuzz's IL instrumentation, and crash detection from
the exception handler in the driver.

## Compared with SharpFuzz alone

[SharpFuzz](https://github.com/Metalnem/sharpfuzz) is the IL-instrumentation
library bhf builds on. Used directly, it is a library: you write a fuzzing
program per target (`Fuzzer.LibFuzzer.Run(bytes => Target.Parse(bytes))` or
`Fuzzer.OutOfProcess.Run`), instrument the target dll yourself, and install
and run `afl-fuzz` (or a libFuzzer host) with the shared-memory plumbing.
bhf automates those steps:

| | SharpFuzz used directly | `bhf auto --languages csharp` |
|---|---|---|
| Fuzzing function to write | one per target | none: methods are discovered |
| Instrument the dll | manual `sharpfuzz` call | automatic |
| Fuzzer to install and wire | AFL or libFuzzer host | built-in engine |
| Coverage plumbing | `__AFL_SHM_ID` / `shmat` | automatic (`BHF_COV_SHM` bridge) |
| Multi-target sweep | scripted by hand | one command over the whole tree |
| Findings with CWE, SARIF, CSV | not included | built in |

Static analyzers (Roslyn analyzers, SonarQube, Coverity) flag candidate issues
without running the code on input.

## Validation campaign

A campaign over 25 widely used .NET libraries (dotnet/runtime, roslyn, EF
Core, Newtonsoft.Json, MessagePack-CSharp, YamlDotNet, ImageSharp,
protobuf-net, SharpZipLib, ML.NET and others) recorded:

- 69,608 C# files scanned, 3,113 fuzzable methods discovered and no bhf
  panics. roslyn alone contributed 17,094 files and 973 targets. 24 of the 25
  repositories completed; dotnet/runtime (32,403 files) needs a longer
  discovery budget.
- On YamlDotNet, 14 of 21 methods were built, IL-instrumented and fuzzed at
  about 15,000 executions per second on one warm CLR, reaching 2,304 edges.
  bhf reported 8 findings with no hand-written harness, among them a
  `System.IndexOutOfRangeException` (CWE-125) reachable from every
  naming-convention entry point. Its root cause is an unguarded `text[0]` on
  an empty string in `StringExtensions.ToCamelOrPascalCase`.

## Requirements and licensing

- **.NET SDK** on the host ([download](https://dotnet.microsoft.com/download)).
- **SharpFuzz.CommandLine**:
  `dotnet tool install --global SharpFuzz.CommandLine`.
- **The SharpFuzz 2.3.0 NuGet package**, and every package the target's
  project references, in NuGet's global packages folder (`$NUGET_PACKAGES`,
  else `~/.nuget/packages`). The harness build restores from that folder
  only, never from a network feed. Preflight reports the C# lane as missing
  the package when the folder has no `sharpfuzz/2.3.0`. A target whose build
  fails with NuGet NU1101 or NU1102 gets a `language_package` entry in
  `missing-deps`, such as `SharpFuzz 2.3.0`.
- SharpFuzz and SharpFuzz.Common are Apache-2.0 and link into your harness
  assembly, never into bhf. The .NET runtime is MIT. The lane involves no GPL
  code.

### Staging the NuGet packages offline

On a connected host with the same .NET SDK:

```sh
dotnet new classlib -o stage && cd stage
dotnet add package SharpFuzz --version 2.3.0
# and each PackageReference of the target's .csproj
dotnet restore
```

Then copy `~/.nuget/packages/sharpfuzz/2.3.0` (and the other restored package
directories) to the same place under the offline host's `NUGET_PACKAGES`, or
`~/.nuget/packages`.

## Limits

- The fuzzable surface is a single `byte[]`, `string` or `Stream` input
  parameter, plus an optional `int` length. Methods that need a constructed
  options or context object, a generic type argument or several structured
  inputs are skipped with a reason; bhf does not drive them with synthesized
  `null`s.
- An instance method's declaring type must have a parameterless constructor
  (the shim creates the instance with `new`); a type with only parameterized
  constructors is skipped. `--force` allocates such a receiver without
  running a constructor.
- The target must build with the .NET SDK through a project reference. A
  project that targets only .NET Framework (`net48`) is skipped on a
  non-Windows host.
- bhf instruments and fuzzes one method at a time. The target's own
  dependencies are loaded but not instrumented, so coverage covers the code
  under test.
