# SPDX-License-Identifier: Apache-2.0

param(
    [Parameter(Mandatory = $true)]
    [string]$BinaryDir,
    [string]$ExpectedCommit
)

$ErrorActionPreference = "Stop"
$binaryRoot = (Resolve-Path $BinaryDir).Path
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$fixture = Join-Path $repoRoot "tests\fixtures\engine_parity\magic_byte"
$bhf = Join-Path $binaryRoot "bhf.exe"
$daemon = Join-Path $binaryRoot "bhf-daemon.exe"
$workspaceVersion = Get-Content (Join-Path $repoRoot "Cargo.toml") |
    Select-String '^version = "([^"]+)"' |
    Select-Object -First 1
if (-not $workspaceVersion) {
    throw "Could not read the workspace package version"
}
$expectedVersion = "bhf v$($workspaceVersion.Matches[0].Groups[1].Value)"

Get-CimInstance Win32_OperatingSystem |
    Select-Object Caption, Version, BuildNumber |
    Format-List
$versionLines = @(& $bhf --version)
if ($LASTEXITCODE -ne 0) { throw "bhf --version failed" }
$actualVersion = $versionLines[0].Trim()
Write-Host $actualVersion
if ($actualVersion -ne $expectedVersion) {
    throw "Expected '$expectedVersion', got '$actualVersion'"
}
if (-not $ExpectedCommit) {
    $ExpectedCommit = (& git -C $repoRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0) { throw "Could not read the tested source commit" }
}
if ($ExpectedCommit -cnotmatch '^[0-9a-f]{40}$') {
    throw "ExpectedCommit must be a full source commit SHA"
}
if ($versionLines -notcontains "commit: $expectedCommit") {
    throw "CLI does not report the exact tested source commit"
}
$daemonHelp = @(& $daemon --help)
if ($LASTEXITCODE -ne 0 -or -not ($daemonHelp -match '^Usage: bhf-daemon')) {
    throw "Daemon help did not report its actual command interface"
}
$daemonVersion = @(& $daemon --version)
if ($LASTEXITCODE -ne 0 -or $daemonVersion -notcontains "commit: $expectedCommit") {
    throw "Daemon source identity disagrees with the tested CLI"
}
& $bhf scan $fixture `
    --work-dir "$env:RUNNER_TEMP\bhf-windows-scan"
& $bhf auto $fixture `
    --work-dir "$env:RUNNER_TEMP\bhf-windows-plan" `
    --languages c --list-targets --no-discovery-cache

if (-not (Get-Command clang -ErrorAction SilentlyContinue) -and
    -not (Test-Path "$env:ProgramFiles\LLVM\bin\clang.exe")) {
    choco install llvm --yes --no-progress
}
if (-not (Get-Command make -ErrorAction SilentlyContinue) -and
    -not (Test-Path "C:\w64devkit\bin\make.exe")) {
    choco install make --yes --no-progress
}

# Chocolatey updates the persistent machine/user PATH, but PowerShell keeps the
# process environment it inherited. Refresh it so tools installed above are
# immediately usable in clean OpenSSH and CI sessions.
$env:Path = (@(
        [Environment]::GetEnvironmentVariable("Path", "Machine")
        [Environment]::GetEnvironmentVariable("Path", "User")
        $env:Path
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ";"

# No Developer shell: bhf finds Visual Studio (vswhere), applies the
# environment VsDevCmd sets, and locates clang and make itself.
foreach ($name in @("INCLUDE", "LIB", "LIBPATH", "VCToolsInstallDir")) {
    Remove-Item "Env:$name" -ErrorAction SilentlyContinue
}

function Invoke-BhfAuto([string]$Source, [string]$Work, [string[]]$Extra, [string]$Languages = "c") {
    $log = "$Work.log"
    # bhf reports progress on stderr; capturing it must not stop the script
    # (Windows PowerShell turns redirected native stderr into error records).
    $ErrorActionPreference = "Continue"
    & $bhf auto $Source --work-dir $Work --jobs 1 --max-targets 1 `
        --per-target-time 15 --languages $Languages --verbose @Extra 2>&1 |
        ForEach-Object { "$_" } | Tee-Object -FilePath $log | Out-Host
    $exit = $LASTEXITCODE
    $ErrorActionPreference = "Stop"
    $text = Get-Content $log -Raw
    if ($text -notmatch "bhf: build environment: .*\((x64|arm64), (captured|cached)\)") {
        throw "bhf did not apply a discovered Visual Studio environment for $Source"
    }
    $report = Get-Content "$Work\auto\run.json" -Raw | ConvertFrom-Json
    if ($exit -ne 0 -or $report.summary.built_and_fuzzed -ne 1) {
        Get-ChildItem $Work -Recurse -File |
            Where-Object { $_.Name -in @("Makefile", "result.json", "c_build_output.log") } |
            ForEach-Object { Write-Host "--- $($_.FullName)"; Get-Content $_.FullName }
        throw "bhf auto $Source $Extra did not build and fuzz its target: $($report.summary | ConvertTo-Json -Compress)"
    }
    return @{ Report = $report; Log = $text }
}

$work = "$env:RUNNER_TEMP\bhf-windows-fuzz"
# Exercise the README first run with the default ASan/UBSan build and pass
# cascade. A sanitizer-disabled smoke cannot catch missing runtime DLLs or a
# crash handler that intercepts ASan's handled exceptions.
& $bhf auto $fixture `
    --work-dir $work `
    --jobs 1 `
    --max-targets 1 `
    --per-target-time 10 `
    --verbose
if ($LASTEXITCODE -ne 0) { throw "Default Windows first run failed" }
$report = Get-Content "$work\auto\run.json" -Raw | ConvertFrom-Json
if ($report.summary.built_and_fuzzed -ne 1) {
    Get-ChildItem $work -Recurse -File |
        Where-Object {
            $_.Name -in @(
                "Makefile",
                "result.json",
                "run.json",
                "missing-deps.txt",
                "bug-report.md"
            )
        } |
        ForEach-Object {
            Write-Host "--- $($_.FullName)"
            Get-Content $_.FullName
        }
    throw "Windows smoke did not build and fuzz parse_frame: $($report.summary | ConvertTo-Json -Compress)"
}
$passes = @($report.targets[0].outcome.passes)
if (-not $passes -or ($passes | Measure-Object executions -Sum).Sum -le 0 -or
    ($passes | Measure-Object coverage_edges -Maximum).Maximum -le 0) {
    throw "Default Windows first run did not execute inputs with coverage"
}
if (-not (Test-Path "$work\results\INDEX.md") -or
    -not (Test-Path "$work\auto\summary.txt")) {
    throw "Default Windows first run did not produce the documented results"
}

# A Visual Studio solution in a directory with spaces: the project import reads
# its include dirs and defines (it runs nothing), and the planted heap overflow
# is found with the clang lane and with the MSVC cl.exe lane.
$solutionRoot = Join-Path $env:RUNNER_TEMP "My Projects\vs solution"
Remove-Item -Recurse -Force $solutionRoot -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $solutionRoot | Out-Null
Copy-Item -Recurse (Join-Path $repoRoot "tests\fixtures\windows\vs_solution\*") $solutionRoot
foreach ($lane in @(@{ Name = "clang"; Extra = @() }, @{ Name = "cl"; Extra = @("--cc", "cl") })) {
    $laneWork = Join-Path $env:RUNNER_TEMP "My Projects\work $($lane.Name)"
    $run = Invoke-BhfAuto $solutionRoot $laneWork $lane.Extra
    if ($run.Log -notmatch "read 2 ClCompile entries from vs\\Widget\.sln \(config Debug\|x64, static evaluation\)") {
        throw "The $($lane.Name) lane did not import the Visual Studio solution"
    }
    # The project's import library is linked into its harness; the output
    # of a project the solution has not built is named and left out.
    if ($run.Log -notmatch "its harnesses link ws2_32\.lib" -or
        $run.Log -notmatch "not linking WidgetSupport\.lib \(not in LIB") {
        throw "The $($lane.Name) lane did not sort the project's link libraries"
    }
    $makefile = Get-ChildItem "$laneWork\harnesses\*\Makefile" | Select-Object -First 1 | Get-Content -Raw
    if ($makefile -notmatch "(?m)^BUILD_CONTEXT_LDFLAGS = -lws2_32\s*$") {
        throw "The $($lane.Name) lane's harness does not link the project's import library"
    }
    $findings = Get-Content "$laneWork\results\findings.json" -Raw | ConvertFrom-Json
    if (-not ($findings.findings | Where-Object { $_.title -like "Heap-based Buffer Overflow*" })) {
        throw "The $($lane.Name) lane did not find the planted heap overflow"
    }
    $finding = $findings.findings | Select-Object -First 1
    $replay = Join-Path "$laneWork\results" $finding.reproduce.command.Split(" ")[1]
    $ErrorActionPreference = "Continue"
    $replayOutput = & python $replay 2>&1 | ForEach-Object { "$_" } | Out-String
    $ErrorActionPreference = "Stop"
    if ($replayOutput -notmatch "AddressSanitizer: heap-buffer-overflow") {
        throw "replay.py of the $($lane.Name) lane did not reproduce: $replayOutput"
    }
}

# The real MSVC build of the same solution, captured: MSBuild's CL task runs
# the cl.exe shim, and each recorded translation unit becomes a cl-style
# compile database row.
$captureRoot = Join-Path $env:RUNNER_TEMP "My Projects\vs capture"
Remove-Item -Recurse -Force $captureRoot -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $captureRoot | Out-Null
Copy-Item -Recurse (Join-Path $repoRoot "tests\fixtures\windows\vs_solution\*") $captureRoot
$run = Invoke-BhfAuto $captureRoot (Join-Path $env:RUNNER_TEMP "My Projects\work capture") @(
    "--build-command", "msbuild vs\Widget.sln /p:Configuration=Release /p:Platform=x64 /nologo /v:minimal")
if ($run.Log -notmatch "--build-command: recorded 2 translation unit\(s\)") {
    throw "The MSBuild capture did not record the solution's two translation units"
}

# C++, with both lanes.
foreach ($lane in @(@{ Name = "clang"; Extra = @() }, @{ Name = "cl"; Extra = @("--cc", "cl") })) {
    $cppWork = "$env:RUNNER_TEMP\bhf-windows-cpp-$($lane.Name)"
    $null = Invoke-BhfAuto (Join-Path $repoRoot "tests\fixtures\windows\cpp_tokens") $cppWork $lane.Extra "cpp"
    $findings = Get-Content "$cppWork\results\findings.json" -Raw | ConvertFrom-Json
    if (-not $findings.findings) {
        throw "The C++ $($lane.Name) lane did not find the planted out-of-bounds read"
    }
}

# A handle-based API (init / feed / end) gets the stateful sequence harness,
# with the default sanitizers.
$sequenceWork = "$env:RUNNER_TEMP\bhf-windows-sequence"
$run = Invoke-BhfAuto (Join-Path $repoRoot "tests\fixtures\windows\handle_session") $sequenceWork @()
$metadata = Get-ChildItem "$sequenceWork\harnesses\*\generation-metadata.json" |
    Select-Object -First 1 | Get-Content -Raw | ConvertFrom-Json
if ($metadata.emitted_path -ne "sequence") {
    throw "The handle-based API was not harnessed as a sequence: $($metadata | ConvertTo-Json -Compress)"
}
$passes = @($run.Report.targets[0].outcome.passes)
if (($passes | Measure-Object executions -Sum).Sum -le 0) {
    throw "The sequence harness executed no inputs"
}

# The sequence template's own driver: main.c built without
# BHF_EXTERNAL_DRIVER, as the AFL++ recipe builds it (here with clang and
# AddressSanitizer). Its crash handler must leave the exceptions ASan handles
# itself alone (a first-chance handler turns ASan's shadow-memory faults into
# crashes): a plain input runs to completion, and the fuzz run's finding is
# reported by ASan.
$sequenceHarness = Split-Path -Parent (Get-ChildItem "$sequenceWork\harnesses\*\generation-metadata.json" |
        Select-Object -First 1).FullName
$savedPath = $env:Path
foreach ($dir in @((Join-Path $env:ProgramFiles "LLVM\bin"), "C:\w64devkit\bin")) {
    if (Test-Path $dir) { $env:Path = "$env:Path;$dir" }
}
Push-Location $sequenceHarness
$ErrorActionPreference = "Continue"
& make main_afl AFLPP_CC=clang "AFLPP_CFLAGS=-g -O1 -fsanitize=address" 2>&1 |
    ForEach-Object { "$_" } | Out-Host
$ErrorActionPreference = "Stop"
if (-not (Test-Path main_afl)) {
    throw "The sequence template's own driver did not build"
}
Copy-Item main_afl standalone.exe -Force
[IO.File]::WriteAllBytes((Join-Path $sequenceHarness "plain.bin"), [byte[]](1, 2, 3, 4, 5, 6, 7, 8))
$ErrorActionPreference = "Continue"
$plainOutput = & .\standalone.exe plain.bin 2>&1 | ForEach-Object { "$_" } | Out-String
$plainExit = $LASTEXITCODE
$ErrorActionPreference = "Stop"
if ($plainExit -ne 0) {
    throw "The sequence template's own driver failed a plain input (exit $plainExit): $plainOutput"
}
$crash = Get-ChildItem "$sequenceWork\results\findings\*\testcase.bin" -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($crash) {
    $ErrorActionPreference = "Continue"
    $crashOutput = & .\standalone.exe $crash.FullName 2>&1 | ForEach-Object { "$_" } | Out-String
    $ErrorActionPreference = "Stop"
    if ($crashOutput -notmatch "ERROR: AddressSanitizer") {
        throw "The sequence template's own driver did not let ASan report the finding: $crashOutput"
    }
}
Pop-Location
$env:Path = $savedPath
