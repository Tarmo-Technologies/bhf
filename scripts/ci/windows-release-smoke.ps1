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

if (-not (Get-Command clang -ErrorAction SilentlyContinue)) {
    choco install llvm --yes --no-progress
}
if (-not (Get-Command make -ErrorAction SilentlyContinue)) {
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
clang --version
make --version

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsPath = & $vswhere -latest -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath
if (-not $vsPath) {
    throw "Visual Studio C++ Build Tools were not found"
}
Import-Module (Join-Path $vsPath "Common7\Tools\Microsoft.VisualStudio.DevShell.dll")
Enter-VsDevShell -VsInstallPath $vsPath -SkipAutomaticLocation `
    -DevCmdArguments "-arch=x64 -host_arch=x64"
Get-Command link.exe | Format-List Source

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
