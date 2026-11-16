# SPDX-License-Identifier: Apache-2.0
# Build the WinAFL and DynamoRIO pair bhf's WinAFL end-to-end tests run
# against, at the versions docs/site/windows.md pins: DynamoRIO 11.91.20763
# (its SHA-256 checked) and WinAFL at fd85f38548, x64 (build64) and x86
# (build32), with the Visual Studio 2022 generator.
#
#   scripts/ci/build-winafl.ps1 -Root C:\tools\bhf-winafl
#
# leaves <Root>\DynamoRIO-Windows-11.91.20763 and <Root>\winafl (the checkout
# holding build64\bin\Release and build32\bin\Release), which is what
# BHF_DYNAMORIO_PATH and BHF_WINAFL_PATH name.
param(
    [Parameter(Mandatory = $true)][string]$Root
)
$ErrorActionPreference = 'Stop'
# Invoke-WebRequest's progress display slows a large download many times over.
$ProgressPreference = 'SilentlyContinue'

$dynamorioVersion = '11.91.20763'
$dynamorioSha256 = 'EA3DAD4AE6E39228FE87B5D4D7BC3A53FAFDB6161EE5BA6A2E98FB64F8A7E0D4'
$dynamorioUrl = "https://github.com/DynamoRIO/dynamorio/releases/download/cronbuild-$dynamorioVersion/DynamoRIO-Windows-$dynamorioVersion.zip"
$winaflCommit = 'fd85f38548b14352f4b70ad414f364ea6dc1a769'

New-Item -ItemType Directory -Force -Path $Root | Out-Null
$dynamorio = Join-Path $Root "DynamoRIO-Windows-$dynamorioVersion"
if (-not (Test-Path (Join-Path $dynamorio 'bin64\drrun.exe'))) {
    $zip = Join-Path $Root "DynamoRIO-Windows-$dynamorioVersion.zip"
    $fetched = $false
    foreach ($attempt in 1..5) {
        try {
            Invoke-WebRequest -Uri $dynamorioUrl -OutFile $zip -UseBasicParsing
            $fetched = $true
            break
        } catch {
            Write-Host "download attempt $attempt failed: $_"
            Start-Sleep -Seconds (5 * $attempt)
        }
    }
    if (-not $fetched) { throw "could not download $dynamorioUrl" }
    $digest = (Get-FileHash -Algorithm SHA256 $zip).Hash
    if ($digest -ne $dynamorioSha256) {
        throw "DynamoRIO-Windows-$dynamorioVersion.zip has SHA-256 $digest, expected $dynamorioSha256"
    }
    Expand-Archive -Path $zip -DestinationPath $Root -Force
    Remove-Item $zip
}
if (-not (Test-Path (Join-Path $dynamorio 'bin32\drrun.exe'))) {
    throw "$dynamorio has no bin64\drrun.exe and bin32\drrun.exe after unpacking"
}

$winafl = Join-Path $Root 'winafl'
if (-not (Test-Path (Join-Path $winafl '.git'))) {
    git clone --quiet https://github.com/googleprojectzero/winafl $winafl
    if ($LASTEXITCODE -ne 0) { throw 'git clone of WinAFL failed' }
}
git -C $winafl fetch --quiet origin $winaflCommit
git -C $winafl checkout --quiet --force $winaflCommit
if ($LASTEXITCODE -ne 0) { throw "WinAFL has no commit $winaflCommit" }
git -C $winafl submodule update --init --recursive --quiet
if ($LASTEXITCODE -ne 0) { throw 'WinAFL submodule update failed' }

# Intel PT is a 64-bit feature of WinAFL; the x86 build leaves it out.
foreach ($build in @(
        @{ Dir = 'build64'; Arch = 'x64'; Extra = @('-DINTELPT=1') },
        @{ Dir = 'build32'; Arch = 'Win32'; Extra = @() })) {
    $dir = Join-Path $winafl $build.Dir
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    cmake -S $winafl -B $dir -G 'Visual Studio 17 2022' -A $build.Arch `
        "-DDynamoRIO_DIR=$dynamorio\cmake" -DUSE_COLOR=1 @($build.Extra)
    if ($LASTEXITCODE -ne 0) { throw "configuring WinAFL $($build.Arch) failed" }
    cmake --build $dir --config Release
    if ($LASTEXITCODE -ne 0) { throw "building WinAFL $($build.Arch) failed" }
    foreach ($binary in 'afl-fuzz.exe', 'winafl.dll') {
        $built = Join-Path $dir "bin\Release\$binary"
        if (-not (Test-Path $built)) { throw "the $($build.Arch) build made no $built" }
    }
}
Write-Host "WinAFL $winaflCommit (x64, x86) against DynamoRIO $dynamorioVersion in $Root"
