# SPDX-License-Identifier: Apache-2.0
#
# Build Lua 5.4 for native Windows (the Lua lane needs 5.3 or later; the
# packaged Windows builds are 5.1) from lua.org's checksum-pinned source with
# clang, which finds the MSVC toolchain by itself, and print the directory
# holding lua.exe for the caller to put on PATH.
#
# Usage: install-lua-windows.ps1 -Dest C:\tools\lua54
param([Parameter(Mandatory = $true)][string]$Dest)
$ErrorActionPreference = 'Stop'

$version = '5.4.7'
$sha256 = '9fbf5e28ef86c69858f6d3d34eccc32e911c1a28b4120ff3e84aaa70cfbf1e30'

if (Test-Path (Join-Path $Dest 'lua.exe')) {
    Write-Output $Dest
    exit 0
}
$work = Join-Path ([System.IO.Path]::GetTempPath()) "bhf-lua-$version-$PID"
New-Item -ItemType Directory -Force $work | Out-Null
try {
    $tarball = Join-Path $work "lua-$version.tar.gz"
    Invoke-WebRequest -UseBasicParsing -Uri "https://www.lua.org/ftp/lua-$version.tar.gz" -OutFile $tarball
    $got = (Get-FileHash $tarball -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($got -ne $sha256) {
        throw "lua-$version.tar.gz has SHA-256 $got, not $sha256"
    }
    & tar -xzf $tarball -C $work
    if ($LASTEXITCODE -ne 0) { throw "tar could not unpack lua-$version.tar.gz" }
    $src = Join-Path $work "lua-$version\src"
    # The interpreter: every library and core source but the compiler's.
    $sources = Get-ChildItem $src -Filter *.c | Where-Object Name -ne 'luac.c' | ForEach-Object FullName
    New-Item -ItemType Directory -Force $Dest | Out-Null
    & clang -O2 -D_CRT_SECURE_NO_WARNINGS -o (Join-Path $Dest 'lua.exe') @sources
    if ($LASTEXITCODE -ne 0) { throw "clang could not build lua.exe" }
    Copy-Item (Join-Path $work "lua-$version\doc\readme.html") (Join-Path $Dest 'readme.html')
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
Write-Output $Dest
