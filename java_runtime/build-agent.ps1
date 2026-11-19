# SPDX-License-Identifier: Apache-2.0
#
# build-agent.sh for a Windows host (#307): bhf's JVM coverage agent and
# fork-server driver in one jar, com.bhf.* shaded with ASM 9.7, both the
# `-javaagent` (Premain-Class) and the driver main class. ASM comes from
# ASM_JAR_DIR, else the cache, else Maven Central, each jar checked against
# its pinned SHA-256 (an ASM_JAR_DIR jar is used as the operator vouches).
#
# Usage: build-agent.ps1 [OUT_JAR]   (default: $BHF_JVM_CACHE\bhf-jvm-agent.jar)
# Prints the absolute path of the built jar on success.
param([string]$Out = '')
$ErrorActionPreference = 'Stop'

$AsmVersion = '9.7'
$Pinned = @{
    "asm-$AsmVersion.jar"      = 'adf46d5e34940bdf148ecdd26a9ee8eea94496a72034ff7141066b3eea5c4e9d'
    "asm-tree-$AsmVersion.jar" = '62f4b3bc436045c1acb5c3ba2d8ec556ec3369093d7f5d06c747eb04b56d52b1'
}
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Src = Join-Path $Here 'src'
$Cache = $env:BHF_JVM_CACHE
if (-not $Cache) { $Cache = Join-Path $env:LOCALAPPDATA 'bhf\jvm' }
if (-not $Out) { $Out = Join-Path $Cache 'bhf-jvm-agent.jar' }
New-Item -ItemType Directory -Force $Cache | Out-Null
$Javac = if ($env:JAVAC) { $env:JAVAC } else { 'javac' }
$Jar = if ($env:JAR) { $env:JAR } else { 'jar' }

function Sha256Of([string]$Path) { (Get-FileHash -Algorithm SHA256 $Path).Hash.ToLowerInvariant() }

function Get-Asm([string]$Name) {
    $want = $Pinned[$Name]
    if ($env:ASM_JAR_DIR -and (Test-Path (Join-Path $env:ASM_JAR_DIR $Name))) {
        return (Join-Path $env:ASM_JAR_DIR $Name)
    }
    $cached = Join-Path $Cache $Name
    if (Test-Path $cached) {
        if ((Sha256Of $cached) -eq $want) { return $cached }
        Remove-Item -Force $cached
    }
    $artifact = $Name -replace "-$AsmVersion\.jar$", ''
    $path = "org/ow2/asm/$artifact/$AsmVersion/$Name"
    $part = "$cached.part.$PID"
    # Maven Central, then Google's mirror of it: Central's CDN has answered
    # some networks with errors for an hour at a time. The pinned digest
    # holds the jar to the same bytes whichever one serves it.
    $bases = @('https://repo1.maven.org/maven2', 'https://maven-central.storage-download.googleapis.com/maven2')
    $fetched = $false
    foreach ($base in $bases) {
        $url = "$base/$path"
        for ($try = 1; $try -le 6; $try++) {
            try {
                Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $part
                $fetched = $true
                break
            } catch {
                $failure = $_
                Start-Sleep -Seconds 5
            }
        }
        if ($fetched) { break }
    }
    if (-not $fetched) { throw "build-agent.ps1: could not fetch $path ($failure); pre-stage it in ASM_JAR_DIR" }
    $got = Sha256Of $part
    if ($got -ne $want) {
        Remove-Item -Force $part
        throw "build-agent.ps1: $url has SHA-256 $got, not ASM ${AsmVersion}'s $want"
    }
    Move-Item -Force $part $cached
    return $cached
}

$AsmCore = Get-Asm "asm-$AsmVersion.jar"
$AsmTree = Get-Asm "asm-tree-$AsmVersion.jar"

$Work = Join-Path ([System.IO.Path]::GetTempPath()) "bhf-jvm-agent-$PID"
$Classes = Join-Path $Work 'classes'
New-Item -ItemType Directory -Force $Classes | Out-Null
try {
    # Shade ASM in first, then our classes; ASM's module-info and META-INF
    # would turn javac's output directory into a module.
    Push-Location $Classes
    & $Jar xf $AsmCore; if ($LASTEXITCODE) { throw "jar xf $AsmCore failed" }
    & $Jar xf $AsmTree; if ($LASTEXITCODE) { throw "jar xf $AsmTree failed" }
    Pop-Location
    Remove-Item -Recurse -Force (Join-Path $Classes 'META-INF') -ErrorAction SilentlyContinue
    Get-ChildItem -Recurse -Filter 'module-info.class' $Classes | Remove-Item -Force
    $sources = 'Cmplog', 'Coverage', 'CoverageAgent', 'Driver', 'BhfData', 'Sink' |
        ForEach-Object { Join-Path $Src "com\bhf\$_.java" }
    & $Javac -cp "$AsmCore;$AsmTree" -d $Classes @sources
    if ($LASTEXITCODE) { throw 'javac failed' }
    $Manifest = Join-Path $Work 'MANIFEST.MF'
    Set-Content -Encoding ascii $Manifest @(
        'Manifest-Version: 1.0',
        'Premain-Class: com.bhf.CoverageAgent',
        'Agent-Class: com.bhf.CoverageAgent',
        'Can-Retransform-Classes: true',
        'Main-Class: com.bhf.Driver',
        ''
    )
    New-Item -ItemType Directory -Force (Split-Path -Parent $Out) | Out-Null
    $partJar = "$Out.part.$PID"
    & $Jar cfm $partJar $Manifest -C $Classes .
    if ($LASTEXITCODE) { throw 'jar cfm failed' }
    Move-Item -Force $partJar $Out
    (Resolve-Path $Out).Path
} finally {
    Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
}
