#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Benign compiler/runtime checks for every full-image language. No campaigns,
# downloads, target projects, or intentionally faulty inputs are involved.
set -euo pipefail
[[ "$(id -u)" == 10001 ]]
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
cd "$stage"
source /usr/local/share/bhf/language-selection.sh
selected="$(bhf_resolve_languages "${1:-all}")"
has() { bhf_has_language "$selected" "$1"; }
[[ "$(cat /usr/local/share/bhf/selected-languages.txt)" == "$selected" ]]
# Check genuine ecosystem exclusion, allowing the documented operational
# Python/Perl and native-linking dependencies shared by other lanes/AFL++.
check_tools() {
  local enabled="$1" tool
  shift
  for tool in "$@"; do
    if command -v "$tool" >/dev/null 2>&1; then
      [[ "$enabled" == yes ]] || { echo "unselected toolchain present: $tool" >&2; exit 1; }
    else
      [[ "$enabled" == no ]] || { echo "selected toolchain absent: $tool" >&2; exit 1; }
    fi
  done
}
for lane in rust go java ada cobol fortran csharp ruby lua php; do
  enabled=no
  if has "$lane"; then enabled=yes; fi
  case "$lane" in
    rust) check_tools "$enabled" rustup rustc cargo ;;
    go) check_tools "$enabled" go ;;
    java) check_tools "$enabled" java javac mvn ;;
    ada) check_tools "$enabled" gnatmake gprbuild ;;
    cobol) check_tools "$enabled" cobc ;;
    fortran) check_tools "$enabled" gfortran ;;
    csharp) check_tools "$enabled" dotnet ;;
    ruby) check_tools "$enabled" ruby ;;
    lua) check_tools "$enabled" lua5.4 ;;
    php) check_tools "$enabled" php ;;
  esac
done
enabled=no
if has javascript || has typescript; then enabled=yes; fi
check_tools "$enabled" node
enabled=no
if has typescript; then enabled=yes; fi
check_tools "$enabled" esbuild
echo "Selection receipt and toolchain exclusions verified: $selected"
export XDG_CACHE_HOME="$stage/cache" GOCACHE="$stage/go-cache" GOMODCACHE="$stage/go-mod"
export DOTNET_CLI_HOME="$stage/dotnet" GOENV=off GOPROXY=off GOSUMDB=off GOMAXPROCS=2
if has c; then
printf '%s\n' '#include <stdio.h>' 'int main(void) { puts("C ready"); return 0; }' > smoke.c
clang smoke.c -o c-smoke && ./c-smoke
fi

if has cpp; then
printf '%s\n' '#include <iostream>' 'int main() { std::cout << "C++ ready\n"; }' > smoke.cpp
clang++ smoke.cpp -o cpp-smoke && ./cpp-smoke
fi

if has ada; then
printf '%s\n' 'with Ada.Text_IO; procedure Smoke is begin Ada.Text_IO.Put_Line ("Ada ready"); end Smoke;' > smoke.adb
gnatmake -q smoke.adb && ./smoke
fi

if has rust; then
printf '%s\n' 'fn main() { println!("Rust ready"); }' > smoke.rs
rustup run "$BHF_RUST_NIGHTLY" rustc smoke.rs -o rust-smoke && ./rust-smoke
fi

if has go; then
printf '%s\n' 'package main' 'import "fmt"' 'func main() { fmt.Println("Go ready") }' > smoke.go
go build -o go-smoke smoke.go && ./go-smoke
fi

if has java; then
printf '%s\n' 'public class Smoke { public static void main(String[] args) { System.out.println("Java ready"); } }' > Smoke.java
javac Smoke.java && java Smoke
fi

if has python; then
python3 -c 'import sys; assert hasattr(sys, "monitoring"); print("Python ready")'
fi

if has perl; then
perl -e 'print "Perl ready\n";'
fi

if has fortran; then
printf '%s\n' 'program smoke' 'print *, "Fortran ready"' 'end program smoke' > smoke.f90
gfortran smoke.f90 -o fortran-smoke && ./fortran-smoke
fi

if has cobol; then
printf '%s\n' 'identification division.' 'program-id. smoke.' 'procedure division.' 'display "COBOL ready".' 'stop run.' > smoke.cob
cobc -x -free smoke.cob -o cobol-smoke && ./cobol-smoke
fi

if has csharp; then
mkdir cs empty-feed
cat > cs/smoke.csproj <<'XML'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework></PropertyGroup>
  <ItemGroup><PackageReference Include="SharpFuzz" Version="2.3.0" /></ItemGroup>
</Project>
XML
printf '%s\n' 'class Program { static void Main() { System.Console.WriteLine("CSharp ready"); } }' > cs/Program.cs
dotnet build cs/smoke.csproj "-p:RestoreSources=$stage/empty-feed" \
  -p:RestoreAdditionalProjectSources= -p:NuGetAudit=false --nologo -v quiet
dotnet cs/bin/Debug/net8.0/smoke.dll
# A missing staged package must fail locally, without retrying public feeds.
rm -rf cs/obj
if NUGET_PACKAGES="$stage/empty-packages" dotnet build cs/smoke.csproj \
  "-p:RestoreSources=$stage/empty-feed" -p:RestoreAdditionalProjectSources= \
  -p:NuGetAudit=false --nologo -v quiet > missing-nuget.log 2>&1; then
  echo 'empty NuGet cache unexpectedly succeeded' >&2
  exit 1
fi
grep -q NU1101 missing-nuget.log
echo 'CSharp empty cache denied'
fi

if has javascript; then
node -e 'console.log("JavaScript ready")'
fi

if has typescript; then
printf '%s\n' 'const result: string = "TypeScript ready"; console.log(result);' > smoke.ts
esbuild smoke.ts --platform=node --outfile=smoke.js && node smoke.js
fi

if has lua; then
lua5.4 -e 'print("Lua ready")'
fi

if has php; then
php -r 'if (!extension_loaded("pcov")) { fwrite(STDERR, "PHP pcov coverage extension absent\n"); exit(1); } echo "PHP ready\n";'
fi

if has ruby; then
ruby -e 'require "rexml/document"; require "net/imap"; require "webrick"; require "zlib"; require "cgi"; require "resolv"; abort unless CGI.escape("<") == "%3C" && Resolv::IPv4.create("127.0.0.1").to_s == "127.0.0.1"; {"cgi"=>"0.5.2", "resolv"=>"0.7.2", "zlib"=>"3.2.3"}.each { |n,v| abort("incorrect loaded gem: " + n) unless Gem.loaded_specs[n].version.to_s == v }; puts "Ruby ready"'

fi
