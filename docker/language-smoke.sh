#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Benign compiler/runtime checks for every full-image language. No campaigns,
# downloads, target projects, or intentionally faulty inputs are involved.
set -euo pipefail
[[ "$(id -u)" == 10001 ]]
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
cd "$stage"
export XDG_CACHE_HOME="$stage/cache" GOCACHE="$stage/go-cache" GOMODCACHE="$stage/go-mod"
export DOTNET_CLI_HOME="$stage/dotnet" GOENV=off GOPROXY=off GOSUMDB=off GOMAXPROCS=2
printf '%s\n' '#include <stdio.h>' 'int main(void) { puts("C ready"); return 0; }' > smoke.c
clang smoke.c -o c-smoke && ./c-smoke
printf '%s\n' '#include <iostream>' 'int main() { std::cout << "C++ ready\n"; }' > smoke.cpp
clang++ smoke.cpp -o cpp-smoke && ./cpp-smoke
printf '%s\n' 'with Ada.Text_IO; procedure Smoke is begin Ada.Text_IO.Put_Line ("Ada ready"); end Smoke;' > smoke.adb
gnatmake -q smoke.adb && ./smoke
printf '%s\n' 'fn main() { println!("Rust ready"); }' > smoke.rs
rustup run "$BHF_RUST_NIGHTLY" rustc smoke.rs -o rust-smoke && ./rust-smoke
printf '%s\n' 'package main' 'import "fmt"' 'func main() { fmt.Println("Go ready") }' > smoke.go
go build -o go-smoke smoke.go && ./go-smoke
printf '%s\n' 'public class Smoke { public static void main(String[] args) { System.out.println("Java ready"); } }' > Smoke.java
javac Smoke.java && java Smoke
python3 -c 'import sys; assert hasattr(sys, "monitoring"); print("Python ready")'
perl -e 'print "Perl ready\n";'
printf '%s\n' 'program smoke' 'print *, "Fortran ready"' 'end program smoke' > smoke.f90
gfortran smoke.f90 -o fortran-smoke && ./fortran-smoke
printf '%s\n' 'identification division.' 'program-id. smoke.' 'procedure division.' 'display "COBOL ready".' 'stop run.' > smoke.cob
cobc -x -free smoke.cob -o cobol-smoke && ./cobol-smoke
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
node -e 'console.log("JavaScript ready")'
printf '%s\n' 'const result: string = "TypeScript ready"; console.log(result);' > smoke.ts
esbuild smoke.ts --platform=node --outfile=smoke.js && node smoke.js
lua5.4 -e 'print("Lua ready")'
php -r 'echo "PHP ready\n";'
ruby -e 'require "rexml/document"; require "net/imap"; require "webrick"; require "zlib"; require "cgi"; require "resolv"; abort unless CGI.escape("<") == "%3C" && Resolv::IPv4.create("127.0.0.1").to_s == "127.0.0.1"; {"cgi"=>"0.5.2", "resolv"=>"0.7.2", "zlib"=>"3.2.3"}.each { |n,v| abort("incorrect loaded gem: " + n) unless Gem.loaded_specs[n].version.to_s == v }; puts "Ruby ready"'
