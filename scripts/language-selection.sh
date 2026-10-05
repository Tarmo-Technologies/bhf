#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Shared distribution selection/dependency resolver. Source from Bash; no eval.
BHF_ALL_LANGUAGES=c,cpp,rust,java,python,perl,go,ada,cobol,fortran,csharp,javascript,typescript,ruby,lua,php

bhf_resolve_languages() {
  local value item canonical selected=, result= language
  value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  if [[ "$value" == all ]]; then printf '%s\n' "$BHF_ALL_LANGUAGES"; return; fi
  if [[ -z "$value" || "$value" == ,* || "$value" == *, || "$value" == *,,* ]]; then
    echo 'language selection must be a nonempty comma-separated list without empty entries' >&2; return 2
  fi
  local -a entries ordered
  IFS=, read -r -a entries <<< "$value"
  IFS=, read -r -a ordered <<< "$BHF_ALL_LANGUAGES"
  for item in "${entries[@]}"; do
    case "$item" in
      c|cpp|rust|java|python|perl|go|ada|cobol|fortran|csharp|javascript|typescript|ruby|lua|php) canonical="$item" ;;
      c++|cxx|cc) canonical=cpp ;; rs) canonical=rust ;; py) canonical=python ;;
      pl) canonical=perl ;; golang) canonical=go ;; cob|cbl) canonical=cobol ;;
      f90|f|for) canonical=fortran ;; cs|'c#'|dotnet|net) canonical=csharp ;;
      js|node|nodejs|mjs|cjs) canonical=javascript ;; ts|tsx) canonical=typescript ;;
      rb) canonical=ruby ;; luajit) canonical=lua ;; php8|phtml) canonical=php ;;
      *) echo "unknown language '$item'; use all alone or a nonempty subset of $BHF_ALL_LANGUAGES" >&2; return 2 ;;
    esac
    selected+="$canonical,"
  done
  for language in "${ordered[@]}"; do
    if [[ "$selected" == *",$language,"* ]]; then result+="${result:+,}$language"; fi
  done
  printf '%s\n' "$result"
}

bhf_has_language() { [[ ",$1," == *",$2,"* ]]; }

# Native package names preserve existing distro policy. Container toolchains
# that use reviewed archives (Rust/Go/Node/Maven) are installed in Dockerfile.
# One row per language; transitive native linking tools are intentional.
bhf_language_packages() {
  local platform="$1" selection language row
  selection="$(bhf_resolve_languages "$2")" || return
  local -a languages
  IFS=, read -r -a languages <<< "$selection"
  for language in "${languages[@]}"; do
    case "$language" in
      c|cpp|rust|go|ada|cobol|fortran)
        case "$platform" in
          container) printf '%s\n' make clang llvm lld libclang-rt-18-dev ;;
          apt|rpm) printf '%s\n' make clang llvm lld ;;
          *) echo "unknown dependency platform: $platform" >&2; return 2 ;;
        esac ;;
    esac
    case "$platform:$language" in
      apt:cpp) row='g++' ;; rpm:cpp) row='gcc-c++' ;;
      container:ada|apt:ada) row='gnat gprbuild' ;; rpm:ada) row='gcc-gnat gprbuild' ;;
      container:java) row='default-jdk-headless libasm-java' ;;
      apt:java) row='default-jdk maven gradle' ;; rpm:java) row='java-17-openjdk-devel maven gradle' ;;
      container:python) row='python3 python3-dev python3-venv python3-pip' ;;
      apt:python|rpm:python) row=python3 ;;
      *:perl) row=perl ;;
      apt:go) row=golang-go ;; rpm:go) row=golang ;;
      *:cobol) row=gnucobol ;;
      container:fortran|apt:fortran) row=gfortran ;; rpm:fortran) row=gcc-gfortran ;;
      apt:javascript|apt:typescript|rpm:javascript|rpm:typescript) row='nodejs npm' ;;
      container:ruby) row='ruby ruby-dev make gcc' ;; apt:ruby|rpm:ruby) row=ruby ;;
      container:lua) row='lua5.4 liblua5.4-dev' ;; apt:lua) row=lua5.4 ;; rpm:lua) row=lua ;;
      *:php) row=php-cli ;;
      container:csharp) row=dotnet-sdk-8.0 ;;
      *) row='' ;;
    esac
    # Words here are static package names above, never caller input.
    for item in $row; do printf '%s\n' "$item"; done
  done | LC_ALL=C sort -u
}
