#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Container entrypoint. Dispatches to the known bhf executables/helpers so that
#   docker run IMAGE auto <src> ...      -> bhf auto <src> ...
#   docker run IMAGE bhf ...             -> bhf ...
#   docker run IMAGE bhf-sweep ...       -> the 32-project sweep runner
#   docker run IMAGE bhf-daemon ...      -> the daemon
#   docker run IMAGE bash|sh             -> a shell
#   docker run IMAGE anything-else       -> treated as `bhf anything-else`
set -euo pipefail

case "${1:-}" in
    bhf | bhf-daemon | bhf-sweep | bhf-fetch-corpus)
        exec "$@"
        ;;
    sh | bash | /bin/sh | /bin/bash)
        exec "$@"
        ;;
    "" )
        exec bhf --help
        ;;
    -* )
        # a bare flag like --version / --help -> pass to bhf
        exec bhf "$@"
        ;;
    * )
        # a bhf subcommand (auto, scan, snippet, ...) or an absolute program
        if command -v "$1" >/dev/null 2>&1 && [ -x "$(command -v "$1")" ] && [[ "$1" == /* ]]; then
            exec "$@"
        fi
        exec bhf "$@"
        ;;
esac
