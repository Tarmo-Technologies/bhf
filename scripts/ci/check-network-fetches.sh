#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# check-network-fetches.sh [FILE...]: fail on a download in the Dockerfiles or
# the workflows that a transient 503 or 403 fails the build with, or whose
# bytes nothing checks. Every `curl` must pass `--retry` and every `wget`
# `--tries`, with a `sha256sum`/`sha512sum` check of what they fetched in the
# same command or one of the next three; `ADD <url>` cannot retry, so it is
# refused. With no FILE it checks Dockerfile* and .github/workflows/*.yml.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
if [ "$#" -eq 0 ]; then
  set -- "$root"/Dockerfile* "$root"/.github/workflows/*.yml
fi
status=0
for file in "$@"; do
  awk -v file="${file#"$root"/}" '
    # One logical command per backslash-continued run of lines.
    {
      line = $0
      if (pending != "") { text = pending " " line } else { text = line; start = NR }
      if (line ~ /\\$/) { sub(/\\$/, "", text); pending = text; next }
      pending = ""
      count++
      starts[count] = start
      texts[count] = text
    }
    END {
      bad = 0
      for (i = 1; i <= count; i++) {
        text = texts[i]
        stripped = text
        sub(/^[ \t]*(- )?/, "", stripped)
        if (stripped ~ /^#/) continue
        what = ""
        if (stripped ~ /^ADD[ \t].*https?:\/\//) {
          printf "%s:%d: ADD of a URL cannot retry; fetch it with curl --retry and check its digest\n", file, starts[i]
          bad = 1
          continue
        }
        # The command, not a package of that name: an option or URL follows.
        if (text ~ /(^|[^A-Za-z_-])curl[ \t]+("?-|"?https?:)/) what = "curl"
        else if (text ~ /(^|[^A-Za-z_-])wget[ \t]+("?-|"?https?:)/) what = "wget"
        else continue
        if (what == "curl" && text !~ /--retry/) {
          printf "%s:%d: curl without --retry\n", file, starts[i]; bad = 1
        }
        if (what == "wget" && text !~ /--tries/) {
          printf "%s:%d: wget without --tries\n", file, starts[i]; bad = 1
        }
        checked = 0
        for (j = i; j <= count && j <= i + 3; j++) {
          if (texts[j] ~ /sha(256|512)sum/) checked = 1
        }
        if (!checked) {
          printf "%s:%d: %s with no sha256sum/sha512sum check of what it fetched\n", file, starts[i], what
          bad = 1
        }
      }
      exit bad
    }
  ' "$file" || status=1
done
exit "$status"
