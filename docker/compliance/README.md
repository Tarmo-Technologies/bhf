<!-- SPDX-License-Identifier: Apache-2.0 -->
# License compliance for the bhf container image

The image aggregates independent programs on one medium. **bhf is Apache-2.0**
and runs the bundled toolchains as **subprocesses** (mere aggregation, GPLv2 §2 /
GPLv3 §5) — it does not link their GPL code, so bhf is not placed under the GPL.
The only obligation redistributing the image creates is **making the GPL/LGPL
corresponding source available**. These files make that turnkey.

## In the built image, at `/usr/share/bhf/licenses/`

| File | Purpose |
|---|---|
| `THIRD_PARTY_NOTICES.md` | Every installed package → version → source → declared license(s). Generated from the exact package set at build. |
| `COPYLEFT-SOURCES.txt` | `source=version` for just the GPL/LGPL packages — the source-obligation list. |
| `WRITTEN-OFFER.md` | The written offer for corresponding source. **Add your contact before distributing.** |
| `fetch-sources.sh` | Downloads the matching Ubuntu source for every package in `COPYLEFT-SOURCES.txt`. |

Per-package **full** license text is retained in the image at
`/usr/share/doc/<package>/copyright` (not deleted by the build).

## Fulfilling the source offer

```sh
# On an Ubuntu 24.04 host/container with network, as root:
docker run --rm -v "$PWD/src":/out ubuntu:24.04 bash -c '
  apt-get update && apt-get install -y --no-install-recommends ca-certificates
  ' # (or just run fetch-sources.sh from the image)

# Simplest: run the baked-in script from the image itself
docker run --rm --user 0 -v "$PWD/corresponding-source":/out bhf:local \
  bash /usr/share/bhf/licenses/fetch-sources.sh /usr/share/bhf/licenses/COPYLEFT-SOURCES.txt /out
```

`fetch-sources.sh` enables `deb-src` for the image's Ubuntu suites and runs
`apt-get source` for each pinned package. Because the packages are **unmodified**
Ubuntu 24.04 packages, that source *is* the corresponding source.

## Notes

- `afl++` is predominantly Apache-2.0 but its Debian package includes a GPL-3+
  file (the gcc instrumentation pass) and MPL-2.0 files — so it appears in
  `COPYLEFT-SOURCES.txt`, correctly.
- The GPL compilers/tools (`gcc`, `gnat`→`gcc-13`, `gprbuild`, `gnucobol`,
  `make`, `openjdk`) and LGPL libs (`glibc`, `libcob`) carry the offer; their
  runtime exceptions (GCC RLE, Classpath) keep bhf's *outputs* unencumbered.
- To shed the GPLv3/GPLv2 **compilers**, drop the Ada, COBOL, and Fortran `apt`
  lanes from the `Dockerfile` (you keep clang for C/C++); `make`/`glibc` remain.
