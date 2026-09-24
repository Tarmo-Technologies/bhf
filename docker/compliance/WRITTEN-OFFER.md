<!-- SPDX-License-Identifier: Apache-2.0 -->
# Redistribution & corresponding-source notice (GPL / LGPL)

**bhf is distributed as source** (Apache-2.0, this repository). The project does
**not** publish prebuilt container images, so the project itself distributes no
GPL/LGPL binaries and carries no corresponding-source offer. When you run
`docker build`, the GPL/LGPL packages (gcc, glibc, make, gnat, gprbuild,
gnucobol, openjdk, afl++'s gcc-pass file, …) are delivered to *you* by Ubuntu at
build time — Ubuntu is their distributor, and its published source is their
corresponding source.

This file, and the manifests beside it, exist so that **if you choose to
redistribute the built image** (push it to a registry, ship a `docker save`
tarball to another party), you can meet the obligation you take on as its
distributor. Building the image for your own use, or on an air-gapped host you
control, is not distribution and triggers nothing.

## If you redistribute the built image

You become the distributor of its GPL/LGPL binaries and must make the
**corresponding source** available (GPLv2 §3, GPLv3 §6, LGPL). Easiest paths:

1. **Accompany** the image with source (GPLv3 §6(a) / GPLv2 §3(a)): run
   `fetch-sources.sh` once and ship its output next to the image. No ongoing
   offer to maintain.
2. **Offer** source (GPLv2 §3(b), 3 years / GPLv3 §6(c)): include a written offer
   naming *your* contact, and archive the `fetch-sources.sh` output so you can
   serve the exact versions later.

The exact packages + versions are in `COPYLEFT-SOURCES.txt`; `fetch-sources.sh`
downloads their source; full per-package license text is at
`/usr/share/doc/<package>/copyright`; a whole-image inventory is in
`THIRD_PARTY_NOTICES.md` and the SBOMs under `/usr/share/bhf/sbom/`.

> Redistributor contact (fill in if you choose the "offer" path):
> _______________________________________________
