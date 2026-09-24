<!-- SPDX-License-Identifier: Apache-2.0 -->
# Written offer for corresponding source (GPL / LGPL)

This container image is a **mere aggregation** of independent programs on a
single distribution medium. **bhf** itself is licensed under **Apache-2.0** and
invokes the bundled GNU/Ubuntu toolchain packages as separate subprocesses — it
does not statically or dynamically link their GPL code into its own binaries.
Aggregating separate programs does not place bhf under the GPL (GPLv2 §2,
GPLv3 §5).

Some of the aggregated Ubuntu packages are licensed under the **GNU GPL** (v2 or
v3) or **LGPL** — principally the compilers and build tools (`gcc`, `g++`,
`gfortran`, `gnat`, `gprbuild`, `make`, `gnucobol`), the OpenJDK runtime
(GPLv2 with the Classpath Exception), and the GNU C Library (LGPL). For **every**
such package this image distributes in binary form, we make the following offer,
valid for **at least three (3) years** from the date you received this image:

> We will provide, to any third party, the complete **corresponding source code**
> for the GPL- and LGPL-licensed packages in this image, under the terms of the
> respective license (GPLv2 §3(b), GPLv3 §6, and the LGPL). Request it at the
> contact below.

## What and how

- The exact copyleft packages and their versions are listed in
  **`COPYLEFT-SOURCES.txt`** (generated at build; baked into the image at
  `/usr/share/bhf/licenses/`).
- These are **unmodified** Ubuntu 24.04 packages, so the corresponding source is
  the source Ubuntu/Canonical publishes for those exact versions. The digest-
  pinned base image makes the versions deterministic.
- **`fetch-sources.sh`** retrieves that source automatically via `apt-get source`
  on an Ubuntu 24.04 host — this is how the offer above is fulfilled.
- The **full, per-package license text** for the entire userland is retained in
  the image at `/usr/share/doc/<package>/copyright`, and a summary manifest of
  all packages is in **`THIRD_PARTY_NOTICES.md`**.

## Contact

To request the corresponding source under this offer, contact:

> **Lane Crawford**, Tarmo Technologies — lcrawford@tarmotechnologies.com

If you redistribute this image (push to a registry, ship to a customer) you become
a distributor of these GPL/LGPL binaries and inherit this obligation; either keep
this contact, substitute your own, or ship the output of `fetch-sources.sh`
alongside the image.
