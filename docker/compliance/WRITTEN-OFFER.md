<!-- SPDX-License-Identifier: Apache-2.0 -->
# Redistribution materials for container candidates

This file is informational material, not a completed publisher written offer.
BHF's own code and the programs bundled into an image retain their respective
license terms. Generated manifests do not constitute a legal compliance decision.

The container candidate workflow retains:

- OS package notices and license files under `/usr/share/bhf/licenses/` and
  `/usr/share/doc/`;
- the installed OS source package/version list in `COPYLEFT-SOURCES.txt`;
- exact corresponding Ubuntu source downloads, with checksums, beside the image;
- the BHF source archive and Dockerfile, including package modifications;
- selected compiled Rust crate notices and license texts under
  `/usr/share/bhf/sbom/rust-licenses/`;
- upstream tool license material retained inside the image.

`fetch-sources.sh` fails if any requested source version cannot be retrieved. It
never replaces a missing exact version with the current package source. The
whole-image inventory and release review must account for separately installed
components as well as OS packages. A distributor using an offer instead of the
included source material needs its own completed, reviewed offer and retention
process; this file supplies neither.
