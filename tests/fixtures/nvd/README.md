<!-- SPDX-License-Identifier: Apache-2.0 -->
# NVD import fixtures

Synthetic NVD CVE JSON 2.0 records (`CVE-2026-901xx`, not real CVEs) for
`bhf pack import-nvd` (#387): an openssl version range that holds 1.0.2t, a
CPE pinned to 1.1.1, a range that ends before 1.0.2a beside a platform that is
not vulnerable, a record with no id, two malformed CPE matches, and a
truncated file.
