<!-- SPDX-License-Identifier: Apache-2.0 -->
# NVD import fixtures

Synthetic NVD CVE JSON 2.0 records for `bhf pack import-nvd`. The ids (`CVE-2026-901xx`) are made up for the tests. `nvdcve-2.0-test.json` holds an openssl version range that contains 1.0.2t, a CPE pinned to 1.1.1, a range that ends before 1.0.2a beside a platform that is not vulnerable, a record with no id and two malformed CPE matches; `truncated.json` is a truncated file.
