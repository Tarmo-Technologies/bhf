<!-- SPDX-License-Identifier: Apache-2.0 -->
# OSV import fixtures

Synthetic OSV records (`TEST-2026-*` ids, not real advisories) for
`bhf pack import-osv` (#223): a range record, a batch file holding an
explicit-version record, a range that ends before 0.10.0 and three malformed
records, a record for an ecosystem bhf does not catalog with a git-only
range, and a truncated file.
