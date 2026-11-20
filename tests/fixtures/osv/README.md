<!-- SPDX-License-Identifier: Apache-2.0 -->
# OSV import fixtures

Synthetic OSV records for `bhf pack import-osv`. The ids (`TEST-2026-*`)
are made up for the tests. `crates.io/` holds a range record and a batch
file with an explicit-version record, a range that ends before 0.10.0 and
three malformed records. `other/` holds a record for an ecosystem bhf does
not catalog, with a git-only range, and a truncated file.
