<!-- SPDX-License-Identifier: Apache-2.0 -->
# GitLab SAST report fixtures

- `sast-report-format.json` is GitLab's security report schema for SAST, version 15.2.1, copied unchanged from <https://gitlab.com/gitlab-org/security-products/security-report-schemas> (`dist/sast-report-format.json` at tag `v15.2.1`). It is GitLab B.V.'s, under the MIT license in `LICENSE.md` beside it.
- `gl-sast-report.json` is bhf's GitLab SAST report of the golden findings document (`tests/fixtures/golden_results`). `crates/results/tests/golden.rs` keeps it current (`BHF_UPDATE_GOLDEN=1`), and `scripts/ci/tests/test_gitlab_sast.py` validates it against the schema.
