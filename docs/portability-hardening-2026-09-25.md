<!-- SPDX-License-Identifier: Apache-2.0 -->
# Portability and daemon-framing repair — 2026-09-25

Base: `30ee685cfe94138dd6d3626d3dee09b24796589f` on
`rtos-radar-fuzzing`. This is a source repair and focused regression-validation
record, not a release approval, performance benchmark, or hardware qualification.
The machine-readable observation is in
[validation/portability-2026-09-25.json](validation/portability-2026-09-25.json).

## Installer

`publish_pack_stage` on Linux now invokes `SYS_renameat2` through `libc::syscall`
rather than dynamically requiring glibc's newer `renameat2` wrapper. It retains
`RENAME_NOREPLACE` and propagates operating-system failures. There is no ordinary
rename fallback and no check-then-overwrite workaround.

Eight new tests call the actual publication helper: complete publication,
existing empty directory/inode preservation, nonempty directory preservation,
file preservation, dangling destination symlink preservation, absent source,
NUL-path rejection, and a two-publisher race with exactly one winner.

The permanent RHEL 7 ABI CI job now runs the governance library tests before its
existing offline-distribution and release build steps.

The EL7 test container reports glibc 2.17. Like other containers, it uses the
hosted runner's kernel. This proves the exercised old-userspace path, not all
physical RHEL 7 kernels/filesystems or every supported Linux architecture.
Unsupported kernel/filesystem operations still fail closed. Non-Linux
publication behavior was not changed by this repair.

## Daemon

The old compact-error regression used a fixed long ID plus a generated temporary
file path, which could exceed its 512-byte inbound-message limit on Windows.
The replacement uses a path-independent request, asserts that its serialized
body fits, asserts that the ordinary response does not fit, and exercises the
actual compact-error and subsequent-frame handling. The 512-byte test limit and
production resource limits remain unchanged.

Four additional tests cover a body exactly at the limit, a body one byte over,
duplicate Content-Length headers (including mixed-case names), and malformed
non-decimal lengths. The production reader now rejects duplicate or non-decimal
lengths rather than accepting ambiguous framing. Existing response-size and
real-source discovery tests remain present.

## Observed focused results

Actions run `36192874457`, setup revision
`0f4a3043f0aef6b98c63c4660d1627e08289449b`, tested deterministic source edits
against exact original Git blob hashes. All three validation jobs succeeded.

| Environment | Suite | Passed | Failed |
| --- | --- | ---: | ---: |
| Ubuntu 24.04 | Governance | 80 | 0 |
| Ubuntu 24.04 | Daemon | 28 | 0 |
| Ubuntu 24.04 | CI policy, Bash behavior, workflow contracts | 50 | 0 |
| Windows Server 2022 | Governance | 69 | 0 |
| Windows Server 2022 | Daemon | 27 | 0 |
| Windows Server 2022 | Platform-neutral CI acceptance policy | 27 | 0 |
| EL7-compatible container / glibc 2.17 | Governance | 80 | 0 |

The platform-specific Rust counts differ because the code and new Linux
publication tests use platform configuration attributes. No native tests were
reported ignored. The Linux and Windows source patches were compared and were
identical after newline normalization. Downloaded artifact ZIPs were verified
against GitHub's reported SHA-256 digests; their IDs and digests are in the JSON
observation. GitHub's temporary artifact retention is not a long-term archive.

The tested edits were materialized as Git tree
`1f0b542592abe021ffb5cb04c832391e73e20c8f` in commit
`22467267adeb99c6c69867bdef8dcac5c8bb77b2`. The publishing job's final ref update
failed because its Actions token did not have workflows permission. Accordingly,
the overall helper workflow is **failed**, despite its successful test jobs.
The source tree was retrieved and reviewed through the connected GitHub access;
the development-branch update uses that reviewed tree plus documentation only.
No additional permissions were granted to the Actions token.

The one-shot transformation script and temporary validation workflow are absent
from the resulting source tree. Their staging history is not needed by BHF.

## Earlier validation attempt

Run `36192503518` also passed the native Linux, Windows, and EL7 tests, but its
extra Windows invocation of the Linux CI Bash/mock suite failed (7 assertion
failures and 22 subtest errors). The production CI policy jobs run on Ubuntu.
The follow-up retained all 50 tests there and separately ran the 27
platform-neutral policy tests on Windows. No native Rust test or permanent CI
acceptance requirement was disabled to obtain the results above.

## Reproduction and remaining acceptance work

On a supported Rust host, run `cargo test --locked -p governance --lib` and
`cargo test --locked -p bhf-daemon --lib`. The full CI workflow retains its
platform matrix and now includes governance tests inside the pinned EL7 image.
The CI policy test commands and Linux shell-fixture scope are documented in
[ci-acceptance.md](ci-acceptance.md).

Focused crate tests do not establish a successful full workspace run, complete
release-binary ABI validation, all advertised platform smoke tests, trustworthy
release publication, operational load tolerance, or any embedded target's
representativeness. The separate release workflow still needs exact-revision
acceptance enforcement, and branch protection is unchanged by this repair.
No release, main-branch merge, hardware run, or enterprise certification was
performed as part of these focused validations.
