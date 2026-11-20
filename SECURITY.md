<!-- SPDX-License-Identifier: Apache-2.0 -->
# Security Policy

## Reporting a vulnerability

Report security vulnerabilities **privately**, not in a public issue or pull
request. Use GitHub's private reporting: on the repository's **Security** tab
choose **Report a vulnerability** (GitHub Security Advisories).

Include a description, the affected version or commit, and a minimal
reproducer if you have one. We aim to acknowledge a report within a few
business days and will keep you updated on remediation and disclosure timing.

## Supported versions

Security fixes target the **latest release** and `main`. Older releases are
not maintained.

## Scope

bhf analyzes and fuzzes **untrusted** code. It treats scanned source trees,
manifests, corpus files, and child-process output as attacker input. A
vulnerability is in scope when that input compromises the **host running
bhf** beyond bhf's stated threat model, for example:

- untrusted input to the bhf process (a scanned tree, a corpus file, a
  manifest, a `compile_commands.json`) causing memory corruption or code
  execution in bhf itself;
- a sandbox or the `bhf_runtrace_shim` LD_PRELOAD interposer failing to
  contain what it is documented to contain;
- bhf running the scanned tree's own build scripts, project files or code
  generators without one of the opt-in flags that allow it:
  `--build-command`, `--probe-build`, `--msbuild-evaluate`, `--run-untrusted`,
  or `--unsafe-search-and-run-build-commands`.

Fuzzing compiles the selected target code into a harness and runs it; that
needs no flag.

## Out of scope

- **Findings bhf reports about the code under analysis.** A crash, taint flow,
  or SAST finding about the target is bhf's output.
- **The opt-in build-recovery flags.** `--build-command`, `--probe-build`,
  `--msbuild-evaluate`, `--run-untrusted`, and
  `--unsafe-search-and-run-build-commands` run code from the scanned tree on
  purpose, after explicit consent. `bhf auto --help` describes each one.
- Missing hardening in a target you are fuzzing, or the behavior of
  third-party toolchains bhf drives as subprocesses.
