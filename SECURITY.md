<!-- SPDX-License-Identifier: Apache-2.0 -->
# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately**, not in a public issue or pull
request. Use GitHub's private reporting: on the repository's **Security** tab choose
**Report a vulnerability** (GitHub Security Advisories).

Include a description, the affected version/commit, and a minimal reproducer if you
have one. We aim to acknowledge a report within a few business days and will keep you
updated on remediation and disclosure timing.

## Supported versions

Security fixes target the **latest release** and `main`. Older releases are not
maintained.

## Scope

bhf's job is to analyze and fuzz **untrusted** code — scanned source trees,
manifests, corpus files, and child-process output are all treated as attacker
input by design. In scope are vulnerabilities where that untrusted input compromises
the **host running bhf** beyond bhf's stated threat model, for example:

- untrusted input to the bhf process (a scanned tree, a corpus file, a manifest,
  a `compile_commands.json`) causing memory corruption or code execution in bhf
  itself;
- a sandbox or the `bhf_runtrace_shim` LD_PRELOAD interposer failing to contain
  what it is documented to contain;
- bhf executing code from a scanned tree **without** the operator's explicit
  consent (the build-executing paths — `--build-command`, `--probe-build`,
  `--run-untrusted`, `--unsafe-search-and-run-build-commands` — require explicit
  opt-in *by design*; a path that runs tree-provided code *without* one of those flags
  would be a vulnerability).

## Out of scope

- **Findings bhf reports about other code.** A crash, taint flow, or SAST finding
  bhf produces about the target under analysis is bhf working as intended, not
  a vulnerability in bhf.
- **The deliberately unsafe, opt-in build-recovery flags.** `--build-command`,
  `--run-untrusted`, and `--unsafe-search-and-run-build-commands` execute the scanned
  tree's own build on purpose; that is documented behavior gated behind explicit
  consent, not a vulnerability.
- Missing hardening in a target you are fuzzing, or the behavior of third-party
  toolchains bhf drives as subprocesses.
