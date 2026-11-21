# Rust, Java and Perl static scan: bhf and per-language tools (2026-07-08 campaign)

Measured 2026-07-09 on the pinned repositories `benchmarks/campaign-2026-07-08/corpus/{rust_semver, java_gson, perl_mojo}`. All numbers are tool output.

## Metrics table

| Repo | bhf | clippy | perlcritic | semgrep | Highest raw count |
|---|---|---|---|---|---|
| rust_semver | **13** (12 high, 1 critical) | 0 warnings | n/a | 20 (all WARNING) | semgrep 20 > bhf 13 |
| java_gson | **5** (5 high) | n/a | n/a | 2 (both WARNING) | bhf 5 > semgrep 2 |
| perl_mojo | **18** (10 critical, 8 medium) | n/a | 221 lines (all Severity 5, style) | 31 (27 ERROR, 4 WARNING) | perlcritic 221 > semgrep 31 > bhf 18 |

Tool versions and settings: semgrep 1.168.0 (`--config=auto`, registry reachable, metrics on, which auto requires: `--metrics=off` aborts it); perlcritic at its default severity 5 ("gentle"); clippy through `cargo clippy --all-targets`, run on a copy outside the workspace, because the in-place run exited 101 with the crate inside the bhf Cargo workspace. No other tool run errored. semgrep logged 2 non-fatal parse errors on perl_mojo (0 findings lost).

## Per-language results

**Rust (rust_semver).**
- clippy: **0** warnings. clippy is a lint tool without a security focus.
- semgrep: **20**, all from the single rule `github-actions-mutable-action-tag` (unpinned GitHub Actions) at WARNING, with no code-level findings.
- bhf: **13**. 12 are the same class (BHF-472 unpinned action, high), plus one BHF-304 command-injection taint in `build.rs:19`, `env::var_os("RUSTC")` → `Command::new(rustc)`, with a full taint trace (medium confidence). The 20 and the 12 differ in action-pin site counts (gap 3); bhf alone reported the build.rs taint.

**Java (java_gson).** bhf reported five findings; semgrep reported two. Both semgrep findings were `github-actions-mutable-action-tag` warnings. bhf reported three BHF-421 Java deserialization findings at `ObjectInputStream.readObject`, plus two action-pin findings.

**Perl (perl_mojo).** perlcritic reported 221 lines, semgrep 31 findings, and bhf 18 findings. The counts measure different classes:
- perlcritic's 221 are all Severity-5 style checks from Perl Best Practices (subroutine prototypes and similar), with no security findings.
- semgrep's 31 include 19 `detect-insecure-websocket` findings (`ws://` in `lib/` and in the `t/` tests), 7 `detected-private-key` findings (mostly test certificates in `t/`), 4 action-pin findings, and 1 `gha-curl-pipe-shell`. semgrep reported the insecure-websocket class that bhf missed.
- bhf's 18 are security findings: 8 BHF-420 **string-eval of Perl code** (medium), 2 BHF-404 **shell exec through system/backticks/qx** (critical), 2 BHF-422 **weak crypto MD5/SHA1** (critical), plus BHF-500/BHF-497 workflow findings.

bhf concentrated on eval, shell, and weak-crypto findings. Semgrep alone reported the insecure-websocket class, and perlcritic produced the largest raw count through style checks.

## Gaps found

1. **Insecure-transport and insecure-websocket rule (Perl and all lanes).** semgrep's `detect-insecure-websocket` (`ws://` against `wss://`) and cleartext-URL detection cover a class bhf had no rule for. A cleartext/insecure transport scheme rule (CWE-319) would cover the one class where semgrep found more than bhf on perl_mojo code.
2. **Rust code-level rules beyond taint.** On semver, bhf's only code finding was the build.rs taint, and 12 of its 13 Rust findings were GitHub Actions findings. Candidate Rust code rules: unsafe-usage context and panic-in-lib.
3. **Action-pin site count.** On rust_semver bhf reported 12 BHF-472 findings, one per site, and semgrep's equivalent rule reported 20. The difference is unexplained; diffing the action references would show whether bhf misses workflow action-pin sites.
4. **Private-key and embedded-secret detection that accounts for test fixtures.** semgrep found 7 `detected-private-key` results, mostly test certificates under `t/`; bhf found none. A secret-scan rule with a lower confidence for test fixtures would add this coverage and keep the fixture context.

In this three-project measurement, bhf found the strongest Java and Rust security signals. On Perl it reported fewer findings than perlcritic and semgrep (18 against 221 and 31), concentrated on higher-severity results. Semgrep alone found the insecure-websocket/cleartext-transport class. These results describe the three pinned projects above.

Artifacts: bhf's reports are in the campaign's [`static-out/`](../static-out/) directory, one `static-report.json` per repository (rust_semver, java_gson, perl_mojo); the other tools' raw output was at `/tmp/clippy.txt`, `/tmp/perlcritic.txt` and `/tmp/semgrep_{rust_semver,java_gson,perl_mojo}.json`.
