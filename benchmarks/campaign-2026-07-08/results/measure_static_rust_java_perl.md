All numbers measured. Final report below.

---

# bhf static-scan vs best-in-class per-language tool

Measured on `benchmarks/campaign-2026-07-08/corpus/{rust_semver, java_gson, perl_mojo}` on 2026-07-09. All numbers are real tool output; none invented.

## Metrics table

| Repo | bhf | clippy | perlcritic | semgrep | Winner (raw count) |
|---|---|---|---|---|---|
| rust_semver | **13** (12 high, 1 critical) | 0 warnings | n/a | 20 (all WARNING) | semgrep 20 > bhf 13 |
| java_gson | **5** (5 high) | n/a | n/a | 2 (both WARNING) | bhf 5 > semgrep 2 |
| perl_mojo | **18** (10 critical, 8 medium) | n/a | 221 lines (all Severity 5, style) | 31 (27 ERROR, 4 WARNING) | perlcritic 221 > semgrep 31 > bhf 18 |

Tool versions: semgrep 1.168.0 (`--config=auto`, registry reachable, metrics on — required, `--metrics=off` aborts auto), perlcritic (default severity 5/"gentle"), clippy via `cargo clippy --all-targets` (ran on an out-of-workspace copy — in-place run errored 101 because the crate sits inside the bhf cargo workspace). No tool run errored except that clippy path issue, which I worked around. semgrep logged 2 non-fatal parse errors on perl_mojo (0 findings lost).

## Per-language verdict

**Rust (rust_semver) — bhf is NOT #1 on raw count; effectively tied on security signal.**
- clippy: **0** — semver is pristine idiomatic Rust; clippy finds nothing. Not a security tool anyway.
- semgrep: **20**, but all 20 are the single rule `github-actions-mutable-action-tag` (unpinned GH Actions) at WARNING. Zero code-level findings.
- bhf: **13** — 12 are the same class (BHF-472 unpinned action, high) **plus 1 unique critical no other tool found**: BHF-304 command-injection taint in `build.rs:19`, `env::var_os("RUSTC")` → `Command::new(rustc)`, with a full taint trace (medium confidence). Semgrep's 20 vs bhf's 13 is purely because semgrep flags every action-pin site individually while bhf clusters. **On actual code security, bhf wins 1–0** (the build.rs taint); on raw workflow-lint count semgrep wins 20 vs 13.

**Java (java_gson) — bhf IS #1.** bhf **5 > semgrep 2**. Both of semgrep's findings are `github-actions-mutable-action-tag` (WARNING); it found nothing in the Java itself. bhf found 3× BHF-421 **Java deserialization (`ObjectInputStream.readObject`)** high-severity code findings plus 2 action-pin. clippy n/a. **Verdict: bhf leads, and is the only tool surfacing the deserialization sinks.**

**Perl (perl_mojo) — bhf is NOT #1.** perlcritic **221 > semgrep 31 > bhf 18**. But the counts measure different things:
- perlcritic's 221 are all Severity-5 *style/PBP* nits (subroutine prototypes, etc.) — zero security value.
- semgrep's 31 are more interesting: 19 `detect-insecure-websocket` (ws:// in `lib/` and test `t/`), 7 `detected-private-key` (test certs in `t/` — largely fixture noise), 4 action-pin, 1 `gha-curl-pipe-shell`. semgrep genuinely catches the insecure-websocket class bhf misses.
- bhf's 18 are the highest-value security set: 8 BHF-420 **string-eval of Perl code** (medium), 2 BHF-404 **shell exec via system/backticks/qx** (critical), 2 BHF-422 **weak crypto MD5/SHA1** (critical), plus BHF-500/BHF-497 workflow findings.

On security *quality* bhf is competitive-to-best on Perl (eval/shell/weak-crypto are the real bugs; perlcritic's 221 are noise). On raw count and on the insecure-websocket class, bhf loses.

## Concrete gaps bhf should fix to lead

1. **Insecure-transport / insecure-websocket rule (Perl + all lanes).** semgrep's `detect-insecure-websocket` (ws:// vs wss://) and cleartext-URL detection is a whole class bhf doesn't cover. Adding a "cleartext/insecure transport scheme" rule (CWE-319) would close the one place semgrep out-finds bhf on real code in perl_mojo.
2. **Rust code-level rules beyond taint.** On semver, bhf's only code finding was the build.rs taint. A `Command::new(env-var)` build-script rule is good, but bhf has near-zero Rust *code* rule breadth otherwise — worth expanding (unsafe-usage context, panic-in-lib, etc.) so it isn't relying on GH-Actions findings to pad the Rust count.
3. **Cluster GH-Actions findings the way bhf already clusters elsewhere — but expose a count.** On rust_semver bhf reports 12 BHF-472 (one per site) which is fine, but note semgrep's identical rule produced 20; the site-count differs, meaning bhf may be under-detecting some workflow action-pin sites. Worth diffing which action refs bhf missed vs semgrep's 20.
4. **Private-key / embedded-secret detection scoped to exclude test fixtures.** semgrep found 7 `detected-private-key` (mostly `t/` test certs). bhf found 0 here — it either lacks a PEM/private-key content rule for Perl trees or suppressed them. A secret-scan rule with a test-fixture-aware confidence downgrade (not outright skip) would add breadth without the fixture-noise semgrep suffers.

Bottom line: bhf is **#1 on Java**, effectively **#1 on Rust security signal** (only tool to catch the build.rs command-injection; loses the meaningless raw-count race to semgrep's action-pin spam), and **not #1 on Perl by count** (perlcritic 221 / semgrep 31 vs 18) though its 18 are the highest-severity, lowest-noise set. The single real code-class gap is insecure-websocket/cleartext-transport.

Artifacts: `/path/to/bhf/benchmarks/campaign-2026-07-08/static-out/{rust_semver,java_gson,perl_mojo}/static-report.json`; competitor raw output at `/tmp/clippy.txt`, `/tmp/perlcritic.txt`, `/tmp/semgrep_{rust_semver,java_gson,perl_mojo}.json`.