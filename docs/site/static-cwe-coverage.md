<!-- SPDX-License-Identifier: Apache-2.0 -->
# Static-scanner CWE coverage matrix

This page maps what bhf's **static** analyzer (`bhf static-scan`, and `bhf auto --static`) detects, by language and CWE. A checkmark means the core scanner has at least one rule for that language and CWE; the notes below the table say how far each rule reaches. The curated precision benchmark (`benchmarks/static/`) is the release gate for representative rule behaviour, and the framework and configuration rules also have focused unit tests and sweeps over real projects.

bhf can also **fuzz-confirm** a static finding. When `bhf auto --static` runs, a static finding that a fuzzer reaches at the same site is upgraded to `fuzz_confirmed`, and one inside a function that fuzzing showed an attacker cannot reach is downgraded to `lab_only`.

## Coverage by language

| CWE | Weakness | Ada | C | C++ | Go | Rust | Java | Python | Perl | JS/TS | Config/IaC |
|---|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| CWE-78 | OS command injection | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | |
| CWE-79 | Cross-site scripting / raw HTML sink | | | | | | | | | ✅ | |
| CWE-89 | SQL injection | ✅ | | ✅ | ✅ | | ✅ | ✅ | | ✅ | |
| CWE-90 | LDAP injection | | | | | | ✅ | ✅ | | ✅ | |
| CWE-94 | Code injection (eval/exec) | | | | | | | ✅ | ✅ | ✅ | |
| CWE-117 | Log injection / log forging | | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | | | |
| CWE-1333 | User-controlled regular expression | | | | | | | | | ✅ | |
| CWE-1336 | Server-side template injection | | | | | | | ✅ | | ✅ | |
| CWE-502 | Unsafe deserialization | | | | | | ✅ | ✅ | | ✅ | |
| CWE-601 | Open redirect | | | | ✅ | | ✅ | ✅ | | ✅ | |
| CWE-611 | XXE (untrusted XML -> unhardened parser) | | ✅ | ✅ | | | ✅ | ✅ | | ✅ | |
| CWE-915 | Mass assignment | | | | | | | | | ✅ | |
| CWE-943 | NoSQL injection | | | | | | | | | ✅ | |
| CWE-943 | GraphQL injection (dynamic `gql()` operation) | | | | | | | ✅ | | | |
| CWE-470 | Unsafe reflection (tainted class/module name) | | | | | | ✅ | ✅ | | | |
| CWE-789 | Uncontrolled allocation size (tainted alloc size) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | | | | |
| CWE-918 | SSRF (attacker-controlled URL) | | | | ✅ | ✅ | ✅ | ✅ | | ✅ | ✅⁵ |
| CWE-295 | TLS verification disabled | | | | ✅ | ✅ | ✅ | ✅ | | ✅ | |
| CWE-319 | Cleartext/downgrade transport controls | | | ✅³ | ✅ | | ✅ | ✅⁴ | ✅ | ✅⁶ | |
| CWE-22 | Path traversal | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅¹ | ✅ | ✅⁷ | |
| CWE-327 | Weak cryptography | ✅ | ✅ | ✅ | ✅ | | ✅ | ✅ | ✅ | ✅ | |
| CWE-338 | Insecure randomness (security context) | ✅ | ✅ | ✅ | ✅ | | ✅ | ✅ | ✅ | ✅ | |
| CWE-347 | Improper JWT signature verification | | | | | | ✅ | ✅ | | ✅ | |
| CWE-352 | CSRF protection disabled | | | | | | ✅ | ✅ | | ✅ | |
| CWE-693 | Protection mechanism disabled | | | ✅⁸ | | | | ✅ | | ✅⁸ | ✅⁸ |
| CWE-798 | Hardcoded secret (name heuristic + verified formats²) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| CWE-1004/614/1275 | Sensitive cookie flags | | | | ✅ | | ✅ | ✅ | | ✅ | |
| CWE-1021 | Clickjacking / frame protection disabled | | | | | | ✅ | ✅ | | ✅ | |
| CWE-1321 | Prototype pollution | | | | | | | | | ✅ | |
| CWE-120/787 | Unsafe buffer copy | | ✅ | ✅ | | | | | | | |
| CWE-134 | Uncontrolled format string | | ✅ | ✅ | | | | | | | |
| CWE-190 | Unchecked integer conversion | | ✅ | ✅ | | | | | | | |
| CWE-457 | Use of uninitialized variable | | ✅ | ✅ | | | | | | | |
| CWE-686 | `printf` argument type mismatch | | ✅ | ✅ | | | | | | | |
| CWE-703 | Exception silently discarded (`except: pass`) | | | | | | | ✅ | | | |
| CWE-917 | JNDI injection (tainted `Context.lookup` name) | | | | | | ✅ | | | | |
| CWE-197 | Numeric truncation | | ✅ | ✅ | | | | | | | |
| CWE-416 | Use-after-free (static, intraprocedural) | ✅ | ✅ | ✅ | | | | | | | |
| CWE-415 | Double free (static, intraprocedural) | ✅ | ✅ | ✅ | | | | | | | |
| CWE-15 | External control of setting (env) | | ✅ | ✅ | | | | | | | |
| CWE-250/266/269/284/668 | Excess privilege / weak isolation | | | | | | | | | | ✅ |
| CWE-494/829 | Mutable or unverified build inputs | | | | | | | | | | ✅ |
| CWE-843 | Type confusion (Ada access forged by `Unchecked_Conversion` or an address overlay; Rust `transmute`) | ✅ | | | | ✅ | | | | | |
| CWE-567 | Unsynchronized shared data (Ada task writes package state) | ✅ | | | | | | | | | |
| CWE-755 | Improper exception handling (broad Ada handler) | ✅ | | | | | | | | | |
| CWE-129 | Index/range checks suppressed (Ada `pragma Suppress`) | ✅ | | | | | | | | | |
| CWE-190 | Overflow check suppressed (Ada `pragma Suppress`) | ✅ | | | | | | | | | |
| CWE-562 | Local object escapes its frame (Ada `'Unchecked_Access`; C/C++ returned address of a local) | ✅ | ✅ | ✅ | | | | | | | |
| CWE-676 | Unsafe C function imported (Ada `pragma Import`) | ✅ | | | | | | | | | |
| CWE-401 | Resource never released (Ada `New_String`; C/C++ handle not freed or closed on every path) | ✅ | ✅ | ✅ | | | | | | | |
| CWE-532 | Secret written to a log or console | ✅ | | | | | | | | | |
| CWE-248 | Uncaught exception or panic (Ada subprogram exported to C; Rust `unwrap()`/`expect()` in a library) | ✅ | | | | ✅ | | | | | |
| CWE-460 | Exception propagates out of `Finalize` | ✅ | | | | | | | | | |

¹ Python path traversal is covered by both the taint/oracle path (`open()` on a non-literal path) and `BHF-542`, which flags `tarfile.extract()`/`extractall()` calls that omit a safe extraction filter.

² Hardcoded secrets have two layers: `BHF-423` (a name heuristic: a `password`/`token`/`api_key` lvalue assigned a literal, all languages) and `BHF-429` (**verified formats**: AWS `AKIA…`, GitHub `ghp_…`, GitLab, Google `AIza…`, Stripe, npm, Slack, SendGrid tokens, and PEM `PRIVATE KEY` blocks that carry actual key material). The format layer reports at critical or high confidence, because a match has the exact shape of a real credential.

³ C++ transport coverage includes Qt WebEngine mixed-content settings that allow active HTTP content inside HTTPS pages.

⁴ Python transport coverage includes Django deployment controls such as `SECURE_SSL_REDIRECT` defaults and HSTS max-age settings.

⁵ Config/IaC SSRF coverage includes Kubernetes probe and lifecycle-hook `host` fields that redirect kubelet-originated checks to explicit internal hosts.

⁶ JavaScript transport coverage includes Electron renderer mixed-content settings.

⁷ JavaScript path traversal coverage includes server-side file responses, Node filesystem reads, and archive-entry writes (`BHF-510` and `BHF-515`). Kubernetes hostPath, hostPort, and volume exposure are tracked under the Config/IaC isolation row because their catalog mappings are CWE-668.

⁸ Protection-mechanism coverage includes Qt WebEngine sandbox/plugin settings, Electron renderer isolation, Docker Compose security profile disables, and Django/Flask deployment controls.

## Framework and Embedded-Webview Rules

The release rule pack includes focused configuration checks of the kind SAST tools usually class as framework or platform hardening:

- **Django**: proxy HTTPS state, `SECURE_CONTENT_TYPE_NOSNIFF`, `SECURE_SSL_REDIRECT`, referrer policy, HSTS, weak password hashers, frame options, CSRF/session-cookie security, host allowlists, request-size limits, and debug mode.
- **Python security APIs**: unsafe deserialization, weak cryptography, insecure randomness in secret-generation contexts, SSRF, disabled TLS verification, permissive CORS, JWT verification disables, server-side template injection, tarfile extraction without a safe filter, and request-data log forging.
- **Qt WebEngine and Qt desktop APIs**: mixed content, local-content remote URL access, sandbox disables, JavaScript clipboard access, insecure-origin geolocation, unknown URL scheme policy, DNS prefetch, WebRTC local IP exposure, screen capture, canvas readback, hyperlink auditing, local file URL access, and plugin support across C++/QML plus selected PyQt/PySide idioms; C++ `QProcess` single-string/native-argument launches and `QSqlQuery` concatenated SQL are covered as desktop Qt SAST sinks.
- **Electron and JavaScript web stacks**: renderer web-security toggles, context isolation, Node integration, insecure mixed content, session/JWT secrets, prototype pollution, NoSQL/SQL/LDAP/XPath/template injection, reflected XSS, path traversal, dynamic code execution, and unsafe deserialization.

**Inline suppression** is honored across every rule class: a `// bhf:ignore`, `# nosec`, or `# nosemgrep` marker on a finding's line (or a standalone comment directly above it) drops it; a scoped marker (`// bhf:ignore[BHF-401,CWE-120]`) drops only the listed rules/CWEs.

**Triage and remediation.** The report groups findings by **root cause**: a taint flow keyed by (CWE, source, sink) collapses its sink sites into one `issue`, so a reviewer sees one row per defect. Each issue carries a composite **priority score** from 0 to 10 (exploitability × confidence × reachability; issues sort fix-first) and a one-line **remediation** step. `--since <git-rev>` scans only the files changed since a revision, which makes repeat CI scans of a large tree fast.

**Static reachability tier.** Every finding carries a `reachability` tier, the static counterpart of an "attacker-reachable" verdict:

- a taint flow is `source_reachable` by construction;
- a pattern finding is `source_reachable` when an input source reaches its enclosing function over the call graph;
- it is `isolated` when the tree has input sources and none reaches it;
- it is `unknown` otherwise.

The tier feeds the priority score, so a finding no attacker can reach ranks below one on an input-influenced path. The tier is a static estimate; when `bhf auto --static` runs, fuzz-confirmation replaces it.

**Durable finding identity.** Besides the line-based `fingerprint`, every finding carries an `identity` that does not depend on the line (rule, file, content key and a stable hash of the normalised code). A finding that only *moves*, because an unrelated edit shifted its line, keeps its identity, so a baseline still recognises it instead of reporting it as new. The fingerprint stays the primary baseline key for compatibility; the identity is the fallback that survives refactoring.

**Dependency (SCA) reachability.** For Go and Rust, a manifest dependency moves up the SBOM **evidence ladder** to `source_observed` only when the source imports it (a Go import path that matches the module path, or a Rust `use` or `extern crate`). A dependency listed in `go.mod` or `Cargo.toml` that is never imported stays at `resolved`, so the VEX ladder keeps its CVEs off the execution path. This is import-level reachability, computed offline.

**Interprocedural taint engine.** In the eight core static-analysis languages (Ada, C, C++, Go, Rust, Java, Python, Perl), the taint engine tracks these injection classes with sanitizer clearing, return-value summaries, branch-aware guards, loop-carried closure and field and container sensitivity. At a site it confirms, its finding replaces the lower-confidence pattern rule:

- **Command injection (CWE-78, `BHF-304`)**: a source reaches `system` / `exec.Command` / `Runtime.exec` / `os.system` / backticks / …
- **Path traversal (CWE-22, `BHF-405`)**: a source reaches a file-open (`fopen`, `os.Open`, `File::open`, `new File`, `open`, …). It fires only when a *tainted* value is the path argument, so an open of a literal path never trips it. Python archive extraction adds `BHF-542` for `tarfile.extract()` and `extractall()` calls that rely on no filter or the fully-trusted filter instead of `filter="data"`, `tarfile.data_filter`, or equivalent member validation.
- **SQL injection (CWE-89, `BHF-419`)**: a source is *built into* a query (`db.Query`, `executeQuery`, `cursor.execute`, …). A parameterized query with a tainted **bound** argument is safe and does not fire (the sink requires concat/format evidence on the line).
- **GraphQL injection (CWE-943, `BHF-545`)**: a GraphQL operation document is parsed via `gql()` from a dynamically-built string (concat / f-string / `.format(`) that carries GraphQL operation syntax (`query`/`mutation`/`subscription`). A literal document with request data bound through `variable_values` is safe and does not fire; the sink requires both the `gql()` parser call and dynamic-string evidence.
- **Log injection / log forging (CWE-117, `BHF-544`)**: a source reaches a log message argument (`syslog`, `spdlog`, Go `log.Print*`, Rust `log::*!` / `tracing::*!`, Java logger APIs, Python `logging`/logger methods). Receiver-only taint and syslog/log-level arguments stay clean, so dependency-injected logger parameters and dynamic priorities do not create findings.
- **XXE (CWE-611, `BHF-430`), LDAP injection (CWE-90, `BHF-432`), unsafe reflection (CWE-470, `BHF-434`)**: a tainted value reaches an XML parser, an LDAP filter, or a dynamic class/module load. Each fires only on a *tainted* argument (a literal parser input, filter or class name never trips it), as the SQL rule does.
- **Uncontrolled allocation size (CWE-789, `BHF-436`)**: a tainted value sizes a heap/stack allocation (`malloc`/`calloc`/`realloc`/`alloca`, `new T[]`, Go `make`, Rust `with_capacity`, Java `new byte[]`); Coverity calls this `TAINTED_SCALAR`. A `sizeof` or constant allocation is never tainted, so it never fires.

These are taint flows, so they cross function boundaries, and `bhf auto --static` can fuzz-confirm any of them. Each taint finding's SARIF result carries the source-to-sink path as standard **`codeFlows`** (ordered threadFlow steps with a message and code snippet for each hop), so GitHub code scanning and IDEs draw the dataflow that makes it a vulnerability.

**Taint sources are input APIs.** A value read from a recognised input source, such as `request.getParameter()`, `os.Getenv()`, `input()`, `os.environ`, `std::env::var()`, `$ENV{…}` or `getenv()`, is treated as attacker-controlled and seeds taint whatever the parameter is called. This covers framework code such as an HTTP handler, a CLI or an environment variable read.

The **CWE-338** row (insecure randomness) is *context-gated*. A weak PRNG (`random.*`, `math/rand`, `java.util.Random`, C `rand`/`srand`, Perl `rand`) is flagged only when the value it produces is a secret, that is, when the line names a `token`, `key`, `nonce`, `salt`, `session`, `csrf`, `otp` or `credential`. bandit's `B311` and gosec's `G404` flag every `random()`, most of which serve jitter, sampling or test data; bhf reports the security-relevant subset and never flags the cryptographically secure sources (`secrets`, `crypto/rand`, `SecureRandom`, `getrandom`, `urandom`).

The Ada rows come from a statement and scope model of each unit (`crates/static_analysis/src/ada_rules.rs`). The rule list, the false-positive patterns each rule excludes and the precision measured on 18 public Ada projects are in the [Ada rule design](../designs/2026-10-16-ada-static-rules.md). The Ada CWE-416 and CWE-415 rows are use-after-free and double free through a local alias of a deallocated access value (`BHF-437`, `BHF-410`).

The C/C++ **CWE-457, CWE-197, CWE-562 and CWE-401** rows come from an intraprocedural def-use pass that tracks a variable's declaration and definitions across a function body: an uninitialised read, a narrowing numeric cast, a returned address of a local (`BHF-549`), and a handle not released on every path (`BHF-550`).

The C/C++ **CWE-416 (use-after-free, `BHF-437`) and CWE-415 (double free, `BHF-438`)** rows are the static counterparts of the AddressSanitizer findings `BHF-202` and `BHF-204`, for code you cannot fuzz. The same def-use pass tracks a pointer that is freed (`free`, `g_free`, `kfree`, `delete`) and then dereferenced (`*p`, `p->`, `p[`) or freed again on the same straight-line path, with no reassignment or NULL-out between. The rules favour precision:

- the freed set is scoped by brace depth, so a guarded free does not reach past its `}`;
- the set is cleared at `switch` case, label, `goto` and `else` boundaries;
- indexed frees (`free(a[i])`) are not tracked, so freeing the elements of an array and then the array is not reported as a double free.

Use-after-free across functions or loop iterations is left to fuzzing, which `bhf auto` runs on what it can reach.

Beyond the taint classes in the table, the Rust rules cover command taint in `build.rs`, unsafe `transmute` (`BHF-552`) and `unwrap()`/`expect()` in library code (`BHF-553`). For general Rust lints, run clippy alongside bhf.

## Web classes that need a running application

Some web weaknesses depend on a running framework, a request lifecycle or a rendered DOM. For these, bhf checks the parts that the source states clearly, and a DAST tool against a live target covers the rest:

- **XSS.** `BHF-512` reports request data that reaches a modelled raw-HTML API in Express, the DOM, React, Vue, Svelte or Angular without visible sanitisation. Escaping rules in other template engines depend on the framework and the context.
- **CSRF.** `BHF-446` reports explicit CSRF disablement and unsafe framework configuration in the modelled stacks. Proving that every state-changing route has a valid token or origin check needs the framework's routing and middleware order, and often a live application.
- **CWE-613 (insufficient session expiration).** This is a runtime property of a framework's session store and configuration, with no source pattern to match.

## External analyzers

bhf's own rules cover the classes it can hold to a measured precision and fuzz-confirm. For framework-specific XSS and CSRF variants beyond the modelled stacks, and the wider catalogues of other SAST tools, bhf runs those tools and folds in their results. `bhf static-scan --external-tools` (and `bhf auto --external-tools`) runs the installed analyzers the licence profile allows (**gosec, Bandit, semgrep, GNATcheck**) as separate processes, never linked, and normalises their SARIF into `<out>/external-findings.json`. Each finding gets a CWE from the result, from the rule metadata (where semgrep records it) or from an adapter mapping (for example gosec `G203` and Bandit `B701` and `B308` map to CWE-79, XSS). `static-scan` reports these findings as they are; under `bhf auto` they are also fuzz-confirmed. The licence profile decides which tools run: `strict-permissive` runs none, so the default profile never starts a GPL tool.

## Extending coverage

The taint model (sinks, sources, sanitizers) is a declarative table in `crates/static_analysis/src/taint_spec.rs`; a new sink, source or sanitizer for a language is a one-line entry. Pattern rules live in the `scan_<lang>` functions of `crates/static_analysis/src/lib.rs`. Every new rule ships with a labelled case in `benchmarks/static/corpus/`, so it counts toward the published precision figure.
