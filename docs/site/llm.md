<!-- SPDX-License-Identifier: Apache-2.0 -->

# LLM Assistance

bhf's scanning, target ranking, harness validation, building, fuzzing, replay and minimization are deterministic and use no model. A language model can help around those steps: plan a run, draft a candidate harness, interpret evidence, explain code, and rank diagnostic hypotheses. bhf's own checks decide whether a harness compiles, links, reaches its target, gains coverage or reproduces a finding.

The LLM commands are an opt-in build feature. Build `bhf` and `bhf-daemon` with the `llm` feature to get the `bhf llm` commands and the two extra MCP tools:

```sh
cargo build --release --locked -p bhf -p bhf-daemon --features bhf/llm,bhf-daemon/llm
```

Release binaries and Docker images are built without it. Their `bhf-daemon --mcp` exposes the three deterministic tools: scan, target list and finding load.

`bhf auto` never calls a model. bhf does not apply a completion to the repository, execute a model-generated command, or turn model prose into a finding. `bhf llm prompt` renders a prompt, `bhf llm assist` makes one bounded provider request, and the MCP server exposes read-only tools. You, or the host agent, decide what to do next, under the same command-review and sandbox policy used for any other change.

## What each part covers

| Capability | Scope |
|---|---|
| bhf fuzzing lanes | Sixteen: Ada, C, C++, Rust, Java, Python, Perl, Go, COBOL, Fortran, C#, JavaScript, TypeScript, Ruby, Lua, PHP |
| `bhf llm` task kinds | Run planning, harness drafting, finding analysis, code explanation, error diagnosis |
| `--language` option of `bhf llm` | Ada, C, C++ |
| MCP deterministic scan | Ada |
| MCP ranked targets and harness preflight | Ada, C, C++ |
| MCP finding loading and prompt preparation | Any language (normalized findings and evidence) |
| Build, fuzz, replay, minimization | CLI commands only; not exposed through MCP |

## Pick an integration mode

| Mode | Credentials bhf sees | Best use | Note |
|---|---|---|---|
| No model | None | Scanning, building, fuzzing, replay, minimization and reporting | Every core workflow runs offline without a model |
| MCP (`bhf-daemon --mcp`) | None | Interactive work in an MCP client session you already have open | The host session reasons and calls bhf's read-only tools |
| `--provider codex` / `claude` | None; the installed CLI uses its cached login | Automation that uses an existing subscription instead of an API key | Starts a new child session, separate from the caller's conversation |
| `--provider openai` / `anthropic` | Key read from an environment variable | CI, services, controlled model and version evaluation | Data goes to the configured remote API |
| `--provider local` | None by default | Air-gapped or data-residency-sensitive work | Needs an OpenAI-compatible endpoint (Ollama, llama.cpp, LM Studio or a gateway) |

`--provider` defaults to `codex`. Start with a status check, which prints no secrets, then make a live request:

```sh
bhf llm status --json
bhf llm test --provider codex
bhf llm test --provider claude
```

bhf never accepts an API key as a command-line value, where it would leak into shell history or process listings. Have the shell, the CI secret store or a credential broker set the environment variable; do not paste a real key into the example below. API providers need an explicit `--model`, because bhf does not pin a model name that will age:

```sh
# OPENAI_API_KEY is already set in this process environment
bhf llm test --provider openai --model '<openai-model-id>'

# ANTHROPIC_API_KEY is already set in this process environment
bhf llm test --provider anthropic --model '<anthropic-model-id>'
```

OpenAI uses the Responses API and Anthropic the Messages API. `--base-url` points either at an organization gateway. Use `--api-key-env NAME` when the key is in a different environment variable.

| Provider option | Default | Meaning |
|---|---|---|
| `--model` | none (session CLIs use their configured default) | Model identifier; required for `openai`, `anthropic` and `local` |
| `--base-url` | provider default | Gateway or local server URL |
| `--api-key-env` | `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | Environment variable holding the key |
| `--timeout-secs` | `180` | Provider wall-clock timeout |
| `--max-output-tokens` | `4096` | Output-token cap for HTTP providers |
| `--bin` | `codex` / `claude` on `PATH` | Session CLI executable |

For a local server:

```sh
# Ollama's default OpenAI-compatible endpoint:
bhf llm test --provider local --model '<installed-model>'

# llama.cpp, LM Studio, or another endpoint:
bhf llm test --provider local --model '<served-model>' \
  --base-url http://127.0.0.1:8080/v1
```

For harness and root-cause work, use the strongest coding and reasoning model you have measured; a smaller model is usually enough for report summarization and first-pass clustering. You choose the model: evaluate it on representative targets, and compare the deterministic build, reachability, coverage and triage outcomes rather than the quality of its prose.

## Recommended: use the current session through MCP

Build the daemon and register its absolute path with your MCP client. A default build serves the three deterministic tools; add `--features llm` for `bhf_prepare_assistance` and `bhf_preflight_harness`:

```sh
cargo build --release --locked -p bhf-daemon --features llm

codex mcp add bhf -- \
  /absolute/path/to/bhf/target/release/bhf-daemon --mcp

claude mcp add --scope user bhf -- \
  /absolute/path/to/bhf/target/release/bhf-daemon --mcp
```

Restart the client, or open a new session, after registration. The server uses MCP stdio framing and exposes these tools:

| MCP tool | Build | Input | Result |
|---|---|---|---|
| `bhf_scan` | default | repository `path` | Deterministic Ada structure summary |
| `bhf_list_targets` | default | `path`, optional positive `top` | Ranked Ada/C/C++ targets, with total and truncation metadata |
| `bhf_load_findings` | default | findings directory, optional positive `top` | Bounded normalized finding records for triage |
| `bhf_prepare_assistance` | `llm` | `kind`, optional question, target, language and evidence | Injection-aware task prompt; MCP kinds use underscores (`plan_run`, `generate_harness`, `analyze_findings`, `explain_code`, `diagnose_error`) |
| `bhf_preflight_harness` | `llm` | target symbol, Ada/C/C++ language, candidate source | Structural checks only; it does not compile, link or run the harness |

All tools advertise read-only, non-destructive, idempotent, closed-world annotations. Check the registration from a shell before restarting the host:

```sh
codex mcp get bhf
claude mcp get bhf
```

The MCP structured scan covers Ada. The ranked-target inventory and harness preflight cover Ada, C and C++. If `top` is omitted, the target and finding tools use a default derived from the MCP message budget. Target discovery keeps only the best candidates as it goes, and both responses report total and truncation metadata; set a positive `top` for a different breadth. For the other language lanes, run the bhf CLI commands and pass their bounded artifacts to the session for explanation or diagnosis.

In this mode the MCP host's model does the reasoning, so no API token is needed. The bhf server calls no model and never receives the host's credential. Long-running or mutating operations (`auto`, `build`, `fuzz`, replay, minimization) stay explicit CLI actions, so approval, logs and resource budgets stay visible.

An agent may read bounded evidence and propose the next step; bhf itself runs no autonomous loop. If a host agent may run CLI commands, its own approval policy governs those shell actions, not the MCP tool metadata. In particular, `--probe-build`, `--build-command`, `--run-untrusted` and `--unsafe-search-and-run-build-commands` can execute repository-controlled build logic, and need the same explicit trust decision whether a person or a model suggested them.

## Workflow audit

| Stage | Give the model | Ask it to | Deterministic check that decides |
|---|---|---|---|
| Run planning | language and build inventory, SLOC, ranked targets, machine RAM and CPU, time budget | propose the cheapest useful sequence, concurrency, limits and stop conditions | read `--help`; run `scan` / `list targets`, then a bounded pilot before a whole-tree campaign |
| Harness generation | exact declaration or signature, callers, headers or specs, build command, target metadata | draft a candidate and list the compile and link inputs it needs; name missing facts | `generate-harness`, `build`, then a short fuzz run with observed target coverage |
| Build or link failure | exact command, stdout and stderr, generated source, symbols and libraries | quote the decisive diagnostic, rank hypotheses, propose one discriminating test at a time | rerun the exact command; inspect symbols and link order; accept only a clean, repeatable build |
| Harness or fuzz failure | run manifest, harness, crash or hang output, coverage progression, resource settings | separate harness defects, target behaviour, environment gaps and budget exhaustion | replay, coverage counters, sanitizer output, timeout and RSS evidence, and a controlled rerun |
| Finding analysis | normalized `finding.json`, minimized input, replay output, nearby code | cluster likely duplicates, explain the input-to-sink flow, label uncertainty, prioritize follow-up | replay, minimize and differential results, and bhf's reachability and actionability fields |
| Code explanation | focused source around the target and its callers, not a 10M-SLOC dump | explain state, guards, dataflow, dangerous sinks and candidate seeds or dictionaries, with citations | source review plus instrumented observations; reject invented paths or line numbers |
| Reporting | validated findings and their reproducer evidence | write explanations and remediation context for the audience | the generated report fields and reproducer artifacts stay authoritative |

The loop that works best is driven by evidence:

1. Let bhf discover and rank targets, or reproduce the problem.
2. Give the model the smallest relevant source and the exact artifacts, not the whole repository.
3. Ask for hypotheses and a verification checklist.
4. Run one deterministic discriminating test.
5. Feed the new result back, and stop when the evidence settles the question.

This keeps context cost and the risk of invented answers down, and works on large trees where sending the repository to a model would be slow, expensive and possibly a data-handling violation.

## Practical agent workflows

### Plan a large or memory-constrained run

Start with a deterministic inventory and a no-build plan. Save compact artifacts instead of sending a whole 10M+ SLOC tree to a model:

```sh
bhf sloc path/to/tree --out bhf-sloc.json
bhf auto path/to/tree --dry-run --max-targets 200 --jobs 1 \
  --rss-limit-mb 1536 > bhf-dry-run.txt
bhf llm prompt --task plan-run \
  --question 'Plan a one-hour pilot for an 8 GiB host; preserve discovery depth' \
  --input bhf-sloc.json --input bhf-dry-run.txt
```

Have the model choose explicit budgets and stop conditions from documented flags. Confirm them with `bhf auto --help`, then run a bounded pilot. Peak memory depends on target RSS, sanitizer cost, compiler concurrency and report size, so do not ask a model to infer it from SLOC alone.

### Generate or repair a harness

Use bhf's deterministic generation first. A model helps most with a wrapper, an unusual lifecycle, or a diagnostic the repair loop could not resolve:

```sh
bhf list targets path/to/source.cpp --format json --top 20 > targets.json
bhf generate-harness path/to/source.cpp --target parse_packet \
  --output generated_harnesses
bhf llm prompt --task generate-harness --language cpp \
  --target-symbol parse_packet --input targets.json \
  --input generated_harnesses/<harness-id>/main.cpp \
  --input bhf_work/auto/run.json
```

`bhf llm assist` and the MCP preflight return advice; neither writes the proposed harness into the work tree. Review and integrate a candidate deliberately, run `bhf_preflight_harness` when you use MCP, then use the real compiler and linker and a short fuzz run. A reference to the target in source does not show that the call survived optimization or was reached; require observed target or coverage evidence.

### Analyze findings and write code-specific explanations

Make the evidence reproducible before asking for prose:

```sh
bhf replay --finding bhf_work/results/findings/F-0001
bhf minimize --finding bhf_work/results/findings/F-0001
bhf explain --work-dir bhf_work --finding-id F-0001
bhf llm assist --provider local --model '<served-model>' \
  --task analyze-findings \
  --question 'Separate reproduced facts from exploitability hypotheses' \
  --input bhf_work/results/findings/F-0001/finding.json \
  --input bhf_work/auto/run.json
```

For `explain-code`, provide the target, its callers, the relevant type declarations, and the smallest source window that contains the observed path. Ask for citations to evidence labels and line numbers. Treat invented symbols, paths, flags and line numbers as a failed answer.

### Root-cause bhf failures

Classify the failing stage before asking for a fix:

| Stage | Evidence to capture | Useful deterministic test |
|---|---|---|
| Discovery | source path and encoding, `--list-targets` output, exclusion and config flags | rerun with `--fresh-discovery`; check `--include-dir`/`--exclude-dir` and the language filter |
| Harness generation | target signature, declarations, callers, generated source | compare the selected file, line and symbol with `list targets`; run the MCP structural preflight for Ada/C/C++ |
| Compile | the complete compiler command and the first decisive diagnostic | rerun the exact command; check the dialect, include paths, generated headers and type completeness |
| Link | the complete linker command, undefined or duplicate symbols, library order | inspect symbols and translation-unit and library inputs; add one real input at a time |
| Fuzz startup | run manifest, child stderr, exit status, timeout and RSS settings | replay the seed directly; separate a loader or toolchain failure from a target failure |
| Fuzz effectiveness | executions, coverage progression, target-reachability and stub metadata | short controlled reruns that change one seed, dictionary or pass; reject stub-only clean results |
| bhf internal error | stderr plus the `bug-report.json` that `--debug` enriches | reproduce with the smallest tree and command, and keep the original report |

Ask `diagnose-error` to quote the decisive diagnostic, rank hypotheses and propose one discriminating test at a time. An edit that changes several variables at once does not identify the root cause, even when it builds.

## CLI assistance workflows

`bhf llm prompt` only renders the bounded task prompt, for manual review or for pasting into a session you already have:

```sh
bhf llm prompt --task diagnose-error \
  --question 'Why is the target missing at link time?' \
  --input bhf-auto.stderr \
  --input bhf_work/harnesses/<harness-id>/main.cpp
```

Capture the exact diagnostic first with `bhf auto ... --verbose 2> bhf-auto.stderr`. Build and link outcomes are kept in `auto/run.json` and in each target's `harnesses/<id>/result.json`; bhf writes no separate `build/link.log`.

`bhf llm assist` renders the same prompt and sends it to a provider:

```sh
bhf llm assist --provider claude --task analyze-findings \
  --question 'Cluster these findings and give replay checks' \
  --input bhf_work/auto/run.json \
  --input bhf_work/results/findings/example/finding.json

bhf llm assist --provider local --model '<served-model>' \
  --task generate-harness --target-symbol parse_packet --language cpp \
  --input include/parser.hpp --input src/parser.cpp
```

The task names are `plan-run`, `generate-harness`, `analyze-findings`, `explain-code` and `diagnose-error`.

The `--language` option and the MCP harness preflight recognize Ada, C and C++. For the other lanes, use focused evidence with `explain-code` or `diagnose-error`, and keep the lane's own harness, build and fuzz path authoritative.

## Memory, privacy, and failure boundaries

Provider stdout and stderr, HTTP responses, CLI evidence, MCP messages and legacy daemon frames are bounded. The default bound is 1/512 of the host or cgroup RAM available at the time, clamped to 1–64 MiB. It is an input-safety budget, not the model's context window. These variables set an exact positive byte limit:

- `BHF_LLM_MAX_RESPONSE_BYTES`
- `BHF_LLM_MAX_EVIDENCE_BYTES`
- `BHF_MCP_MAX_MESSAGE_BYTES`
- `BHF_DAEMON_MAX_MESSAGE_BYTES`

Provider subprocesses stop at `--timeout-secs`, and a timed-out process tree is terminated. `--max-output-tokens` sets the HTTP providers' output-token cap.

Cloud API and authenticated-CLI modes can send prompts, code, logs and findings to their provider. Check the target repository's classification and the provider's retention policy first. Use a local model, or none, for air-gapped or restricted data. Treat repository text, logs and finding content as untrusted data that can carry prompt injection, and give a model-generated command the same review and sandboxing as a command a person wrote.

Evidence can also contain credentials that belong to the target under test. Run the source and binary secret checks (including BHF-429 verified-format findings), review build logs and environment dumps, and redact secrets before a cloud or authenticated-CLI request. `bhf llm status --json` reports only whether credentials are present, the executable paths and the limits; it never prints credential values. Clear provider variables from the environment when the call is complete, and review prompts, provider output and MCP transcripts as carefully as source before you commit them.

The dated [LLM and MCP validation record](../validation/2026-07-20-llm-mcp-validation.md) documents the tested session paths, the raw MCP protocol, the local mock HTTP transports, the resource measurements, and the live-provider limits of the validation host.
