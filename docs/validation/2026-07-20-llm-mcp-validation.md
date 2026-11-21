<!-- SPDX-License-Identifier: Apache-2.0 -->

# LLM and MCP validation (2026-07-20)

This validation covers the optional LLM-assistance and MCP interfaces. BHF's deterministic scanning, building, fuzzing, replay, and minimization remain the source of truth; model output is advisory.

Since b6dde09 (2026-10-04), `bhf llm` and two of the five MCP tools are built only with the `llm` feature; release binaries leave it out. See [LLM Assistance](../site/llm.md).

## Environment

- Linux host: 6 logical CPUs, 13 GiB RAM, 8 GiB swap
- BHF: optimized release build
- `codex` CLI: 0.144.6, authenticated with the existing user session
- `claude` CLI: 2.1.178, authenticated with the existing user session
- No `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` was present
- `llama-server` was installed, but no local model weights or running local API server were present

## Connection results

| Path | Result | Wall time | Maximum resident process observed |
| --- | --- | ---: | ---: |
| `bhf llm test --provider codex` | connected; 15-byte sentinel | 6.73 s | 170,392 KiB |
| `bhf llm test --provider claude` | connected; 15-byte sentinel | 3.47 s | 319,464 KiB |
| `codex` host -> BHF MCP preflight | `CODEX_READONLY_ANNOTATION_OK` | 15.46 s | not recorded |
| `claude` host -> BHF MCP preflight | `CLAUDE_BHF_MCP_OK` | 15.00 s | 346,204 KiB |
| Raw MCP initialize/list/preflight | five tools; `isError: false` | <0.01 s | 3,456 KiB |

The CLI figures include the model client process. Each is the largest single resident process observed; it is neither the BHF daemon's own footprint nor a sum over the provider's process tree.

The `codex` session's first non-interactive read-only run stopped at its approval gate, because the MCP tools lacked read-only annotations. After all five tools were marked read-only, non-destructive, idempotent, and closed-world, the final validation passed under the normal read-only sandbox with no approval bypass. The `claude` session was restricted to the one BHF MCP preflight tool during its approval-bypassed validation run.

## Protocol and regression coverage

- OpenAI Responses, Anthropic Messages, and OpenAI-compatible local HTTP wire formats are covered by local mock-server tests, including response parsing.
- Provider output, HTTP response bodies, MCP input messages, evidence files, and subprocess output have bounded, environment-overrideable capture.
- All five MCP tools advertise read-only/idempotent annotations. On this host, the ranked-target tool derived a default breadth of about 6,100 from the current message budget; its incremental top-K retention keeps only the top K candidates when a bound is active. Finding output has a separate message-budget-derived default because individual records are larger.
- BHF kills the whole process group of a timed-out CLI provider, model descendants included.
- The combined `bhf`, `bhf-daemon`, and `llm_harness_gen` all-target regression run passed, including 1,235 CLI library tests and compiled C, C++, COBOL, sanitizer, build-recovery, replay-capsule, and real miniz fixtures.
- The documentation build, SPDX check, strict-permissive license audit, `cargo deny check`, and release build passed.

## Mock-tested transports

The host had no API keys, no local model weights, and no running local model server. The OpenAI and Anthropic token-authenticated HTTP transports and the local-model transport were therefore validated at the HTTP protocol boundary with local mock servers. Run `bhf llm test` with your selected model and credentials before a production campaign.
