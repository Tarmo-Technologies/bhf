# SPDX-License-Identifier: Apache-2.0
"""Render a trade-study JSON (from trade_study.py) into a Markdown report.

Reads the raw rows + aggregated summary and emits per-target comparison tables,
a cross-target rollup (which engine leads on crash speed, coverage, throughput),
and the honest caveats. Pure rendering — no measurement — so it can be re-run on
any completed or in-progress evidence file.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ENGINE_LABEL = {
    "bhf": "BHF (builtin)",
    "aflpp": "AFL++ 5.03c",
    "libfuzzer": "libFuzzer",
    "honggfuzz": "honggfuzz",
}
CASE_DESC = {
    "magic_byte": "2-byte sync + length gate → stack OOB (st24-style)",
    "const_gate": "multi-byte constant gate → bug",
    "len_field": "length-field record parse → bug",
    "redqueen_int": "magic 32-bit integer comparison → bug (cmplog/redqueen probe)",
}


def fmt(v, suffix=""):
    if v is None:
        return "—"
    if isinstance(v, float):
        return f"{v:g}{suffix}"
    return f"{v}{suffix}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    d = json.loads(args.input.read_text())
    rows = d["rows"]
    summary = d["summary"]
    cfg = d["config"]
    engines = cfg["engines"] if isinstance(cfg["engines"], list) else list(ENGINE_LABEL)
    cases = list(summary)

    out = []
    out.append("<!-- SPDX-License-Identifier: Apache-2.0 -->")
    out.append(
        "# Multi-engine fuzzing trade study — BHF vs AFL++ vs libFuzzer vs honggfuzz\n"
    )
    out.append(
        f"Generated: {d.get('generated_utc', '?')} · elapsed {d.get('elapsed_s', '?')}s · "
        f"{len(rows)} raw trial rows.\n"
    )
    host = d.get("host", {})
    out.append(
        f"**Host:** {host.get('cpu', '?')} ({host.get('nproc', '?')} cores; "
        f"each campaign pinned to one core via taskset).\n"
    )
    out.append(
        f"**Budget:** {cfg.get('budget')}s wall per trial · **trials:** {cfg.get('trials')} "
        f"per (engine,target) · **max_len:** {cfg.get('max_len')} · "
        f"identical zero-seed corpus for every engine.\n"
    )

    tv = d.get("tool_versions", {})
    out.append("## Tool versions\n")
    out.append(f"- **BHF:** `{(tv.get('bhf') or '?').strip()}`")
    out.append(
        f"- **AFL++:** pinned 5.03c build at `{tv.get('afl_fuzz_dir', '?')}` "
        f"(compiler: `{(tv.get('afl_cc') or '?').splitlines()[0] if tv.get('afl_cc') else '?'}`)"
    )
    out.append(
        f"- **libFuzzer / clang:** `{(tv.get('clang') or '?').splitlines()[0] if tv.get('clang') else '?'}`"
    )
    out.append(f"- **honggfuzz:** source build at `{tv.get('honggfuzz_dir', '?')}`\n")

    out.append("## Methodology\n")
    out.append(
        "- **Targets:** controlled coverage-gated bug fixtures — a human-audited bug sits behind "
        "a gate (a magic value / length field) so the metric is how well each engine's mutator "
        "reaches deep, guarded code. Each fixture defines one `target_one_input(data,size)`; every "
        "engine drives the SAME source.\n"
        "- **Independent crash oracle:** each engine's saved crash artifact AND its final corpus are "
        "replayed through one ASan+UBSan binary the engines never see; only oracle-confirmed crashes "
        "count. This neutralizes each engine's own crash classifier (honggfuzz's persistent+ASan loop, "
        "for instance, keeps the crasher in its corpus without flagging it).\n"
        "- **Engine-neutral coverage:** every engine's final corpus is merged through ONE shared "
        "libFuzzer-sancov binary (`-merge=1`), so `edges`/`features` use identical instrumentation and "
        "are directly comparable — not each engine's own counter.\n"
        "- **Time-to-first-crash (TTFC):** wall seconds from campaign start to the first "
        "oracle-confirmed crash artifact, polled at 10 ms. Only engines that write a native crash "
        "artifact get a TTFC (honggfuzz reports crash REACHABILITY via the corpus backstop, no TTFC).\n"
        "- **Setup/build time is separated from campaign time.** Native exec/s is recorded but is "
        "**not** cross-engine comparable (each engine defines an execution differently).\n"
    )

    for case in cases:
        out.append(f"## Target: `{case}`\n")
        out.append(f"_{CASE_DESC.get(case, '')}_\n")
        out.append(
            "| Engine | Crash-find rate | Median TTFC (s) | Min TTFC (s) | "
            "Median cov edges | Max cov edges | Median native exec/s | Median build (s) |"
        )
        out.append("|---|---|---|---|---|---|---|---|")
        for e in engines:
            s = summary[case].get(e)
            if not s:
                continue
            out.append(
                f"| {ENGINE_LABEL.get(e, e)} | {s['crash_find_rate']:.0%} "
                f"({int(round(s['crash_find_rate'] * s['trials']))}/{s['trials']}) "
                f"| {fmt(s['median_ttfc_s'])} | {fmt(s['min_ttfc_s'])} "
                f"| {fmt(s['median_cov_edges'])} | {fmt(s['max_cov_edges'])} "
                f"| {fmt(s['median_native_execs_per_s'])} | {fmt(s['median_build_s'])} |"
            )
        out.append("")

    # Cross-target rollup.
    out.append("## Cross-target rollup\n")
    out.append("| Target | Fastest confirmed crash | Best common coverage |")
    out.append("|---|---|---|")
    for case in cases:
        best_ttfc = None
        best_ttfc_e = None
        best_cov = None
        best_cov_e = None
        for e in engines:
            s = summary[case].get(e)
            if not s:
                continue
            if s["median_ttfc_s"] is not None and (
                best_ttfc is None or s["median_ttfc_s"] < best_ttfc
            ):
                best_ttfc, best_ttfc_e = s["median_ttfc_s"], e
            if s["median_cov_edges"] is not None and (
                best_cov is None or s["median_cov_edges"] > best_cov
            ):
                best_cov, best_cov_e = s["median_cov_edges"], e
        ttfc_s = (
            f"{ENGINE_LABEL.get(best_ttfc_e, '—')} ({fmt(best_ttfc)}s)"
            if best_ttfc_e
            else "— (none solved)"
        )
        cov_s = (
            f"{ENGINE_LABEL.get(best_cov_e, '—')} ({fmt(best_cov)} edges)"
            if best_cov_e
            else "—"
        )
        out.append(f"| `{case}` | {ttfc_s} | {cov_s} |")
    out.append("")

    # Aggregate crash-find across all targets.
    out.append("### Overall crash-find reliability (all targets pooled)\n")
    out.append("| Engine | Confirmed crashes / trials | Rate |")
    out.append("|---|---|---|")
    for e in engines:
        sub = [r for r in rows if r["engine"] == e]
        conf = sum(1 for r in sub if r["crash_confirmed"])
        rate = conf / len(sub) if sub else 0
        out.append(f"| {ENGINE_LABEL.get(e, e)} | {conf}/{len(sub)} | {rate:.0%} |")
    out.append("")

    out.append("## Caveats\n")
    out.append(
        "- These are **controlled micro-fixtures** with planted, gated bugs — they isolate mutator "
        "reach and magic-value solving, not whole-program throughput on production code. They do not "
        "establish enterprise superiority on real targets; pair with the real-code reach study in "
        "`benchmarks/harness-parity-20/` (BHF-generated vs expert harness).\n"
        "- Single-core, one host, bounded budget. `min_ttfc` and rate are the robust signals; a single "
        "median can hide variance — the raw rows are in the evidence JSON.\n"
        "- Native exec/s differs in definition per engine and is reported for context only.\n"
        "- A licensed Mayhem comparison is out of scope (no license/environment).\n"
    )
    args.output.write_text("\n".join(out) + "\n")
    print(f"wrote {args.output} ({len(rows)} rows, {len(cases)} targets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
