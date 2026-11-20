# SLOC counting: bhf, cloc, scc and tokei (2026-07-08 campaign)

All four tools ran over the 14-repository corpus. Numbers below are **primary-language code lines**. For the four C/C++ repositories, the comparison sums `C + C++ + C/C++ Header` for cloc, scc, and tokei. bhf folds headers into `c` or `cpp`, so its `c+cpp` values are summed on the same basis. The `bhf Δ vs cloc` column is relative to cloc, the conservative comment-aware reference used here.

| repo | primary | cloc | scc | tokei | **bhf** | bhf Δ vs cloc |
|---|---|---:|---:|---:|---:|---:|
| c_zlib | C | 30357 | 29923 | 29917 | **30368** | +0.0% |
| c_jansson | C | 14581 | 14720 | 14719 | **14581** | +0.0% |
| cpp_json | C++ | 109744 | 110974 | 110574 | **110071** | +0.3% |
| cpp_fmt | C++ | 45684 | 47413 | 47411 | **46173** | +1.1% |
| rust_ripgrep | Rust | 35402 | 37798 | 37935 | **36784** | +3.9% |
| rust_semver | Rust | 2160 | 2160 | 2160 | **2160** | +0.0% |
| go_gin | Go | 17317 | 18475 | 17868 | **18264** | +5.5% |
| go_cobra | Go | 12624 | 12897 | 12624 | **12624** | +0.0% |
| py_click | Python | 17506 | 20793 | 21399 | **17818** | +1.8% |
| py_requests | Python | 7729 | 9708 | 9256 | **7575** | −2.0% |
| java_commonslang | Java | 106409 | 106614 | 106614 | **106409** | +0.0% |
| java_gson | Java | 37430 | 37636 | 37731 | **37430** | +0.0% |
| perl_mojo | Perl | 10608 | 25647* | 25665* | **10446** | −1.5% |
| js_express | JavaScript | 15687 | 15878 | 15878 | **15756** | +0.4% |

\* scc and tokei classify Mojolicious `.pod`, `.t` and embedded template files as "Raku", which raises the Perl count to about 25.6k (plus a separate 31.9k "Raku" row in scc). cloc and bhf both report about 10.5k Perl.

## Speed (total wall time over the whole corpus)

| tool | wall time | max RSS | invocation model |
|---|---:|---:|---|
| **tokei** | **0.09 s** | 15 MB | single whole-corpus run |
| **scc** | **0.11 s** | 63 MB | single whole-corpus run |
| cloc | 4.43 s | 118 MB | single whole-corpus run |
| **bhf** | **16.5 s** | — | 14 separate `static-scan` invocations |

Speed order: **tokei ≈ scc (both about 0.1 s), then cloc (4.4 s), then bhf (16.5 s)**. tokei, scc and cloc each ran once over the whole tree. bhf ran 14 times, once per repository, because `--sloc` was a side output of each scan, and each bhf run also performed a full SAST parse and scan. The times compare these recorded invocation modes.

## Accuracy

bhf agrees with cloc within about 5% on all 14 repositories. On 8 of 14 it matches cloc within 0.0–0.5%. Where scc and tokei diverge upward (py_click +19%, py_requests +26%, ripgrep +7%), they count Python docstrings and Rust `//!` doc comments as code. bhf's language-aware comment stripping tracks cloc's conservative counts on these repositories.

## Result

For the recorded invocation modes, tokei and scc were about 150 times faster. bhf aligned more closely with cloc on Perl classification and on excluding docstrings and documentation comments from code counts.

Other differences:

- **Language-aware comment counting** that tracked cloc within the deviations above across 8 languages.
- **Dependency and build-tree pruning**: bhf applies the security scan's pruning, which excludes `.venv`, `node_modules` and vendored code; the other tools count those by default.
- **Part of the security scan**: the SLOC breakdown comes with the SAST scan (for findings-per-KLOC density), with no second tool.

## Gaps found

1. **Speed and invocation model.** Proposed: a standalone `bhf sloc <path>` (or `--sloc-only`) that skips the SAST parse, does a fast line-count pass, and counts several roots or a whole corpus in one invocation. At the time, the counts cost a full scan (16.5 s) where tokei took 0.09 s. This was the largest gap.
2. **Header attribution.** bhf folds all `.h` files into `c`, even in a C++ repository (cpp_json shows `c: 44` and everything else `cpp`), so a like-for-like comparison needs manual summing. An optional cloc-style `c_header`/`cpp_header` split, or documentation of the fold, would remove that step.

A dedicated fast SLOC path would keep the measured accuracy and address the throughput gap. At the time of this measurement, tokei was about 150 times faster, and bhf handled Perl and comments more accurately on the pinned corpus.

Relevant files: `/tmp/bhf/*_sloc.json` (bhf outputs), `/tmp/{cloc,scc,tokei}_time.txt` (timing captures).
