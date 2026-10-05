---

## SLOC Counting: bhf vs cloc / scc / tokei — Real Measured Results

All four tools ran over the 14-repository corpus. Numbers below are
**primary-language code lines**. For the four C/C++ repositories, the comparison
sums `C + C++ + C/C++ Header` for cloc, scc, and tokei. bhf folds headers into
`c` or `cpp`, so its `c+cpp` values are summed on the same basis. `bhf Δ%` is
relative to cloc, the conservative comment-aware reference used here.

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

\* scc and tokei **misclassify** Mojolicious `.pod`/`.t`/embedded template files as "Raku," increasing the Perl count to ~25.6k (plus a separate 31.9k "Raku" row in scc). cloc and bhf both report ~10.5k Perl.

### Speed (total wall over the whole corpus)

| tool | wall time | max RSS | invocation model |
|---|---:|---:|---|
| **tokei** | **0.09 s** | 15 MB | single whole-corpus run |
| **scc** | **0.11 s** | 63 MB | single whole-corpus run |
| cloc | 4.43 s | 118 MB | single whole-corpus run |
| **bhf** | **16.5 s** | — | 14 separate `static-scan` invocations |

Speed ranking: **tokei ≈ scc (both ~0.1 s) ≫ cloc (4.4 s) ≫ bhf (16.5 s)**. tokei, scc, and cloc each ran once over the whole tree, while bhf ran 14 times (once per repository) because `--sloc` is a per-scan side output. Each bhf run also performs a full SAST parse and scan. The measurements therefore compare the recorded invocation modes rather than isolated counting kernels.

### Accuracy verdict

bhf agrees with cloc within about 5% on all 14 repositories. On 8 of 14 it
matches cloc within 0.0–0.5%. Where scc and tokei diverge upward (py_click +19%,
py_requests +26%, ripgrep +7%), they count Python docstrings and Rust `//!` doc
comments as code. bhf's language-aware comment stripping tracks cloc's
conservative counts on these repositories.

### Overall result

For the recorded invocation modes, tokei and scc were about 150 times faster.
bhf aligned more closely with cloc on Perl classification and on excluding
docstrings and documentation comments from code counts.

The contextual differences were:
- **Language-aware comment counting** matching cloc-grade accuracy across 8 languages.
- **Dependency/build-tree pruning** — the same pruning as the security scan excludes `.venv`/`node_modules`/vendored code, which the others don't do by default.
- **Integrated in the security tool** — you get the SLOC breakdown "for free" as a side-effect of the SAST scan you were already running (findings-per-KLOC density, etc.), no second tool.

### Concrete gaps bhf should fix to lead

1. **Speed / invocation model.** Offer a standalone `bhf sloc <path>` (or `--sloc-only`) that skips the SAST parse and does a fast line-count pass, and support multi-root/whole-corpus counting in one invocation. Today you pay full scan cost (16.5 s) for numbers tokei produces in 0.09 s. This is the single biggest gap.
2. **Header attribution transparency.** bhf folds all `.h` into `c` even in a C++ repo (cpp_json shows `c: 44`, everything else `cpp`), which is defensible but makes apples-to-apples comparison require manual summing. Emitting an optional cloc-style `c_header`/`cpp_header` split (or documenting the fold) would remove the footgun.

A dedicated fast SLOC path would retain the measured accuracy while addressing
the throughput gap. At the time of this measurement, tokei was about 150 times
faster, while bhf handled Perl and comments more accurately on the pinned
corpus.

Relevant files: `/tmp/bhf/*_sloc.json` (bhf outputs), `/tmp/{cloc,scc,tokei}_time.txt` (timing captures).
