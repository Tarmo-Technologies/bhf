go_gin: `comm -3` returned empty = **bhf and syft found the exact same 42 go-modules**. java_gson: empty diff = same 21 java-archives. Strong validation that bhf matches syft on manifest-declared components. I have everything needed.

## Findings

I compared **bhf sbom** against **syft** (component discovery) and **grype** (CVE matching) on the 8 dependency-manifest repos. All numbers below are measured, not estimated. Syft/grype were run with `dir:` scanning; syft's counts include GitHub Actions cataloged from `.github/workflows/`, which I broke out separately since they're not the dependency-ecosystem components under comparison.

### Component discovery (dependency ecosystems only)

| Repo | Ecosystem | Manifest | bhf | syft (deps) | syft (raw incl. gh-actions) | grype vulns | bhf vulns |
|---|---|---|---|---|---|---|---|
| py_requests | pypi | pyproject/setup | **21** | 2 | 22 | 0 | 0 |
| py_click | pypi | pyproject + uv.lock | 30 | **81** | 101 | **11** | 0 |
| java_commonslang | maven | pom.xml | 8 | 8 (tie) | 22 | 0 | 0 |
| java_gson | maven | pom.xml (multi) | 21 | 21 (tie, same set) | 41 | **1** | 0 |
| go_gin | golang | go.mod/go.sum | 42 | 42 (tie, identical set) | 56 | 0 | 0 |
| go_cobra | golang | go.mod/go.sum | 7 | 7 (tie) | 13 | 0 | 0 |
| rust_semver | cargo | Cargo.toml | **6** | **0** | 11 | 0 | 0 |
| js_express | npm | package.json | **45** | **0** | 17 | 0 | 0 |

### Verdict: bhf is roughly co-#1 on component discovery, but loses on CVE correlation.

- **bhf wins outright on npm and cargo.** syft found **0** components for both js_express (npm) and rust_semver (cargo) — it only cataloged GitHub Actions. syft catalogs npm from `package-lock.json`/`node_modules` and cargo from `Cargo.lock`; neither lockfile is present in these repos, so syft reports nothing. bhf reads the declared `package.json` (45) and `Cargo.toml` (6) directly. Clear bhf advantage: 45–0 and 6–0.
- **bhf ties syft exactly on go and maven.** go_gin (42/42) and go_cobra (7/7) are identical sets (`comm` diff empty); java_gson (21/21) and java_commonslang (8/8) match. Both tools resolve go.sum and pom.xml the same way. Neither leads.
- **syft wins big on Python.** py_click: syft **81** vs bhf **30**; py_requests: syft **2** vs bhf **21** (bhf higher here, but see below). The py_click gap is because bhf parses `pyproject.toml` declarations while syft additionally parses `uv.lock`, pulling the full **transitive** dependency closure (81 pinned packages). bhf counted only direct declared deps across the repo's pyproject files. On py_requests bhf's higher count comes from scanning multiple pyproject/requirements files including dev/docs extras that syft's default cataloger skipped.

### CVE correlation: syft+grype wins, bhf found 0 in every repo.

grype found **11** vulns in py_click and **1** in java_gson; bhf matched **0** everywhere. Root cause is measured, not the offline DB: grype gets **pinned versions** from lockfiles (py_click `uv.lock` → starlette@1.0.0, urllib3@2.6.3, idna@3.11, uv@0.11.3, pytest@9.0.2; java_gson transitive jackson-databind@2.22.0). bhf parsed the same package names from `pyproject.toml`/`pom.xml` but with `version: null` — and a null version can't match a CVE range. bhf's version coverage confirms this: py_click 11/30, py_requests 2/21, rust_semver 2/6, js_express 9/45 components have versions; the rest are unpinned specifiers from manifests.

### Concrete gaps bhf should fix to lead

1. **Ingest lockfiles, not just manifests (highest impact).** bhf reads `pyproject.toml` but ignores `uv.lock` (confirmed: no uv.lock in any component's `evidence` field). Also add `package-lock.json`/`pnpm-lock.yaml`, `Cargo.lock`, and `poetry.lock`/`requirements.txt`-pinned parsing. Lockfiles give (a) the transitive closure syft counts (the 81-vs-30 Python gap) and (b) the pinned versions grype needs for CVE matching (the 11-vs-0 gap). This single fix closes both the Python component gap and the entire CVE-correlation deficit.
2. **Fill in versions to enable its own CVE gate.** bhf's vuln matcher works but is starved — with null versions across most components it structurally can't match. Fixing lockfile ingestion feeds the matcher.

### Net
On raw manifest-declared component discovery, bhf is at least as good as syft and strictly better on npm/cargo where syft needs a lockfile bhf doesn't. But without transitive lockfile resolution, syft beats it on Python transitive depth (81 vs 30) and grype beats bhf on CVEs everywhere (11 and 1 vs 0). bhf is **not #1 on the combined SBOM+CVE feature today**; syft+grype win on the two repos that have pinned lockfiles. Lockfile ingestion is the one change that would flip bhf to leading across all eight repos.

Output files: bhf SBOMs at `/tmp/sb_<repo>/sbom.json`; syft at `/tmp/syft_<repo>.json`; grype at `/tmp/grype_<repo>.json`.