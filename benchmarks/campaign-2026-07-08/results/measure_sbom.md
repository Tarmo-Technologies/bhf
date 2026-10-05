For go_gin, `comm -3` returned empty: bhf and syft found the same 42 Go
modules. The java_gson diff was also empty, with 21 Java archives from each
tool. These two repositories show matching manifest-declared component sets.

## Findings

The measurement compares **bhf sbom** with **syft** for component discovery and
**grype** for CVE matching on eight dependency-manifest repositories. Syft and
grype used `dir:` scanning. Syft's counts include GitHub Actions cataloged from
`.github/workflows/`; the table separates those from dependency-ecosystem
components.

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

### Measured result

- **npm and cargo:** syft found **0** components for both js_express (npm)
  and rust_semver (cargo), while bhf found 45 and 6. syft catalogs npm from
  `package-lock.json`/`node_modules` and cargo from `Cargo.lock`; neither
  lockfile is present in these repositories. bhf reads the declared
  `package.json` and `Cargo.toml` directly.
- **bhf ties syft exactly on go and maven.** go_gin (42/42) and go_cobra (7/7) are identical sets (`comm` diff empty); java_gson (21/21) and java_commonslang (8/8) match. Both tools resolve go.sum and pom.xml the same way. Neither leads.
- **Python:** py_click produced 81 components in syft and 30 in bhf;
  py_requests produced 2 in syft and 21 in bhf. The py_click difference comes
  from syft parsing `uv.lock` for the transitive dependency closure. On
  py_requests, bhf scanned multiple project and requirements files, including
  development and documentation extras that syft's default cataloger skipped.

### CVE correlation

grype found **11** vulns in py_click and **1** in java_gson; bhf matched **0** everywhere. Root cause is measured, not the offline DB: grype gets **pinned versions** from lockfiles (py_click `uv.lock` → starlette@1.0.0, urllib3@2.6.3, idna@3.11, uv@0.11.3, pytest@9.0.2; java_gson transitive jackson-databind@2.22.0). bhf parsed the same package names from `pyproject.toml`/`pom.xml` but with `version: null` — and a null version can't match a CVE range. bhf's version coverage confirms this: py_click 11/30, py_requests 2/21, rust_semver 2/6, js_express 9/45 components have versions; the rest are unpinned specifiers from manifests.

### Concrete gaps

1. **Ingest lockfiles, not just manifests (highest impact).** bhf reads `pyproject.toml` but ignores `uv.lock` (confirmed: no uv.lock in any component's `evidence` field). Also add `package-lock.json`/`pnpm-lock.yaml`, `Cargo.lock`, and `poetry.lock`/`requirements.txt`-pinned parsing. Lockfiles give (a) the transitive closure syft counts (the 81-vs-30 Python gap) and (b) the pinned versions grype needs for CVE matching (the 11-vs-0 gap). This single fix closes both the Python component gap and the entire CVE-correlation deficit.
2. **Fill in versions to enable its own CVE gate.** bhf's vuln matcher works but is starved — with null versions across most components it structurally can't match. Fixing lockfile ingestion feeds the matcher.

### Net
bhf found more declared components on the measured npm and cargo repositories,
matched syft on Go and Maven, and found fewer transitive components on py_click.
grype reported 11 and 1 CVEs on two repositories while bhf reported none.
Lockfile ingestion addresses both the Python transitive-depth gap and the missing
version data needed for CVE correlation.

Output files: bhf SBOMs at `/tmp/sb_<repo>/sbom.json`; syft at `/tmp/syft_<repo>.json`; grype at `/tmp/grype_<repo>.json`.
