# BHF results

- bhf 0.3.0 · source `/src/demo`
- **7 findings** in 7 root-cause groups — critical 1 · high 5 · medium 1 · low 0 · info 0
- By kind: fuzz 1 · runtime 1 · static 2 · binary 1 · differential 1 · sca 1
- Campaign: 3 target(s) swept — details in [`../auto/run.md`](../auto/run.md)
- Machine-readable: [`findings.json`](findings.json) · [`findings.csv`](findings.csv) · [`findings.sarif`](findings.sarif)
- Native reports: [`static/`](static/) · [`sbom/`](sbom/)

## 1. [CRITICAL] Heap-based Buffer Overflow in parse\_header

- Finding: `F-0000-1a2b3c4d` (fuzz)
- Rule: `BHF-201`
- Evidence: sanitizer_crash · confidence medium · verdict likely\_reachable
- CWE: CWE-122
- Location: `src/parse.c`:42 in `parse_header`
- Suggested fix: Bounds-check the index/length before the access at \`src/parse.c:42\` (\`parse\_header\`): validate it against the buffer size before reading or writing.
- Evidence bundle: [`findings/F-0000-1a2b3c4d/`](findings/F-0000-1a2b3c4d/)

## 2. [HIGH] Binary crash, abnormal exit, or timeout

- Finding: `BF-0001` (binary)
- Rule: `BHF-501`
- Evidence: crash_lead · confidence high · verdict unknown
- CWE: CWE-754
- Evidence bundle: [`findings/BF-0001/`](findings/BF-0001/)

## 3. [HIGH] Unsafe string copy call in source (copy\_name)

- Finding: `F-RO-BHF-401-0000ABCD` (static)
- Rule: `BHF-401`
- Evidence: static · confidence medium · verdict unknown
- CWE: CWE-120
- Location: `lib/parse.c`:6 in `copy_name`
- Evidence bundle: [`findings/F-RO-BHF-401-0000ABCD/`](findings/F-RO-BHF-401-0000ABCD/)

## 4. [HIGH] CVE-2026-0001 in example 2.4.2

- Finding: `F-SCA-203b6b399c3b3dac` (sca)
- Rule: `CVE-2026-0001`
- Evidence: advisory · confidence high
- CWE: CWE-1395
- Component: `pkg:npm/example@2.4.2` · fixed in 2.4.3
- Suggested fix: Upgrade example to 2.4.3 or later.
- Source: [`sbom/vulnerabilities.json`](sbom/vulnerabilities.json)

## 5. [HIGH] Data race (ThreadSanitizer)

- Finding: `F-TSAN-0000` (runtime)
- Rule: `BHF-556`
- Evidence: crash_lead · confidence low · verdict likely\_reachable
- CWE: CWE-362
- Evidence bundle: [`findings/F-TSAN-0000/`](findings/F-TSAN-0000/)

## 6. [HIGH] Unsafe string copy call in source (greet)

- Finding: `S-0001` (static)
- Rule: `BHF-401`
- Evidence: static · confidence medium
- CWE: CWE-120
- Location: `weak.c`:9 in `greet`
- Suggested fix: Use a bounded copy.
- Source: [`static/static-report.json`](static/static-report.json)

## 7. [MEDIUM] Output divergence between implementations

- Finding: `F-DIFF-0000` (differential)
- Rule: `BHF-301`
- Evidence: runtime_oracle · confidence low · verdict unknown
- CWE: CWE-754
- Evidence bundle: [`findings/F-DIFF-0000/`](findings/F-DIFF-0000/)

