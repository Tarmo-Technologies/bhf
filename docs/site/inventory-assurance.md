<!-- SPDX-License-Identifier: Apache-2.0 -->
# Inventory assurance and the VEX review queue

## Automatic observations are not vulnerability adjudications

BHF inventories components and matches them against the advisory database supplied
by the operator. A missing source/link/load observation does not establish that a
component is absent. A fuzz campaign that did not reach a component does not
establish that its vulnerable paths are unreachable. Loading or exercising part
of a library does not establish that a particular CVE is exploitable.

Accordingly, automatically matched CVEs now remain OpenVEX
`under_investigation` and CycloneDX `in_triage`, with no non-impact justification.
The native match retains identity confidence, matching method, component evidence,
reachability observations, and advisory fixed-version hints. Generic numeric
comparison of those hints is no longer used to assert `fixed`: package identity,
ecosystem version semantics, pre-releases, vendor backports and affected release
branches need vulnerability-specific analysis.

This is an intentional correction to earlier automatic `not_affected`, `affected`
and `fixed` verdicts. It neither removes CVE matches nor suppresses severity gates.
Regenerate assessments produced by the earlier mapping before relying on them.
A previously generated `not_affected` statement is not validated by this change.

## Queue for review

The default `bhf sbom` output adds `vex-review.json` (schema
`bhf.vex.review_queue.v1`). It contains the matched and pending counts and one
entry per unresolved advisory/component pair. Entries retain the advisory ID,
component reference and identity, product ID, severity, match confidence, matching
method, evidence and reachability, the assessment notes, fixed-version hints, and
an explicit next action. A repeated CVE in two products remains two review items.

Select just this report with:

```sh
bhf sbom /path/to/source --vuln-db /path/to/advisories.json \
  --out /path/to/reports --emit vex-review
```

The queue is limited to `matched_advisories_only`. An empty queue does **not**
assert that the source is safe, that inventory is complete, or that every relevant
CVE exists in the supplied database. Database freshness, coverage and authenticity
remain operator responsibilities. An inventory-only run without a database can
produce an empty queue; do not treat that as a vulnerability review.

## Explicit CI gate

```sh
bhf sbom /path/to/source --vuln-db /path/to/advisories.json \
  --out /path/to/reports --fail-on-unreviewed
```

`--fail-on-unreviewed` requires explicit `--vuln-db` and writes `vex-review.json`
even with a narrower `--emit` or `--format` selection. It blocks on any pending
match, including a low-severity match below a separate severity threshold.
Existing `--fail-on` and policy severity gates still operate independently.

| Outcome | CLI exit |
| --- | ---: |
| Inventory completed; no requested gate blocked | 0 |
| Pending review, a severity gate blocked, or a processing error | 1 |
| Argument error, including review gate without explicit database | 2 |

Reports remain available when a completed assessment trips a gate. Processing
errors are different: do not consume an old report as the result of a failed run.
Use a dedicated output directory per run and retain the command, source revision,
database revision/digest and exit code together. No all-artifact atomic publication
or multi-writer output-directory guarantee is added by this feature.

An advisory database must have a `vulnerabilities` array. Each record must have a
nonempty ID and a package identity (name/ecosystem, PURL or CPE); when supplied,
`affected_versions` must be a string array (or null, for existing format
compatibility). Malformed records reject the run rather than disappearing into a
successful empty review. An explicit valid empty array remains supported.

## Reviewer and integration boundaries

The queue is a work product for analyst review, not an approval store. This change
does not add a signed adjudication importer, exception/waiver mechanism, reviewer
identity management or an automated way to clear a CVE. Vulnerability-specific
review and any definitive VEX publication remain separate controlled activities.

OpenVEX statements now include `status_notes`. The existing `impact_statement`
field is retained for consumer compatibility but is not a non-impact assertion.
The existing document ID, `bhf` author label and deterministic timestamp behavior
are unchanged. Before publishing externally, supply accountable publisher,
product/revision, date, version and review provenance through your controlled
publication process; these generated files are not a signed publisher attestation.

## Offline verifier portability

`scripts/verify-offline-dist.sh` no longer requires `xxd`: it constructs the same
Ed25519 public-key DER encoding using Bash builtins after checking the key format.
Public-key input is capped at 66 bytes; the raw signature must remain 64 bytes.
The verifier still authenticates the domain-separated archive digest using
OpenSSL before extraction or execution. There is no legacy or unsigned fallback.

OpenSSL must support the verifier's Ed25519 `pkeyutl -rawin` operation. Removing
`xxd` does not add Ed25519 to an older OpenSSL installation. Obtain the verifier
and trusted key independently of the unverified archive. Existing archive/path
and signature verification requirements remain in force.

The EL7 CI job selects the Python 3.12 interpreter already in its pinned image
and builds a separately prefixed OpenSSL 3.5.8 CLI from a checksum-pinned official
source archive. This is a connected CI prerequisite, not a bundled offline
OpenSSL installer, a replacement for the host's system libraries, or a FIPS
validation claim. BHF release-library linkage and the existing ABI checks remain
unchanged. An offline deployment must provision compatible, trusted verification
tools separately.

## Relevant checks

```sh
cargo test --locked -p governance --lib
cargo test --locked -p bhf --lib sbom::tests
cargo test --locked -p bhf --test sbom_assurance_cli
cargo test --locked -p bhf --test offline_dist_scripts
python3 -m unittest discover -s scripts/tests -p test_offline_verifier.py -v
python3 -m unittest discover -s scripts/ci/tests -v
```

The signature tests require a Unix host, Bash and OpenSSL with Ed25519 support.
They generate test-only keys locally and exclude `xxd` from the verifier's PATH.
They exercise valid verification, archive/signature/key tampering, malformed and
oversized keys, signature length, symlinks and missing domain separation.
