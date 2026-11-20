<!-- SPDX-License-Identifier: Apache-2.0 -->
# Inventory assurance and the VEX review queue

## What an automatic match records

`bhf sbom` inventories components and matches them against the advisory
database you supply. The inventory and a fuzz campaign record observations:
which components bhf saw in source, link and load evidence, and which code a
campaign reached. A component bhf did not observe can still be present, a
vulnerable path a campaign did not reach can still be reachable, and code
that ran is not proof that a given CVE is exploitable. Deciding those
questions takes vulnerability-specific analysis.

So every automatically matched CVE is marked OpenVEX `under_investigation`
and CycloneDX `in_triage`, with no non-impact justification. Each match
keeps its identity confidence, matching method, component evidence,
reachability observations and the advisory's fixed-version hints. bhf does
not mark a match `fixed` from a numeric comparison of those hints, because
package identity, ecosystem version rules, pre-releases, vendor backports
and affected release branches all need case-by-case review. Matches and
severity gates work as usual.

Earlier bhf versions wrote automatic `not_affected`, `affected` and `fixed`
verdicts. Regenerate any assessment produced by those versions before you
rely on it; bhf does not re-validate an old `not_affected` statement.

## Review queue

By default `bhf sbom` also writes `vex-review.json` (schema
`bhf.vex.review_queue.v1`). It holds the matched and pending counts and one
entry per unresolved advisory and component pair. Each entry keeps the
advisory ID, the component reference and identity, the product ID, the
severity, the match confidence, the matching method, the evidence and
reachability, the assessment notes, the fixed-version hints and a next
action. The same CVE in two products is two review items.

To write only this report:

```sh
bhf sbom /path/to/source --vuln-db /path/to/advisories.json \
  --out /path/to/reports --emit vex-review
```

The queue's scope is `matched_advisories_only`: it lists matches against the
database you supplied. An empty queue means no match is pending review. The
completeness of the inventory and the freshness, coverage and authenticity
of the database are yours to establish. A run without a database writes an
inventory and an empty queue, with no vulnerability review.

## CI gate

```sh
bhf sbom /path/to/source --vuln-db /path/to/advisories.json \
  --out /path/to/reports --fail-on-unreviewed
```

`--fail-on-unreviewed` needs an explicit `--vuln-db` and writes
`vex-review.json` even when `--emit` or `--format` selects fewer reports. It
fails on any pending match, including a low-severity match below a separate
severity threshold. The `--fail-on <severity>` gate and the policy severity
gate (`--policy`) work independently of it and also need `--vuln-db`.

| Outcome | Exit code |
| --- | ---: |
| Inventory completed; no requested gate blocked | 0 |
| Pending review, a severity gate blocked, or a processing error | 1 |
| Argument error, including the review gate without an explicit database | 2 |

When a completed assessment trips a gate, its reports are still written.
After a processing error, the output directory can still hold an older
report; never read it as the result of the failed run. Use a separate
output directory for each run,
and keep the command, source revision, database revision or digest and exit
code together. bhf does not publish the output files atomically as a set,
and two runs writing to one output directory can mix their files.

An advisory database must have a `vulnerabilities` array. Each record needs
a non-empty ID and a package identity (name and ecosystem, PURL or CPE).
When present, `affected_versions` must be an array of strings, or `null` for
older files. A malformed record fails the run, so it cannot hide behind an
empty review. A valid empty array is accepted.

## Advisory database format

`bhf sbom --vuln-db` reads a JSON object whose `vulnerabilities` array holds
one record per affected package:

| Field | Meaning |
| --- | --- |
| `id` | The advisory id (required). |
| `aliases` | Other ids of the same advisory, such as its CVE. |
| `package.ecosystem`, `package.name` | The package, by bhf's ecosystem names: `cargo`, `npm`, `pypi`, `golang`, `maven`, `nuget`, `gem`, `composer`, `conan`, ... |
| `package.purl` | A package URL; one without a version matches every version the record affects. |
| `package.cpe` | A CPE 2.3 string or 2.2 URI; `*` fields are wildcards. |
| `affected_versions` | Exact affected versions; `"*"` is every version. |
| `affected_ranges` | Version ranges, each an object of optional bounds `start_including`, `start_excluding`, `end_including` and `end_excluding`; `{}` is every version. |
| `severity` | `critical`, `high`, `medium`, `low`, `none` or `unknown`; the `--fail-on` gate compares it. |
| `summary`, `kev`, `cvss`, `cwe`, `references` | Carried into `vulnerabilities.json`. |

A record needs an id and a package identity (ecosystem and name, purl, or
CPE). A component is affected when its version is listed or lies in a
range. Versions compare the way package managers order them: dotted
segments numerically (`0.10.38` after `0.10.9`), letters after a number's
digits in order (`1.0.2` before `1.0.2a`), and a pre-release (`1.0.0-rc.1`)
before its release.

### Building a database from OSV

`bhf pack import-osv INPUT... --out cve-db.json` builds a database from OSV
records: an OSV ecosystem export unzipped into a directory, or single record
files (each holding one record or an array of them). Each affected package
becomes a record:

- OSV `crates.io`, `npm`, `PyPI`, `Go`, `Maven`, `NuGet`, `RubyGems`,
  `Packagist` and `ConanCenter` packages take the bhf ecosystem names above,
  and a Maven `group:artifact` also gets its purl.
- `versions` become `affected_versions`.
- `SEMVER` and `ECOSYSTEM` range events become `affected_ranges`:
  `introduced` is a start (`"0"` means none), `fixed` or `limit` is an
  excluded end, and `last_affected` is an included end.
- The severity is the GitHub advisory rating the record carries (`MODERATE`
  is `medium`), else the rating of its highest CVSS v3 base score, else
  `unknown`.

The summary JSON on stdout counts what was read and written. A record or
file that cannot be read is reported on stderr and in the summary's
`malformed` list, and skipped. A package in an ecosystem bhf does not
catalogue, or with only a git commit range, is counted and left out. The
command exits 1 when malformed input left nothing to import.

### Building a database from NVD

`bhf pack import-nvd INPUT... --out cve-db.json` builds a database from NVD
CVE JSON 2.0 files (the yearly feeds, or API responses saved to disk), for
the C and C++ libraries that an SBOM or `bhf binary scan` identifies by CPE.

- Each vulnerable CPE match in a CVE's configurations becomes a record whose
  `package.cpe` is the match's `criteria` (a CPE 2.3 string,
  `cpe:2.3:part:vendor:product:version:...`, where `*` fields are
  wildcards).
- The match's bounds (`versionStartIncluding`, `versionStartExcluding`,
  `versionEndIncluding`, `versionEndExcluding`) become an `affected_ranges`
  entry. Without bounds, the CPE's own version field applies (`*` or `-` is
  every version).
- A match marked not vulnerable (the platform of an `AND` configuration), a
  negated node and a rejected CVE are left out.
- The severity is the base severity of the first CVSS metric present, in the
  order v4.0, v3.1, v3.0, v2, taking the NVD's primary score first.

Malformed records are reported and skipped as with OSV, and a CVE with no
configuration is counted under `without_versions`. A component matches a
CPE record when its CPE agrees field by field and its version lies in the
record's range.

## Review and publication

The queue is a work list for analyst review. bhf has no signed adjudication
importer, waiver mechanism, reviewer identity management or automatic way to
clear a CVE; vulnerability-specific review and any final VEX publication
happen in your own controlled process.

OpenVEX statements carry `status_notes`, which describe the open question.
They also keep an `impact_statement` field with the same text for consumers
that read it; it makes no claim of non-impact. The document ID, the `bhf`
author label and the deterministic timestamp come from bhf. Before you
publish externally, add the accountable publisher, product and revision,
date, version and review provenance through your publication process; the
generated files carry no publisher signature.

## Offline verifier portability

`scripts/verify-offline-dist.sh` needs no `xxd`: after it checks the key
format, it builds the Ed25519 public-key DER encoding with Bash builtins.
The public-key file may be at most 66 bytes, and the raw signature must be
64 bytes. The verifier authenticates the domain-separated archive digest
with OpenSSL before anything is extracted or run, and has no unsigned
fallback.

OpenSSL must support the Ed25519 `pkeyutl -rawin` operation the verifier
uses. Obtain the verifier and the trusted key independently of the archive
you verify; the archive, path and signature checks all apply.

The EL7 CI job uses the Python 3.12 interpreter in its pinned image and
builds a separately prefixed OpenSSL 3.5.8 CLI from a checksum-pinned
official source archive. That OpenSSL is a CI build prerequisite: it is not
shipped in the offline bundle, does not replace the host's system libraries
and carries no FIPS validation. The release binaries' library linkage and
ABI checks are the same as for every release. On an offline host, provide
compatible, trusted verification tools yourself.

## Tests

```sh
cargo test --locked -p governance --lib
cargo test --locked -p bhf --lib sbom::tests
cargo test --locked -p bhf --test sbom_assurance_cli
cargo test --locked -p bhf --test offline_dist_scripts
python3 -m unittest discover -s scripts/tests -p test_offline_verifier.py -v
python3 -m unittest discover -s scripts/ci/tests -v
```

The signature tests need a Unix host, Bash and an OpenSSL with Ed25519
support. They generate test-only keys and remove `xxd` from the verifier's
`PATH`. They cover valid verification, archive, signature and key
tampering, malformed and oversized keys, signature length, symlinks and a
missing domain separation.
