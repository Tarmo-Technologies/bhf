# SPDX-License-Identifier: Apache-2.0
"""bhf results documents validate against the checked-in JSON Schemas."""

import hashlib
import json
import unittest
from pathlib import Path

import jsonschema  # CI: pip install jsonschema (see .github/workflows/ci.yml)
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[3]
SCHEMAS = ROOT / "schemas"
EXAMPLES = SCHEMAS / "examples"
GOLDEN = ROOT / "tests" / "fixtures" / "golden_results"
KINDS = {"fuzz", "runtime", "static", "binary", "differential", "sca"}


def _registry() -> Registry:
    resources = []
    for path in sorted(SCHEMAS.glob("*.schema.json")):
        doc = json.loads(path.read_text())
        resources.append((doc["$id"], Resource.from_contents(doc)))
    return Registry().with_resources(resources)


def _validator(schema_file: str):
    schema = json.loads((SCHEMAS / schema_file).read_text())
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)
    return cls(schema, registry=_registry(), format_checker=cls.FORMAT_CHECKER)


def _errors(validator, doc) -> list[str]:
    return [f"{'/'.join(map(str, e.absolute_path))}: {e.message}" for e in validator.iter_errors(doc)]


class SchemaFilesTest(unittest.TestCase):
    def test_every_schema_is_a_valid_2020_12_schema(self):
        for path in SCHEMAS.glob("*.schema.json"):
            with self.subTest(path.name):
                _validator(path.name)

    def test_example_findings_document_validates(self):
        doc = json.loads((EXAMPLES / "findings.v1.example.json").read_text())
        self.assertEqual(_errors(_validator("bhf.findings.v1.schema.json"), doc), [])

    def test_finding_envelope_validates(self):
        doc = {
            "schema_version": "bhf.finding.v1",
            "id": "F-0000-1a2b3c4d",
            "finding_kind": "fuzz",
            "created_at": "2026-10-01T11:20:00Z",
            "kind": "binary_crash",
            "history": [{"at": "2026-10-01T11:21:00Z", "command": "minimize", "fields": ["minimal_reproducer"]}],
        }
        validator = _validator("bhf.finding.v1.schema.json")
        self.assertEqual(_errors(validator, doc), [])

        bad = {**doc, "finding_kind": "nope"}
        self.assertNotEqual(_errors(validator, bad), [])

    def test_build_fidelity_validates_in_both_documents(self):
        fidelity = {
            "level": "reduced",
            "context": "none",
            "fabricated": [
                {"kind": "macro", "name": "WIDGET_SLOTS", "value": "0"},
                {"kind": "header", "name": "tables.h"},
            ],
        }
        doc = json.loads((EXAMPLES / "findings.v1.example.json").read_text())
        doc["findings"][0]["reproduce"]["build"]["fidelity"] = fidelity
        findings = _validator("bhf.findings.v1.schema.json")
        self.assertEqual(_errors(findings, doc), [])
        bad = json.loads(json.dumps(doc))
        bad["findings"][0]["reproduce"]["build"]["fidelity"]["fabricated"][0]["kind"] = "guess"
        self.assertNotEqual(_errors(findings, bad), [])

        envelope = {
            "schema_version": "bhf.finding.v1",
            "id": "F-0000-1a2b3c4d",
            "finding_kind": "fuzz",
            "created_at": "2026-10-01T11:20:00Z",
            "build": {"binary": {"sha256": "0" * 64}, "fidelity": fidelity},
        }
        self.assertEqual(_errors(_validator("bhf.finding.v1.schema.json"), envelope), [])

    def test_verdict_reason_is_an_optional_known_code(self):
        findings = _validator("bhf.findings.v1.schema.json")
        doc = json.loads((EXAMPLES / "findings.v1.example.json").read_text())
        doc["findings"][0]["verdict"] = "lab_only"
        doc["findings"][0]["verdict_reason"] = "harness_sized_buffer"
        self.assertEqual(_errors(findings, doc), [])
        bad = json.loads(json.dumps(doc))
        bad["findings"][0]["verdict_reason"] = "because"
        self.assertNotEqual(_errors(findings, bad), [])
        older = json.loads(json.dumps(doc))
        for finding in older["findings"]:
            finding.pop("verdict_reason", None)
        self.assertEqual(_errors(findings, older), [])

    def test_an_imported_kernel_crash_validates(self):
        """`bhf kernel import`: producer `kernel import`, and the console log
        and syzkaller reproducers as evidence roles."""
        findings = _validator("bhf.findings.v1.schema.json")
        doc = json.loads((EXAMPLES / "findings.v1.example.json").read_text())
        finding = doc["findings"][0]
        finding["producer"] = "kernel import"
        evidence_dir = finding["evidence"]["dir"]
        for role, name in (("console_log", "console.log"), ("repro_syz", "repro.syz"), ("repro_c", "repro.c")):
            finding["evidence"]["files"].append(
                {"role": role, "path": f"{evidence_dir}/{name}", "sha256": None, "size": 12})
        self.assertEqual(_errors(findings, doc), [])
        bad = json.loads(json.dumps(doc))
        bad["findings"][0]["evidence"]["files"][-1]["role"] = "repro_cobol"
        self.assertNotEqual(_errors(findings, bad), [])

    def test_allocated_by_harness_is_an_optional_flag(self):
        findings = _validator("bhf.findings.v1.schema.json")
        doc = json.loads((EXAMPLES / "findings.v1.example.json").read_text())
        doc["findings"][0]["fuzz"]["access"]["allocated_by_harness"] = True
        self.assertEqual(_errors(findings, doc), [])
        bad = json.loads(json.dumps(doc))
        bad["findings"][0]["fuzz"]["access"]["allocated_by_harness"] = "yes"
        self.assertNotEqual(_errors(findings, bad), [])
        older = json.loads(json.dumps(doc))
        older["findings"][0]["fuzz"]["access"].pop("allocated_by_harness")
        self.assertEqual(_errors(findings, older), [])

    def test_sanitizer_second_opinion_validates_in_both_documents(self):
        opinion = {
            "check": "object-size",
            "used": "asan",
            "reason": "with the check suppressed, AddressSanitizer reported heap-buffer-overflow at the same sink",
        }
        envelope = {
            "schema_version": "bhf.finding.v1",
            "id": "F-0000-1a2b3c4d",
            "finding_kind": "fuzz",
            "created_at": "2026-10-01T11:20:00Z",
            "sanitizer_second_opinion": {**opinion, "replaced_cluster_key": "c0ffee00c0ffee00"},
        }
        finding = _validator("bhf.finding.v1.schema.json")
        self.assertEqual(_errors(finding, envelope), [])
        stands = {"check": "object-size", "used": "ubsan", "reason": "the re-run reported no error"}
        self.assertEqual(_errors(finding, {**envelope, "sanitizer_second_opinion": stands}), [])
        for bad in ({**opinion, "used": "msan"}, {**opinion, "check": "alignment"}, {"check": "object-size", "used": "asan"}):
            with self.subTest(bad=bad):
                self.assertNotEqual(_errors(finding, {**envelope, "sanitizer_second_opinion": bad}), [])

        findings = _validator("bhf.findings.v1.schema.json")
        doc = json.loads((EXAMPLES / "findings.v1.example.json").read_text())
        doc["findings"][0]["fuzz"]["sanitizer_second_opinion"] = opinion
        self.assertEqual(_errors(findings, doc), [])
        # A document written before the field existed omits the key.
        del doc["findings"][0]["fuzz"]["sanitizer_second_opinion"]
        self.assertEqual(_errors(findings, doc), [])
        bad = json.loads(json.dumps(doc))
        bad["findings"][0]["fuzz"]["sanitizer_second_opinion"] = {**opinion, "replaced_cluster_key": "c0ffee"}
        self.assertNotEqual(_errors(findings, bad), [])

    def test_seed_lineage_validates_in_both_documents_and_is_optional(self):
        lineage = {
            "origin": "mined_seed",
            "root_sha256": "ab" * 32,
            "root_path": "tests/data/x.bin",
            "layout_prefix": None,
            "depth": 7,
            "parent_sha256": "cd" * 32,
            "donor_sha256": None,
            "reason": None,
        }
        findings = _validator("bhf.findings.v1.schema.json")
        doc = json.loads((EXAMPLES / "findings.v1.example.json").read_text())
        doc["findings"][0]["fuzz"]["lineage"] = lineage
        self.assertEqual(_errors(findings, doc), [])
        unknown = {**lineage, "origin": "unknown", "root_sha256": None, "root_path": None,
                   "depth": None, "parent_sha256": None, "reason": "found by AFL++"}
        doc["findings"][0]["fuzz"]["lineage"] = unknown
        self.assertEqual(_errors(findings, doc), [])
        for bad in ({**lineage, "origin": "guessed"}, {**lineage, "root_sha256": "XYZ"},
                    {**lineage, "depth": -1}, {k: v for k, v in lineage.items() if k != "reason"}):
            doc["findings"][0]["fuzz"]["lineage"] = bad
            self.assertNotEqual(_errors(findings, doc), [], bad)
        # A document written before the key existed still validates.
        del doc["findings"][0]["fuzz"]["lineage"]
        self.assertEqual(_errors(findings, doc), [])

        envelope = _validator("bhf.finding.v1.schema.json")
        record = {
            "schema_version": "bhf.finding.v1",
            "id": "F-0000-1a2b3c4d",
            "finding_kind": "fuzz",
            "created_at": "2026-10-01T11:20:00Z",
            "lineage": {"origin": "user_seed", "root_sha256": "ab" * 32,
                        "root_path": "/seeds/x.bin", "depth": 0},
        }
        self.assertEqual(_errors(envelope, record), [])
        record["lineage"] = {"origin": "unknown", "reason": "found by AFL++"}
        self.assertEqual(_errors(envelope, record), [])
        record["lineage"] = {"origin": "guessed"}
        self.assertNotEqual(_errors(envelope, record), [])

    def test_manifest_validates(self):
        doc = {
            "schema_version": "bhf.results-manifest.v1",
            "tool": {"name": "bhf", "version": "0.3.0", "build": "0.3.0"},
            "source": {
                "root": "/src",
                "vcs": {"kind": "git", "commit": "0123456789abcdef0123456789abcdef01234567", "branch": "main", "dirty": None},
            },
            "producers": [
                {
                    "command": "auto",
                    "argv": ["bhf", "auto"],
                    "started_at": "2026-10-01T11:00:00Z",
                    "finished_at": "2026-10-01T11:58:00Z",
                    "status": "complete",
                    "exit_code": 0,
                    "findings_total": 1,
                }
            ],
        }
        validator = _validator("bhf.results-manifest.v1.schema.json")
        self.assertEqual(_errors(validator, doc), [])

        bad = json.loads(json.dumps(doc))
        bad["producers"][0]["status"] = "failed"
        self.assertNotEqual(_errors(validator, bad), [])

    def test_golden_results_validate(self):
        results = GOLDEN / "results"
        doc = json.loads((results / "findings.json").read_text())
        self.assertEqual(_errors(_validator("bhf.findings.v1.schema.json"), doc), [])
        manifest = json.loads((results / "manifest.json").read_text())
        self.assertEqual(_errors(_validator("bhf.results-manifest.v1.schema.json"), manifest), [])
        finding_validator = _validator("bhf.finding.v1.schema.json")
        records = sorted((results / "findings").glob("*/finding.json"))
        self.assertNotEqual(records, [])
        for path in records:
            with self.subTest(path.parent.name):
                self.assertEqual(_errors(finding_validator, json.loads(path.read_text())), [])

    def test_golden_attestation_digests_match_the_files(self):
        results = GOLDEN / "results"
        statement = json.loads((results / "attestation.json").read_text())
        subjects = statement["subject"]
        self.assertNotEqual(subjects, [])
        for subject in subjects:
            with self.subTest(subject["name"]):
                path = results / subject["name"]
                self.assertTrue(path.is_file(), path)
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                self.assertEqual(digest, subject["digest"]["sha256"])

    def test_golden_covers_every_kind(self):
        doc = json.loads((GOLDEN / "results" / "findings.json").read_text())
        self.assertEqual({f["kind"] for f in doc["findings"]}, KINDS)


if __name__ == "__main__":
    unittest.main()
