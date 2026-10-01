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
