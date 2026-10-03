# SPDX-License-Identifier: Apache-2.0
"""The bhf.collector-event.v1 contract validates against its checked-in JSON Schema.

This is the normative wire-format gate for the platform-neutral runtime-event
collector (#60): the Rust golden test in `crates/runtime_collector/tests` pins the
serde round-trip, and this one pins the externally-implementable JSON Schema so an
out-of-repo provider can target the exact wire format. Runs in the `ci-policy` job
(one Linux job) where `jsonschema` is pip-installed.
"""

import json
import unittest
from pathlib import Path

import jsonschema  # CI: pip install jsonschema (see .github/workflows/ci.yml)

ROOT = Path(__file__).resolve().parents[3]
SCHEMAS = ROOT / "schemas"
SCHEMA_FILE = SCHEMAS / "bhf.collector-event.v1.schema.json"
EXAMPLE = SCHEMAS / "examples" / "collector-event.v1.example.json"
GOLDEN = ROOT / "crates" / "runtime_collector" / "tests" / "fixtures" / "golden.jsonl"
MALFORMED = ROOT / "crates" / "runtime_collector" / "tests" / "fixtures" / "malformed.jsonl"


def _validator():
    schema = json.loads(SCHEMA_FILE.read_text())
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)
    return cls(schema, format_checker=cls.FORMAT_CHECKER)


def _nonblank_lines(path: Path):
    return [line for line in path.read_text().splitlines() if line.strip()]


class CollectorSchemaTest(unittest.TestCase):
    def test_schema_is_a_valid_2020_12_schema(self):
        schema = json.loads(SCHEMA_FILE.read_text())
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        _validator()  # raises if the schema itself is invalid

    def test_example_event_validates(self):
        doc = json.loads(EXAMPLE.read_text())
        errors = list(_validator().iter_errors(doc))
        self.assertEqual([e.message for e in errors], [])

    def test_every_golden_line_validates(self):
        validator = _validator()
        lines = _nonblank_lines(GOLDEN)
        self.assertNotEqual(lines, [], "golden corpus must not be empty")
        kinds = set()
        for line in lines:
            doc = json.loads(line)
            with self.subTest(seq=doc.get("seq")):
                self.assertEqual([e.message for e in validator.iter_errors(doc)], [])
            kinds.add(doc["kind"])
        # The golden corpus must exercise every known event family.
        self.assertTrue(
            {
                "process_create",
                "shell_execute",
                "file_create",
                "file_open",
                "file_write",
                "file_rename",
                "file_delete",
                "module_load",
                "network",
                "registry",
            }.issubset(kinds),
            f"golden corpus is missing an event family: {sorted(kinds)}",
        )

    def test_malformed_lines_are_rejected(self):
        validator = _validator()
        for line in _nonblank_lines(MALFORMED):
            with self.subTest(line=line[:40]):
                try:
                    doc = json.loads(line)
                except json.JSONDecodeError:
                    continue  # unparseable JSON is rejected before schema validation
                self.assertNotEqual(
                    list(validator.iter_errors(doc)),
                    [],
                    f"a malformed event must fail schema validation: {line}",
                )

    def test_unknown_kind_is_accepted_for_forward_compat(self):
        # A newer provider's kind must validate (it is preserved, not dropped).
        doc = {
            "schema": "bhf.collector-event.v1",
            "testcase": "tc",
            "worker": 0,
            "seq": 1,
            "phase": "event",
            "kind": "some_future_kind",
        }
        self.assertEqual(list(_validator().iter_errors(doc)), [])

    def test_bad_phase_is_rejected(self):
        doc = {
            "schema": "bhf.collector-event.v1",
            "testcase": "tc",
            "worker": 0,
            "seq": 1,
            "phase": "not_a_phase",
            "kind": "process_create",
        }
        self.assertNotEqual(list(_validator().iter_errors(doc)), [])


if __name__ == "__main__":
    unittest.main()
