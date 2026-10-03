# SPDX-License-Identifier: Apache-2.0
"""The bhf.extension.v1 request/response contract validates against its JSON Schema.

This is the externally-implementable wire-format gate for the versioned
out-of-process extension protocol (#57): the Rust golden test in
`crates/extension_host/tests/schema_fixtures.rs` pins the serde round-trip (the
host's real parser), and this one pins the published JSON Schema so an out-of-repo
extension — in any language — can target the exact wire format. Both validate the
SAME committed fixtures, so the two layers can never drift.

Runs in the `ci-policy` job (one Linux job) where `jsonschema` is pip-installed.
"""

import json
import unittest
from pathlib import Path

import jsonschema  # CI: pip install jsonschema (see .github/workflows/ci.yml)

ROOT = Path(__file__).resolve().parents[3]
SCHEMAS = ROOT / "schemas"
REQUEST_SCHEMA = SCHEMAS / "bhf.extension.v1.request.schema.json"
RESPONSE_SCHEMA = SCHEMAS / "bhf.extension.v1.response.schema.json"

FIXTURES = ROOT / "crates" / "extension_host" / "tests" / "fixtures"
REQUEST_FIXTURE = FIXTURES / "oracle_evaluate.request.json"
OK_RESPONSE = FIXTURES / "oracle_ok.response.json"
FINDING_RESPONSE = FIXTURES / "oracle_finding.response.json"
MALFORMED_RESPONSE = FIXTURES / "malformed.response.json"
# The codec/mutator/scenario/lifecycle capabilities carry their structured output
# in a non-oracle `value` channel; these golden fixtures pin that wire shape too.
CODEC_REPAIR_REQUEST = FIXTURES / "codec_repair.request.json"
CODEC_REPAIR_RESPONSE = FIXTURES / "codec_repair.response.json"
SCENARIO_NEXT_RESPONSE = FIXTURES / "scenario_next.response.json"


def _validator(schema_file: Path):
    schema = json.loads(schema_file.read_text())
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)
    return cls(schema, format_checker=cls.FORMAT_CHECKER)


class ExtensionSchemaTest(unittest.TestCase):
    def test_schemas_are_valid_2020_12(self):
        for schema_file in (REQUEST_SCHEMA, RESPONSE_SCHEMA):
            with self.subTest(schema=schema_file.name):
                schema = json.loads(schema_file.read_text())
                self.assertEqual(
                    schema["$schema"], "https://json-schema.org/draft/2020-12/schema"
                )
                # Every wire object closes the door on unknown keys so a forged or
                # extended message is a bounded protocol error, not silently
                # accepted. Check the top-level object and each $def.
                self.assertFalse(schema.get("additionalProperties", True))
                for name, sub in schema.get("$defs", {}).items():
                    if sub.get("type") == "object":
                        with self.subTest(defn=name):
                            self.assertFalse(sub.get("additionalProperties", True))
                _validator(schema_file)  # raises if the schema itself is invalid

    def test_request_fixtures_validate(self):
        validator = _validator(REQUEST_SCHEMA)
        for fixture in (REQUEST_FIXTURE, CODEC_REPAIR_REQUEST):
            with self.subTest(fixture=fixture.name):
                doc = json.loads(fixture.read_text())
                self.assertEqual([e.message for e in validator.iter_errors(doc)], [])

    def test_ok_and_finding_responses_validate(self):
        validator = _validator(RESPONSE_SCHEMA)
        for fixture in (
            OK_RESPONSE,
            FINDING_RESPONSE,
            CODEC_REPAIR_RESPONSE,
            SCENARIO_NEXT_RESPONSE,
        ):
            with self.subTest(fixture=fixture.name):
                doc = json.loads(fixture.read_text())
                self.assertEqual([e.message for e in validator.iter_errors(doc)], [])

    def test_capability_value_channel_carries_structured_output(self):
        # The non-oracle `value` channel is part of the published contract: a
        # codec.repair ok carries repaired bytes; scenario.next carries the next
        # message + label.
        repair = json.loads(CODEC_REPAIR_RESPONSE.read_text())
        self.assertIn("output_b64", repair["value"])
        self.assertNotIn("finding", repair)
        nxt = json.loads(SCENARIO_NEXT_RESPONSE.read_text())
        self.assertEqual(nxt["value"]["label"], "OPEN")
        self.assertIn("message_b64", nxt["value"])
        # An oracle ok still carries no value channel.
        self.assertNotIn("value", json.loads(OK_RESPONSE.read_text()))

    def test_finding_response_carries_rule_signature_and_evidence(self):
        doc = json.loads(FINDING_RESPONSE.read_text())
        finding = doc["finding"]
        # The schema permits these; assert the golden fixture actually exercises
        # them so the published contract and the captured bytes stay in step.
        self.assertEqual(finding["rule"], "oracle.path-escape")
        self.assertTrue(finding["signature_inputs"])
        self.assertTrue(finding["evidence"])
        self.assertEqual(finding["min_predicate"], "path-contains-dotdot")

    def test_malformed_response_is_rejected(self):
        # The malformed fixture is valid JSON but carries an unknown top-level key;
        # additionalProperties:false must reject it (it is the same fixture the Rust
        # envelope test proves `deny_unknown_fields` rejects).
        doc = json.loads(MALFORMED_RESPONSE.read_text())
        errors = list(_validator(RESPONSE_SCHEMA).iter_errors(doc))
        self.assertNotEqual(
            errors, [], "a response with an unknown field must fail schema validation"
        )

    def test_request_missing_required_field_is_rejected(self):
        doc = json.loads(REQUEST_FIXTURE.read_text())
        del doc["payload"]
        errors = list(_validator(REQUEST_SCHEMA).iter_errors(doc))
        self.assertNotEqual(errors, [], "a request missing `payload` must be rejected")

    def test_bad_result_class_is_rejected(self):
        doc = json.loads(OK_RESPONSE.read_text())
        doc["result"] = "not_a_result_class"
        errors = list(_validator(RESPONSE_SCHEMA).iter_errors(doc))
        self.assertNotEqual(errors, [], "an unknown result class must be rejected")


if __name__ == "__main__":
    unittest.main()
