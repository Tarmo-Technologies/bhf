# SPDX-License-Identifier: Apache-2.0
"""The sweep's row extraction, commit pinning and Go classes."""

import json
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

import build_corpus
import go1_rerun
import run_sweep
from go_resweep_compare import go_class


def write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


class DistilRunTests(unittest.TestCase):
    def test_findings_are_read_from_results_and_failed_builds_keep_their_cause(self):
        with TemporaryDirectory() as tmp:
            work = Path(tmp)
            write(
                work / "auto" / "run.json",
                {
                    "summary": {"findings": 1},
                    "targets": [
                        {
                            "name": "Parse",
                            "source": "pkg/parse.go",
                            "outcome": {
                                "outcome": "failed_build",
                                "last_errors": [{"kind": "missing_module"}],
                            },
                        }
                    ],
                },
            )
            write(
                work / "results" / "findings" / "F-0000-aa" / "finding.json",
                {
                    "rule_id": "BHF-201",
                    "harness_id": "H-G0001",
                    "cluster_normalized_frames": ["a", "b", "c", "d", "e"],
                    "exception": {"message": "index out of range"},
                },
            )
            # A legacy layout beside it is not read when results/ exists.
            write(work / "findings" / "F-OLD" / "finding.json", {"rule_id": "BHF-999"})
            row = run_sweep.distil_run(work)
        self.assertIn("missing_module", row["targets"][0]["reason"])
        [finding] = row["findings_detail"]
        self.assertEqual(finding["rule"], "BHF-201")
        self.assertEqual(finding["frames"], ["a", "b", "c", "d"])
        self.assertEqual(finding["message"], "index out of range")


class PinTests(unittest.TestCase):
    def test_a_results_dir_pins_each_row_to_its_commit(self):
        with TemporaryDirectory() as tmp:
            write(Path(tmp) / "go__a__b.json", {"repo": "a/b", "sha": "1" * 40})
            write(Path(tmp) / "go__c__d.json", {"repo": "c/d", "status": "clone_failed"})
            self.assertEqual(run_sweep.read_pins(Path(tmp)), {"go__a__b": "1" * 40})

    def test_a_pinned_clone_checks_out_that_commit(self):
        with TemporaryDirectory() as tmp:
            origin = Path(tmp) / "origin"
            origin.mkdir()

            def git(*args, cwd=origin):
                return subprocess.run(
                    ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
                    cwd=cwd,
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.strip()

            git("init", "-q")
            (origin / "f").write_text("one")
            git("add", "f")
            git("commit", "-qm", "one")
            first = git("rev-parse", "HEAD")
            (origin / "f").write_text("two")
            git("commit", "-qam", "two")
            git("config", "uploadpack.allowReachableSHA1InWant", "true")
            with mock.patch.object(build_corpus, "CORPUS_ROOT", Path(tmp) / "corpus"):
                url = origin.as_uri()
                tree, sha = build_corpus.clone_repo("go", "o/r", url, sha=first)
                self.assertEqual(sha, first)
                self.assertEqual((tree / "f").read_text(), "one")
                # A clone of another commit is replaced.
                head = git("rev-parse", "HEAD")
                tree, _ = build_corpus.clone_repo("go", "o/r", url, sha=head)
                self.assertEqual((tree / "f").read_text(), "two")


class GoClassTests(unittest.TestCase):
    def test_reasons_map_to_the_expected_gaps_classes(self):
        cases = {
            "unsupported Go parameter type `*zap.Logger` (skipped)": "Go-1",
            "Go method `Run` needs a receiver value and its type ...": "Go-2 method",
            "Go receiver type `*mkcert` of method `Run` is not nameable from the "
            "harness package (unexported or generic)": "Go-2 receiver",
            "target is not inside a Go module (no go.mod found)": "Go-3",
            "go: x requires go >= 1.25.0 (running go 1.22.2)": "Go-4",
        }
        for reason, prefix in cases.items():
            klass = go_class({"outcome": "unsupported_params", "reason": reason})
            self.assertTrue(klass.startswith(prefix), (reason, klass))


class GoRerunTests(unittest.TestCase):
    def test_a_class_is_selected_per_row_with_its_multiplicity(self):
        go3 = "target is not inside a Go module (no go.mod found)"
        go1 = "unsupported Go parameter type `*zap.Logger` (skipped)"

        def row(targets):
            return {"repo": "o/r", "sha": "s", "surfaces": {"auto": {"targets": targets}}}

        def target(source, name, reason):
            return {
                "source": source,
                "name": name,
                "outcome": "unsupported_params",
                "reason": reason,
            }

        with TemporaryDirectory() as tmp:
            before = Path(tmp)
            (before / "go__o__r.json").write_text(
                json.dumps(
                    row(
                        [
                            target("build.go", "FixHeader", go3),
                            target("build.go", "FixHeader", go3),
                            target("api.go", "Serve", go1),
                        ]
                    )
                )
            )
            (before / "ruby__o__r.json").write_text(
                json.dumps(row([target("locales.go", "Asset", go3), target("x.rb", "run", go3)]))
            )
            go_lane = go1_rerun.wanted_targets(before, "Go-3", all_lanes=False)
            self.assertEqual(list(go_lane), ["go__o__r.json"])
            self.assertEqual(go_lane["go__o__r.json"][1], {("build.go", "FixHeader"): 2})
            every_lane = go1_rerun.wanted_targets(before, "Go-3", all_lanes=True)
            self.assertEqual(every_lane["ruby__o__r.json"][1], {("locales.go", "Asset"): 1})
            self.assertEqual(
                go1_rerun.wanted_targets(before, "Go-1", all_lanes=False)["go__o__r.json"][1],
                {("api.go", "Serve"): 1},
            )

    def test_java_targets_are_selected_by_their_own_classes(self):
        java1 = "Java target 'join' parameter #0 has an unsupported type `List<String>`"
        with TemporaryDirectory() as tmp:
            before = Path(tmp)
            row = {
                "repo": "o/r",
                "sha": "s",
                "surfaces": {
                    "auto": {
                        "targets": [
                            {"source": "Parts.java", "name": "join", "reason": java1},
                            {"source": "parts.go", "name": "Join", "reason": java1},
                        ]
                    }
                },
            }
            (before / "cobol__o__r.json").write_text(json.dumps(row))
            wanted = go1_rerun.wanted_targets(before, "Java-1", all_lanes=True, lang="java")
            self.assertEqual(wanted["cobol__o__r.json"][1], {("Parts.java", "join"): 1})
            self.assertEqual(
                go1_rerun.wanted_targets(before, "Java-1", all_lanes=False, lang="java"), {}
            )
        self.assertEqual(go1_rerun.java_class({"outcome": "built_and_fuzzed"}), "built and fuzzed")


if __name__ == "__main__":
    unittest.main()
