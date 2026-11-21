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
import publish
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


class ReportSurfaceTests(unittest.TestCase):
    """The `report` surface reads the findings where the `auto` run wrote them."""

    def run_project(self, layout: str) -> tuple[dict, list[list[str]]]:
        calls = []

        def fake_sh(args, cwd, timeout, env_extra=None, keep_stdout=False):
            calls.append(args)
            if args[1] == "auto":
                work = Path(args[args.index("--work-dir") + 1])
                write(work / layout / "F-0000-aa" / "finding.json", {"rule_id": "BHF-201"})
            if args[1] == "report":
                (Path(args[args.index("--out") + 1]) / "findings.sarif").parent.mkdir(parents=True)
                (Path(args[args.index("--out") + 1]) / "findings.sarif").write_text("{}")
            return {"cmd": " ".join(args[1:]), "exit": 0, "wall_s": 0.1, "timed_out": False, "panic": False}

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            tree = root / "tree"
            tree.mkdir()
            args = mock.Mock(wave="w1", pins={}, surfaces="fuzz,report", campaign_time=1, per_target_time=1,
                             max_attempts=1, max_repair_rounds=0, inner_jobs=1, max_targets=0,
                             single_pass=False, force=False, auto_slack=1, keep_clone=True, keep_work=False)
            with mock.patch.object(run_sweep, "WORK_ROOT", root / "work"), \
                    mock.patch.object(run_sweep, "sh", fake_sh), \
                    mock.patch.object(run_sweep.bc, "clone_repo", return_value=(tree, "0" * 40)), \
                    mock.patch.object(run_sweep.bc, "check_lane", return_value=(True, "ok")):
                row = run_sweep.run_project({"lane": "c", "repo": "acme/parse_record", "url": "x"}, args)
            work = root / "work" / "c__acme__parse_record"
            for call in calls:
                if call[1] == "report":
                    call[call.index("--findings") + 1] = str(Path(call[call.index("--findings") + 1])
                                                             .relative_to(work))
        return row, calls

    def test_the_report_surface_reads_the_findings_under_results(self):
        row, calls = self.run_project("results/findings")
        [report] = [call for call in calls if call[1] == "report"]
        self.assertEqual(report[report.index("--findings") + 1], "results/findings")
        self.assertEqual(row["surfaces"]["report"]["emitted"], [".sarif"])

    def test_the_report_surface_reads_an_older_bhfs_findings(self):
        row, calls = self.run_project("findings")
        [report] = [call for call in calls if call[1] == "report"]
        self.assertEqual(report[report.index("--findings") + 1], "findings")
        self.assertIn("report", row["surfaces"])


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


class PublishTests(unittest.TestCase):
    PAGE = Path(publish.HERE).parents[1] / "docs/site/sweep-500.md"

    def publish_to(self, page: Path, *args: str) -> None:
        with mock.patch("sys.argv", ["publish.py", "--page", str(page), *args]), \
                mock.patch("builtins.print"):
            publish.main()

    def test_republishing_the_committed_rows_leaves_the_reviewed_page_unchanged(self):
        with TemporaryDirectory() as tmp:
            page = Path(tmp) / "sweep-500.md"
            page.write_text(self.PAGE.read_text())
            self.publish_to(page)
            self.assertEqual(page.read_text(), self.PAGE.read_text())

    def test_only_the_pinned_projects_are_counted(self):
        def row(lane, repo, sloc, surfaces):
            return {"lane": lane, "repo": repo, "status": "done",
                    "surfaces": {"sloc": {"sloc_total": sloc}, **surfaces}}
        auto = {"auto": {"summary": {"discovered_total": 7, "built_and_fuzzed": 1, "failed_build": 1,
                                     "findings": 2},
                         "blockers": [{"language": "c", "detail": "no decoder for Widget", "count": 3}]}}
        with TemporaryDirectory() as tmp:
            work = Path(tmp)
            write(work / "results/c__acme__parse_record.json", row("c", "acme/parse_record", 900, auto))
            write(work / "results/c__acme__copy_at.json", row("c", "acme/copy_at", 100, {"static": {"timed_out": True}}))
            write(work / "results/c__acme__replaced.json", row("c", "acme/replaced", 5000, auto))
            (work / "corpus.tsv").write_text(
                "# lane\trepo\tclone_url\n"
                "c\tacme/parse_record\thttps://example.invalid/a.git\n"
                "c\tacme/copy_at\thttps://example.invalid/b.git\n"
                "c\tacme/never_ran\thttps://example.invalid/c.git\n")
            page = work / "page.md"
            page.write_text("# Sweep\n\n## Results\n\nold\n\n## Reading the blocker table\n\nkept\n")
            self.publish_to(page, "--results", str(work / "results"), "--corpus", str(work / "corpus.tsv"))
            text = page.read_text()
        self.assertIn("1 projects measured out of 3 pinned, 1,000 lines of code, 7 fuzzable targets "
                      "discovered, with no harness written by hand.", text)
        self.assertIn("| C | 2 | 1 | 1,000 | 7 | 2 | 1 | 50% | 2 |", text)
        self.assertIn("| **All 1** | **2** | **1** | **1,000** | **7** | **2** | **1** | **50.0%** | **2** |", text)
        self.assertIn("Across the 2 pinned projects and 4 surface invocations: **0 panics**, **1 timeouts**.",
                      text)
        self.assertIn("| 3 | c | no decoder for Widget |", text)
        self.assertNotIn("old", text)
        self.assertTrue(text.endswith("## Reading the blocker table\n\nkept\n"))

    def test_the_blocker_table_ranks_what_bhf_could_not_drive_and_leaves_out_build_failures(self):
        blockers = [
            {"language": "c", "category": "failed_build", "detail": "missing header", "count": 9},
            {"language": "c", "category": "unsupported_params", "detail": "no decoder for Widget", "count": 3},
            {"language": "cpp", "category": "report_only", "detail": "header copy_at.h is not self-contained",
             "count": 2},
        ]
        row = {"lane": "c", "repo": "acme/parse_record", "status": "done",
               "surfaces": {"auto": {"summary": {"discovered_total": 4, "failed_build": 9}, "blockers": blockers}}}
        with TemporaryDirectory() as tmp:
            work = Path(tmp)
            write(work / "results/c__acme__parse_record.json", row)
            (work / "corpus.tsv").write_text("c\tacme/parse_record\thttps://example.invalid/a.git\n")
            page = work / "page.md"
            page.write_text("# Sweep\n\n## Results\n\nold\n\n## Reading the blocker table\n\nkept\n")
            self.publish_to(page, "--results", str(work / "results"), "--corpus", str(work / "corpus.tsv"))
            table = page.read_text().split("### What blocked the rest", 1)[1]
        self.assertIn("| Targets | Language | Cause |\n|---:|---|---|\n"
                      "| 3 | c | no decoder for Widget |\n"
                      "| 2 | cpp | header copy_at.h is not self-contained |\n\n", table)
        self.assertNotIn("missing header", table)


if __name__ == "__main__":
    unittest.main()
