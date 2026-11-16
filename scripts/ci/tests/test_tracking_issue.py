# SPDX-License-Identifier: Apache-2.0
"""Run tracking-issue.py against a stand-in `gh` that keeps issues in a file,
so a sequence of runs shows what a repository would end up with."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/ci/tracking-issue.py"

FAKE_GH = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
state_path = pathlib.Path(os.environ["FAKE_GH_STATE"])
state = json.loads(state_path.read_text()) if state_path.exists() else {"issues": [], "labels": [], "calls": []}
args = sys.argv[1:]
state["calls"].append(args)
def opt(name):
    return args[args.index(name) + 1] if name in args else None
def issue(number):
    return next(i for i in state["issues"] if i["number"] == int(number))
status = 0
if os.environ.get("FAKE_GH_FAIL") and args[:2] == os.environ["FAKE_GH_FAIL"].split():
    print("HTTP 403: Resource not accessible by integration", file=sys.stderr)
    status = 1
elif args[:2] == ["label", "create"]:
    if args[2] not in state["labels"]:
        state["labels"].append(args[2])
elif args[:2] == ["issue", "list"]:
    assert opt("--state") == "open" and opt("--repo") == "owner/repo", args
    print(json.dumps([{"number": i["number"], "body": i["body"], "url": i["url"]} for i in state["issues"]
                      if i["state"] == "open" and opt("--label") in i["labels"]]))
elif args[:2] == ["issue", "create"]:
    if opt("--label") not in state["labels"]:
        print(f"could not add label: '{opt('--label')}' not found", file=sys.stderr)
        status = 1
    else:
        number = len(state["issues"]) + 1
        state["issues"].append({"number": number, "title": opt("--title"), "labels": [opt("--label")],
                                "body": pathlib.Path(opt("--body-file")).read_text(), "state": "open",
                                "url": f"https://github.com/owner/repo/issues/{number}", "comments": []})
        print(f"https://github.com/owner/repo/issues/{number}")
elif args[:2] == ["issue", "edit"]:
    issue(args[2])["body"] = pathlib.Path(opt("--body-file")).read_text()
elif args[:2] == ["issue", "comment"]:
    issue(args[2])["comments"].append(pathlib.Path(opt("--body-file")).read_text())
else:
    status = 2
state_path.write_text(json.dumps(state))
sys.exit(status)
'''


class TrackingIssueTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.gh = self.root / "gh"
        self.gh.write_text(FAKE_GH)
        self.gh.chmod(0o755)
        self.state = self.root / "state.json"
        self.body = self.root / "body.md"
        self.comment = self.root / "comment.md"
        self.comment.write_text("The list changed.\n")

    def sync(self, body: str, *extra: str, key: str = "widget-scan", fail: str = "") -> subprocess.CompletedProcess:
        self.body.write_text(body)
        env = dict(os.environ, GH=str(self.gh), FAKE_GH_STATE=str(self.state), FAKE_GH_FAIL=fail)
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--repo", "owner/repo", "--key", key, "--label", "ci-tracking",
             "--title", "Widget scan found problems", "--body-file", str(self.body), *extra],
            env=env, capture_output=True, text=True, timeout=30)

    def issues(self) -> list[dict]:
        return json.loads(self.state.read_text())["issues"]

    def test_first_run_opens_one_labelled_issue(self):
        result = self.sync("Two problems.\n", "--fingerprint", "abc123", "--comment-file", str(self.comment))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["action"], "opened")
        [issue] = self.issues()
        self.assertEqual(issue["title"], "Widget scan found problems")
        self.assertEqual(issue["labels"], ["ci-tracking"])
        self.assertTrue(issue["body"].startswith("Two problems.\n"))
        self.assertIn("<!-- bhf-tracking-issue: widget-scan -->", issue["body"])
        self.assertIn("<!-- bhf-tracking-fingerprint: abc123 -->", issue["body"])
        self.assertEqual(issue["comments"], [], "a new issue needs no comment")

    def test_second_run_updates_the_open_issue_instead_of_opening_another(self):
        self.assertEqual(self.sync("Two problems.\n", "--fingerprint", "abc123").returncode, 0)
        result = self.sync("Two problems, seen again.\n", "--fingerprint", "abc123",
                           "--comment-file", str(self.comment))
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual((report["action"], report["number"], report["commented"]), ("updated", 1, False))
        [issue] = self.issues()
        self.assertTrue(issue["body"].startswith("Two problems, seen again.\n"))
        self.assertEqual(issue["comments"], [], "an unchanged fingerprint does not notify again")

    def test_a_changed_fingerprint_comments_on_the_open_issue(self):
        self.assertEqual(self.sync("Two problems.\n", "--fingerprint", "abc123").returncode, 0)
        result = self.sync("Three problems.\n", "--fingerprint", "def456", "--comment-file", str(self.comment))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["commented"])
        [issue] = self.issues()
        self.assertEqual(issue["comments"], ["The list changed.\n"])
        self.assertIn("<!-- bhf-tracking-fingerprint: def456 -->", issue["body"])
        self.assertNotIn("abc123", issue["body"])

    def test_other_keys_and_closed_issues_are_left_alone(self):
        self.assertEqual(self.sync("Other.\n", key="other-scan").returncode, 0)
        self.assertEqual(self.sync("Mine.\n").returncode, 0)
        state = json.loads(self.state.read_text())
        state["issues"][1]["state"] = "closed"
        self.state.write_text(json.dumps(state))
        result = self.sync("Mine again.\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["action"], "opened")
        bodies = [(issue["number"], issue["state"], issue["body"].splitlines()[0]) for issue in self.issues()]
        self.assertEqual(bodies, [(1, "open", "Other."), (2, "closed", "Mine."), (3, "open", "Mine again.")])

    def test_a_gh_failure_fails_the_run(self):
        result = self.sync("Two problems.\n", fail="issue list")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Resource not accessible", result.stderr)
        self.assertFalse(json.loads(self.state.read_text())["issues"])

    def test_keys_and_fingerprints_that_could_end_the_marker_are_refused(self):
        for extra, key in ((("--fingerprint", "a -->"), "widget-scan"), ((), "bad key")):
            with self.subTest(key=key, extra=extra):
                result = self.sync("x\n", *extra, key=key)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.state.exists() and json.loads(self.state.read_text())["issues"])


if __name__ == "__main__":
    unittest.main()
