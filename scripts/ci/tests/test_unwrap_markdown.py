# SPDX-License-Identifier: Apache-2.0
"""Markdown in the repository keeps each paragraph and list item on one source
line (a terminal or a viewer wraps it), and unwrap-markdown.py joins only the
lines of a paragraph."""
from __future__ import annotations

import importlib.util
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/ci/unwrap-markdown.py"
spec = importlib.util.spec_from_file_location("unwrap_markdown", SCRIPT)
unwrap_markdown = importlib.util.module_from_spec(spec)
spec.loader.exec_module(unwrap_markdown)
unwrap = unwrap_markdown.unwrap

# Markdown that is not ours to reflow: vendored and licence texts, a legal
# notice, test fixtures whose bytes a test compares, generated reports, and
# the roadmap its owner edits by hand.
EXEMPT = re.compile(
    r"^(vendor/|ROADMAP\.md$|.*LICENSE\.md$|docker/compliance/WRITTEN-OFFER\.md$"
    r"|tests/fixtures/golden_results/|benchmarks/.*/static-out/)"
)


def tracked_markdown() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z", "*.md"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.split("\0")
    return [ROOT / p for p in out if p and not EXEMPT.match(p)]


class UnwrapTests(unittest.TestCase):
    def test_a_wrapped_paragraph_and_list_item_become_one_line_each(self):
        text = "First line of a\nparagraph here.\n\n- an item that\n  wraps\n  - a nested\n    item\n"
        self.assertEqual(
            unwrap(text),
            "First line of a paragraph here.\n\n- an item that wraps\n  - a nested item\n",
        )

    def test_code_tables_headings_and_hard_breaks_are_left_alone(self):
        text = (
            "# A heading\n\n"
            "```sh\nbhf auto ./src \\\n  --work-dir w\n```\n\n"
            "| a | b |\n|---|---|\n| 1 | 2 |\n\n"
            "line one  \nline two\n\n"
            "    indented code\n    more code\n"
        )
        self.assertEqual(unwrap(text), text)

    def test_a_block_quote_paragraph_joins_inside_the_quote(self):
        self.assertEqual(unwrap("> quoted text\n> that wraps\n"), "> quoted text that wraps\n")

    def test_a_blank_quote_line_keeps_the_next_paragraph_outside_the_list(self):
        self.assertEqual(
            unwrap("> - one item\n>   with a continuation\n>\n> New paragraph\n> that wraps\n"),
            "> - one item with a continuation\n>\n> New paragraph that wraps\n",
        )

    def test_an_inline_tag_at_a_line_start_is_paragraph_text(self):
        self.assertEqual(
            unwrap('<p align="center">\n<strong>bhf</strong> fuzzes\ncode.\n</p>\n'),
            '<p align="center">\n<strong>bhf</strong> fuzzes code.\n</p>\n',
        )

    def test_unwrapping_changes_whitespace_only_and_is_idempotent(self):
        for path in tracked_markdown():
            text = path.read_text(encoding="utf-8")
            once = unwrap(text)
            strip = lambda s: re.sub(r"(?m)^\s*>\s?", "", s).split()
            self.assertEqual(strip(once), strip(text), path)
            self.assertEqual(unwrap(once), once, path)


class RepositoryMarkdownTests(unittest.TestCase):
    def test_no_tracked_markdown_is_hard_wrapped(self):
        wrapped = [str(p.relative_to(ROOT)) for p in tracked_markdown() if unwrap(p.read_text(encoding="utf-8")) != p.read_text(encoding="utf-8")]
        self.assertEqual(wrapped, [], "run scripts/ci/unwrap-markdown.py on these files")


if __name__ == "__main__":
    unittest.main()
