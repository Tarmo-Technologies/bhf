#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Unwrap hard-wrapped Markdown: each paragraph, list item and block-quote
paragraph on one source line.

Lines are joined only inside a paragraph. Fenced and indented code blocks,
tables, headings, HTML blocks, link reference definitions, front matter,
thematic breaks and explicit hard line breaks (two trailing spaces, a
trailing backslash or a trailing <br>) are left as they are.

  unwrap-markdown.py FILE...          rewrite the files in place
  unwrap-markdown.py --check FILE...  list wrapped paragraphs; exit 1 if any
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

FENCE = re.compile(r"^(\s*)(`{3,}|~{3,})")
LIST_ITEM = re.compile(r"^(\s*)([-*+]|\d{1,9}[.)])(\s+)(.*)$")
HEADING = re.compile(r"^\s{0,3}#{1,6}(\s|$)")
SETEXT = re.compile(r"^\s{0,3}(=+|-+)\s*$")
THEMATIC = re.compile(r"^\s{0,3}([-*_])(\s*\1){2,}\s*$")
TABLE = re.compile(r"^\s*\|")
TABLE_DELIM = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$")
LINK_DEF = re.compile(r"^\s{0,3}\[[^\]]+\]:\s")
# CommonMark's block-level HTML tags (plus <br> and <img> on their own line);
# a line that starts with an inline tag such as <strong> or <a> is paragraph text.
HTML_START = re.compile(
    r"^\s{0,3}<(/?(address|article|aside|blockquote|body|caption|center|col|colgroup|dd|details|dialog"
    r"|dir|div|dl|dt|fieldset|figcaption|figure|footer|form|h[1-6]|head|header|hr|html|iframe|legend"
    r"|li|link|main|menu|nav|noframes|ol|optgroup|option|p|param|section|summary|table|tbody|td|tfoot"
    r"|th|thead|title|tr|ul|pre|script|style|br|img|picture|source)\b|!--)",
    re.IGNORECASE,
)
QUOTE = re.compile(r"^(\s{0,3}>\s?)(.*)$")


def hard_break(line: str) -> bool:
    return line.endswith("  ") or line.rstrip().endswith("\\") or line.rstrip().lower().endswith("<br>")


def is_block_line(line: str) -> bool:
    """A line that is never joined to the one before or after it."""
    return bool(
        not line.strip()
        or HEADING.match(line)
        or THEMATIC.match(line)
        or TABLE.match(line)
        or LINK_DEF.match(line)
        or HTML_START.match(line)
    )


def unwrap(text: str) -> str:
    lines = text.split("\n")
    out: list[str] = []
    i = 0
    n = len(lines)
    # Front matter.
    if n and lines[0].strip() == "---":
        end = next((j for j in range(1, n) if lines[j].strip() == "---"), None)
        if end is not None:
            out.extend(lines[: end + 1])
            i = end + 1
    fence: str | None = None
    html_comment = False
    prev_blank = True
    while i < n:
        line = lines[i]
        if fence is not None:
            out.append(line)
            m = FENCE.match(line)
            if m and m.group(2)[0] == fence[0] and len(m.group(2)) >= len(fence) and not line.strip()[len(m.group(2)):].strip():
                fence = None
            i += 1
            prev_blank = False
            continue
        if html_comment:
            out.append(line)
            if "-->" in line:
                html_comment = False
            i += 1
            continue
        m = FENCE.match(line)
        if m:
            fence = m.group(2)
            out.append(line)
            i += 1
            prev_blank = False
            continue
        if line.lstrip().startswith("<!--") and "-->" not in line:
            html_comment = True
            out.append(line)
            i += 1
            continue
        # Indented code block: four or more spaces after a blank line, outside a list.
        if prev_blank and line.startswith("    ") and line.strip() and not (out and _in_list(out)):
            while i < n and (lines[i].startswith("    ") or not lines[i].strip()):
                if not lines[i].strip() and (i + 1 >= n or not lines[i + 1].startswith("    ")):
                    break
                out.append(lines[i])
                i += 1
            prev_blank = False
            continue
        if is_block_line(line):
            out.append(line)
            prev_blank = not line.strip()
            i += 1
            continue
        # A paragraph, a list item or a block-quote paragraph: gather its lines.
        q = QUOTE.match(line)
        if q:
            prefix = q.group(1)
            parts = [q.group(2)]
            i += 1
            if not parts[0].strip():
                out.append(line)
                prev_blank = True
                continue
            while i < n:
                nq = QUOTE.match(lines[i])
                if not nq or not nq.group(2).strip() or hard_break(parts[-1]):
                    break
                inner = nq.group(2)
                if is_block_line(inner) or LIST_ITEM.match(inner) or FENCE.match(inner):
                    break
                parts.append(inner.strip())
                i += 1
            out.append(prefix + _join(parts))
            prev_blank = False
            continue
        lm = LIST_ITEM.match(line)
        if lm:
            indent = len(lm.group(1)) + len(lm.group(2)) + len(lm.group(3))
            parts = [line.rstrip("\n")]
            i += 1
            while i < n:
                nxt = lines[i]
                if not nxt.strip() or hard_break(parts[-1]) or is_block_line(nxt) or FENCE.match(nxt) or LIST_ITEM.match(nxt) or QUOTE.match(nxt) or SETEXT.match(nxt):
                    break
                lead = len(nxt) - len(nxt.lstrip(" "))
                if lead > indent + 3:
                    break  # an indented code block inside the item
                parts.append(nxt.strip())
                i += 1
            out.append(_join(parts))
            prev_blank = False
            continue
        # Plain paragraph.
        parts = [line]
        i += 1
        while i < n:
            nxt = lines[i]
            if not nxt.strip() or hard_break(parts[-1]) or is_block_line(nxt) or FENCE.match(nxt) or LIST_ITEM.match(nxt) or QUOTE.match(nxt):
                break
            if SETEXT.match(nxt):
                break
            parts.append(nxt.strip())
            i += 1
        out.append(_join(parts))
        prev_blank = False
    return "\n".join(out)


def _in_list(out: list[str]) -> bool:
    for prev in reversed(out):
        if not prev.strip():
            continue
        return bool(LIST_ITEM.match(prev)) or prev.startswith("  ")
    return False


def _join(parts: list[str]) -> str:
    first = parts[0].rstrip()
    rest = [p.strip() for p in parts[1:]]
    return " ".join([first] + rest) if rest else parts[0]


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--check", action="store_true", help="report wrapped paragraphs, change nothing")
    p.add_argument("files", nargs="+", type=Path)
    args = p.parse_args(argv)
    bad = 0
    for f in args.files:
        text = f.read_text(encoding="utf-8")
        new = unwrap(text)
        if new == text:
            continue
        if args.check:
            bad += 1
            print(f"{f}: has hard-wrapped paragraphs ({len(text.splitlines()) - len(new.splitlines())} line breaks to join)")
        else:
            f.write_text(new, encoding="utf-8")
            print(f"unwrapped {f}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
