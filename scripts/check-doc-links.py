#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check that the relative links in Markdown files resolve under a root.

Each FILE is a path relative to --root. Every relative link in it (Markdown
`[text](target)`, reference definitions, and HTML `href`/`src` attributes)
must name a file or directory that exists under the root, and a `#fragment`
must name a heading (GitHub's anchor rules) or an `id`/`name` anchor of the
Markdown file it points to. Links with a URL scheme (https:, mailto:) are not
checked. Code blocks and code spans are skipped.

The release workflow runs this over the extracted Linux bundle and the
installed prefix, so the documentation links work offline. Exit status: 0
when every link resolves, 1 when one does not, 2 on a usage error.
"""
import argparse
import re
import sys
from pathlib import Path

INLINE_LINK = re.compile(r"!?\[(?:[^\[\]]|\[[^\[\]]*\])*\]\(\s*(<[^>]*>|[^)\s]+)(?:\s+\"[^\"]*\")?\s*\)")
REFERENCE = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*(<[^>]*>|\S+)")
HTML_ATTR = re.compile(r"\b(?:href|src)\s*=\s*\"([^\"]*)\"", re.IGNORECASE)
HTML_ANCHOR = re.compile(r"<a\s[^>]*\b(?:id|name)\s*=\s*\"([^\"]+)\"", re.IGNORECASE)
HEADING = re.compile(r"^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$")
SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
FENCE = re.compile(r"^\s{0,3}(`{3,}|~{3,})")


def prose_lines(text):
    """Yield (line number, line) outside fenced code blocks."""
    fence = None
    for number, line in enumerate(text.splitlines(), 1):
        match = FENCE.match(line)
        if match:
            marker = match.group(1)
            if fence is None:
                fence = marker[0]
            elif marker[0] == fence:
                fence = None
            continue
        if fence is None:
            yield number, line


def strip_code_spans(line):
    return re.sub(r"(`+)(?:(?!\1).)+\1", "", line)


def links(text):
    for number, line in prose_lines(text):
        line = strip_code_spans(line)
        for pattern in (INLINE_LINK, REFERENCE, HTML_ATTR):
            for match in pattern.finditer(line):
                target = match.group(1).strip()
                if target.startswith("<") and target.endswith(">"):
                    target = target[1:-1]
                yield number, target


def slug(heading):
    """GitHub's anchor for a heading's text."""
    parts = []
    # A code span renders as literal text; outside one, images and HTML tags
    # render as nothing and a link as its text.
    for index, part in enumerate(re.split(r"(`+[^`]*`+)", heading)):
        if index % 2:
            parts.append(part.strip("`"))
            continue
        part = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", part)
        part = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", part)
        part = re.sub(r"<[^>]+>", "", part)
        parts.append(part.replace("*", ""))
    text = "".join(parts).strip().lower()
    text = re.sub(r"[^\w\- ]", "", text, flags=re.UNICODE)
    return text.replace(" ", "-")


def anchors(text):
    found = set()
    seen = {}
    for _, line in prose_lines(text):
        for match in HTML_ANCHOR.finditer(line):
            found.add(match.group(1))
        match = HEADING.match(line)
        if not match:
            continue
        base = slug(match.group(2))
        count = seen.get(base, 0)
        seen[base] = count + 1
        found.add(base if count == 0 else "{}-{}".format(base, count))
    return found


def check(root, relative):
    """Return the broken links of one file, as printable strings."""
    root = root.resolve()
    source = (root / relative).resolve()
    if not source.is_file():
        return ["{}: no such file under {}".format(relative, root)]
    text = source.read_text(encoding="utf-8")
    cache = {}
    broken = []
    for number, target in links(text):
        if not target or SCHEME.match(target):
            continue
        path, _, fragment = target.partition("#")
        path = path.split("?", 1)[0]
        resolved = (source.parent / path).resolve() if path else source
        where = "{}:{}: {}".format(relative, number, target)
        try:
            resolved.relative_to(root)
        except ValueError:
            broken.append(where + " (outside the root)")
            continue
        if not resolved.exists():
            broken.append(where + " (no such file)")
            continue
        if fragment and resolved.is_file() and resolved.suffix.lower() == ".md":
            if resolved not in cache:
                cache[resolved] = anchors(resolved.read_text(encoding="utf-8"))
            if fragment not in cache[resolved]:
                broken.append(where + " (no such heading)")
    return broken


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, required=True, help="directory the links must resolve in")
    parser.add_argument("files", nargs="+", help="Markdown files to check, relative to --root")
    args = parser.parse_args(argv)
    if not args.root.is_dir():
        print("check-doc-links.py: --root is not a directory: {}".format(args.root), file=sys.stderr)
        return 2
    broken = []
    for relative in args.files:
        broken.extend(check(args.root, relative))
    for line in broken:
        print("broken link: " + line, file=sys.stderr)
    if broken:
        return 1
    print("check-doc-links.py: every link in {} file(s) resolves under {}".format(len(args.files), args.root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
