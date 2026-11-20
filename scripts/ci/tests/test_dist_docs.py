# SPDX-License-Identifier: Apache-2.0
"""The full Linux bundle carries the user documentation, and its links work.

scripts/stage-dist-docs.sh copies the documentation into the bundle with the
repository layout, install.sh copies it into the install prefix, and
scripts/check-doc-links.py checks that the relative links of the front pages
resolve there. These tests stage the documentation, install a minimal bundle
with the real installer, and check the links in both places, and that every
guide is within two links of README.md.
"""
from __future__ import annotations

from collections import deque
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
STAGE = ROOT / "scripts/stage-dist-docs.sh"
CHECKER = ROOT / "scripts/check-doc-links.py"
FRONT_PAGES = ["README.md", "INSTALL.md", "docs/README.md", "docs/site/index.md"]

_spec = importlib.util.spec_from_file_location("check_doc_links", CHECKER)
check_doc_links = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_doc_links)


def stage(dest: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(STAGE), str(ROOT), str(dest)],
                          capture_output=True, text=True, timeout=60)


def check_links(root: Path, *files: str) -> subprocess.CompletedProcess:
    return subprocess.run(["python3", str(CHECKER), "--root", str(root), *files],
                          capture_output=True, text=True, timeout=60)


def guides(root: Path) -> list[Path]:
    """The pages a reader must reach from README.md within two links."""
    pages = sorted((root / "docs/site").glob("*.md"))
    pages += sorted((root / "docs").glob("*.md"))
    pages += sorted((root / "examples").glob("*/README.md"))
    pages.append(root / "benchmarks/engine-comparison/METHODOLOGY.md")
    return pages


def link_depths(root: Path, start: str = "README.md") -> dict[Path, int]:
    """Each Markdown file's distance, in links, from `start`."""
    first = (root / start).resolve()
    depth = {first: 0}
    queue = deque([first])
    while queue:
        page = queue.popleft()
        for _, target in check_doc_links.links(page.read_text(encoding="utf-8")):
            if check_doc_links.SCHEME.match(target) or target.startswith("#"):
                continue
            path = (page.parent / target.partition("#")[0]).resolve()
            if path.suffix == ".md" and path.is_file() and path not in depth:
                depth[path] = depth[page] + 1
                queue.append(path)
    return depth


class StagedDocumentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="bhf dist docs ")
        cls.bundle = Path(cls.tmp.name) / "bhf-dist-test"
        result = stage(cls.bundle)
        assert result.returncode == 0, result.stderr

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_the_bundle_holds_the_user_documentation(self):
        for page in FRONT_PAGES + ["LICENSE", "NOTICE", "THIRD_PARTY.md", "RELEASE_NOTES.md",
                                   "docs/recommended-sweep.md", "docs/finding-report-fields.md",
                                   "benchmarks/engine-comparison/METHODOLOGY.md",
                                   "schemas/bhf.findings.v1.schema.json"]:
            self.assertTrue((self.bundle / page).is_file(), page)
        for source in (ROOT / "docs/site").glob("*.md"):
            self.assertTrue((self.bundle / "docs/site" / source.name).is_file(), source.name)
        for image in (ROOT / "docs/site/img").iterdir():
            self.assertTrue((self.bundle / "docs/site/img" / image.name).is_file(), image.name)
        for readme in (ROOT / "examples").glob("*/README.md"):
            self.assertTrue((self.bundle / readme.relative_to(ROOT)).is_file(), readme)

    def test_front_page_links_resolve_inside_the_bundle(self):
        result = check_links(self.bundle, *FRONT_PAGES)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_every_guide_is_within_two_links_of_the_readme(self):
        depth = link_depths(self.bundle)
        far = [str(page.relative_to(self.bundle)) for page in guides(self.bundle)
               if depth.get(page.resolve(), 99) > 2]
        self.assertEqual(far, [], "not reachable from README.md within two links")

    def test_staging_again_replaces_the_directories(self):
        stale = self.bundle / "docs/stale-page.md"
        stale.write_text("old\n")
        result = stage(self.bundle)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(stale.exists())

    def test_staging_refuses_a_tree_that_is_not_a_checkout(self):
        with tempfile.TemporaryDirectory() as empty:
            result = subprocess.run(["bash", str(STAGE), empty, str(Path(empty) / "out")],
                                    capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not a bhf checkout", result.stderr)


class CheckoutLinkTests(unittest.TestCase):
    def test_front_page_links_resolve_in_the_checkout(self):
        result = check_links(ROOT, *FRONT_PAGES)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_front_page_links_are_relative(self):
        for page in FRONT_PAGES:
            text = (ROOT / page).read_text(encoding="utf-8")
            for _, target in check_doc_links.links(text):
                if target.startswith(("https://github.com/Tarmo-Technologies/bhf/blob/",
                                      "https://github.com/Tarmo-Technologies/bhf/tree/")):
                    path = target.split("/", 7)[-1].partition("#")[0]
                    # The verifier is fetched from the repository on purpose:
                    # it must not come from the bundle it verifies.
                    self.assertEqual(path, "scripts/verify-offline-dist.py", f"{page}: {target}")


class InstalledPrefixTests(unittest.TestCase):
    def test_install_sh_copies_the_documentation_into_the_prefix(self):
        with tempfile.TemporaryDirectory(prefix="bhf install docs ") as tmp:
            bundle = Path(tmp) / "bundle"
            result = stage(bundle)
            self.assertEqual(result.returncode, 0, result.stderr)
            (bundle / "tool").mkdir()
            fake = bundle / "tool/bhf"
            fake.write_text("#!/bin/sh\nexit 0\n")
            fake.chmod(0o755)
            (bundle / "RUN-BHF.md").write_text("# Running BHF\n")
            (bundle / "VERSION").write_text("version=test\n")
            prefix = Path(tmp) / "prefix"
            install = subprocess.run(
                ["bash", str(ROOT / "scripts/install-dist.sh"), "--non-interactive",
                 "--no-system-packages", "--no-rustup", "--no-symlink", "--no-content", "--no-smoke",
                 "--languages", "python", "--targets", "none", "--fuzzers", "none", "--extras", "none",
                 "--prefix", str(prefix)],
                cwd=bundle, capture_output=True, text=True, timeout=120,
                env=dict(os.environ, BHF_INSTALL_NO_GUI="1"))
            self.assertEqual(install.returncode, 0, install.stdout + install.stderr)
            for page in FRONT_PAGES + ["RUN-BHF.md", "VERSION", "LICENSE", "NOTICE",
                                       "docs/site/img/sast-signal.png"]:
                self.assertTrue((prefix / page).is_file(), page)
            result = check_links(prefix, *FRONT_PAGES)
            self.assertEqual(result.returncode, 0, result.stderr)


class PackagingWiringTests(unittest.TestCase):
    def test_the_packager_stages_the_documentation(self):
        script = (ROOT / "scripts/package-offline-dist.sh").read_text()
        self.assertIn('run bash "$SCRIPT_DIR/stage-dist-docs.sh" "$REPO_ROOT" "$STAGE_ROOT"', script)
        with tempfile.TemporaryDirectory() as out:
            result = subprocess.run(
                ["bash", str(ROOT / "scripts/package-offline-dist.sh"), "--dry-run", "--skip-build",
                 "--legacy-integrity-only", "--out", out, "--version", "test"],
                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("stage-dist-docs.sh", result.stdout)

    def test_the_release_checks_the_documentation_in_the_bundle_and_the_prefix(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn('python3 scripts/check-doc-links.py --root "$bundle_root"', workflow)
        self.assertIn('python3 scripts/check-doc-links.py --root "$install_root/prefix"', workflow)
        self.assertIn('test -d "$bundle_root/docs/site/img"', workflow)


class CheckerTests(unittest.TestCase):
    def run_checker(self, files: dict[str, str], *pages: str) -> subprocess.CompletedProcess:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for name, text in files.items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(text)
        return check_links(root, *pages)

    def test_a_missing_file_and_a_missing_heading_fail(self):
        result = self.run_checker({
            "README.md": "[a](docs/a.md#usage) [b](docs/gone.md) [c](docs/a.md#gone)\n",
            "docs/a.md": "# Title\n\n## Usage\n",
        }, "README.md")
        self.assertEqual(result.returncode, 1)
        self.assertIn("docs/gone.md (no such file)", result.stderr)
        self.assertIn("docs/a.md#gone (no such heading)", result.stderr)
        self.assertNotIn("#usage", result.stderr)

    def test_code_external_links_and_github_anchors_pass(self):
        result = self.run_checker({
            "README.md": (
                "See [the guide](docs/a.md#choice-1-all-in-one-installsh-bundle),\n"
                "[options](docs/a.md#tuning-with-san_options), [again](docs/a.md#usage-1),\n"
                "[site](https://example.invalid/x.md), [top](#readme) and `[x](nowhere.md)`.\n"
                "<a href=\"LICENSE\">license</a>\n\n# Readme\n\n"
                "```sh\n[y](nowhere.md)\n```\n"),
            "LICENSE": "text\n",
            "docs/a.md": ("## Choice 1: all-in-one `install.sh` bundle\n"
                          "## Tuning with `<SAN>_OPTIONS`\n## Usage\n## Usage\n"),
        }, "README.md")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_link_out_of_the_root_fails(self):
        result = self.run_checker({"README.md": "[up](../outside.md)\n"}, "README.md")
        self.assertEqual(result.returncode, 1)
        self.assertIn("outside the root", result.stderr)


if __name__ == "__main__":
    unittest.main()
