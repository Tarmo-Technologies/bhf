# SPDX-License-Identifier: Apache-2.0
"""The full Linux bundle carries the user documentation, and its links work.

scripts/stage-dist-docs.sh copies the documentation into the bundle with the
repository layout, install.sh copies it into the install prefix, and
scripts/check-doc-links.py checks that the relative links of the front pages
resolve there. These tests stage the documentation, install a minimal bundle
with the real installer, and check the links in both places, and that every
guide is within two links of README.md. Every cargo-dist component archive
(the CLI, the daemon and the two Linux shims) carries the same documentation
beside its README.md; those tests lay an archive out from the package's
include list the way cargo-dist does, check its links, and check the layout
against `dist manifest` when cargo-dist is installed.
"""
from __future__ import annotations

from collections import deque
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import textwrap
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[3]
STAGE = ROOT / "scripts/stage-dist-docs.sh"
CHECKER = ROOT / "scripts/check-doc-links.py"
FRONT_PAGES = ["README.md", "INSTALL.md", "docs/README.md", "docs/site/index.md"]
# The packages that cargo-dist builds a component archive for, by archive
# name, and the pages whose links must resolve inside each archive.
COMPONENT_PACKAGES = {
    "bhf": ROOT / "crates/cli",
    "bhf-daemon": ROOT / "crates/daemon",
    "bhf_runtrace_shim": ROOT / "crates/bhf_runtrace_shim",
    "bhf_cc_intercept": ROOT / "crates/bhf_cc_intercept",
}
ARCHIVE_PAGES = ["README.md", "INSTALL.md", "docs/site/index.md"]
# cargo-dist adds these to every archive without an `include` entry: the
# package directory's copy, or the workspace root's when the package has none.
DIST_AUTO_INCLUDES = ("README.md", "LICENSE", "CHANGELOG.md")
DOCS_STEP = "Validate the documentation in every Linux component archive"

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


def component_archive_entries(package: Path) -> dict[str, Path]:
    """The top-level entries of `package`'s cargo-dist archive, each with its
    source: the auto-included files, then every `include` path under its own
    name (a directory is copied whole)."""
    config = tomllib.loads((package / "Cargo.toml").read_text())["package"]["metadata"]["dist"]
    entries = {}
    for name in DIST_AUTO_INCLUDES:
        entries[name] = package / name if (package / name).is_file() else ROOT / name
    for include in config.get("include", []):
        source = (package / include).resolve()
        entries[source.name] = source
    return entries


def stage_component_archive(package: Path, dest: Path) -> Path:
    dest.mkdir(parents=True)
    for name, source in component_archive_entries(package).items():
        if source.is_dir():
            shutil.copytree(source, dest / name)
        else:
            shutil.copy2(source, dest / name)
    return dest


def release_step_script(name: str) -> str:
    """The `run:` script of the release workflow step called `name`."""
    workflow = (ROOT / ".github/workflows/release.yml").read_text()
    step = workflow.split(f"      - name: {name}\n", 1)[1].split("\n      - ", 1)[0]
    return textwrap.dedent(step.split("        run: |\n", 1)[1])


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


class ComponentArchiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="bhf component archives ")
        cls.archives = {name: stage_component_archive(package, Path(cls.tmp.name) / name)
                        for name, package in COMPONENT_PACKAGES.items()}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_every_package_cargo_dist_archives_is_checked(self):
        archived = set()
        for manifest in ROOT.glob("crates/*/Cargo.toml"):
            package = tomllib.loads(manifest.read_text())["package"]
            if package.get("metadata", {}).get("dist", {}).get("dist"):
                archived.add(package["name"])
        self.assertEqual(archived, set(COMPONENT_PACKAGES))

    def test_each_archive_holds_the_documentation_beside_its_readme(self):
        for name, root in self.archives.items():
            with self.subTest(archive=name):
                self.assertTrue((root / "README.md").is_file())
                for directory in ("docs/site", "docs/site/img", "examples", "schemas"):
                    self.assertTrue((root / directory).is_dir(), directory)
                self.assertTrue((root / "schemas/bhf.findings.v1.schema.json").is_file())

    def test_the_front_page_links_resolve_inside_each_archive(self):
        for name, root in self.archives.items():
            with self.subTest(archive=name):
                result = check_links(root, *ARCHIVE_PAGES)
                self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which("dist"), "cargo-dist is not installed")
    def test_dist_lays_out_each_archive_as_staged_here(self):
        result = subprocess.run(["dist", "manifest", "--artifacts=all", "--output-format=json",
                                 "--no-local-paths"], cwd=ROOT, capture_output=True, text=True,
                                timeout=600)
        self.assertEqual(result.returncode, 0, result.stderr)
        artifacts = json.loads(result.stdout)["artifacts"]
        for name, package in COMPONENT_PACKAGES.items():
            archives = [artifact for key, artifact in artifacts.items()
                        if artifact.get("kind") == "executable-zip"
                        and re.match(rf"{re.escape(name)}-(x86_64|aarch64)-", key)]
            self.assertTrue(archives, name)
            for archive in archives:
                with self.subTest(archive=archive["name"]):
                    # The built binary or shared library is the component, not an include.
                    paths = {asset["path"] for asset in archive["assets"]
                             if asset["kind"] not in ("executable", "c_dynamic_library")}
                    self.assertEqual(paths, set(component_archive_entries(package)))

    def run_release_check(self, drop: str | None = None) -> subprocess.CompletedProcess:
        """Run the release workflow's documentation check over archives packed
        from the staged layouts, with `drop` removed from the CLI archive."""
        target = "x86_64-unknown-linux-gnu"
        with tempfile.TemporaryDirectory(prefix="bhf release docs ") as tmp:
            work = Path(tmp)
            (work / "scripts").mkdir()
            shutil.copy2(CHECKER, work / "scripts/check-doc-links.py")
            (work / "target/distrib").mkdir(parents=True)
            for name, staged in self.archives.items():
                tree = work / "trees" / name / f"{name}-{target}"
                shutil.copytree(staged, tree)
                if drop and name == "bhf":
                    shutil.rmtree(tree / drop)
                subprocess.run(["tar", "-cJf", str(work / f"target/distrib/{name}-{target}.tar.xz"),
                                "-C", str(tree.parent), tree.name], check=True, timeout=300,
                               env=dict(os.environ, XZ_OPT="-0"))
            return subprocess.run(["bash", "-c", release_step_script(DOCS_STEP)], cwd=work,
                                  env=dict(os.environ, DIST_TARGET=target),
                                  capture_output=True, text=True, timeout=300)

    def test_the_release_checks_the_documentation_in_each_archive(self):
        result = self.run_release_check()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.count("every link in 3 file(s) resolves"), len(COMPONENT_PACKAGES),
                         result.stdout)

    def test_the_release_check_fails_an_archive_without_the_documentation(self):
        result = self.run_release_check(drop="examples")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing examples/ from target/distrib/bhf-x86_64-unknown-linux-gnu.tar.xz",
                      result.stderr)


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
