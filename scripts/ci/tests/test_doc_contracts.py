# SPDX-License-Identifier: Apache-2.0
"""The fast release and documentation contract tests run on every change.

These tests read README.md, INSTALL.md, docs/site/*.md and the release
workflows, and finish in seconds, but used to run only in the nightly: a
contract broke main twice, and a documentation-only change skipped them
entirely. build-test runs them for a code change; the doc-contracts lane runs
them for a documentation-only change. The classifier step is run with a
stand-in git, so the lane a path selects is the workflow's own answer.

Every Rust test that reads a documentation page (a file under docs/, or a
Markdown page at the repository root) is found by scanning the test sources,
and the doc-contracts lane must build and select each one, so a new contract
test that the lane's filter does not name fails here.
"""
from __future__ import annotations

from dataclasses import dataclass
import fnmatch
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import textwrap
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[3]
CI = ROOT / ".github/workflows/ci.yml"
TESTS = ROOT / "crates/cli/tests"

# Each fast contract and the repository file it reads, which a change to that
# file alone must still test.
CONTRACTS = {
    "m19_docs_cli_examples": "docs/site/cli.md",
    "m19_signed_releases": "docs/site/install.md",
    "m19_docs_site": "docs/site/index.md",
    "offline_dist_scripts": "docs/site/offline-auto-runbook.md",
    "release_bundle_manifest": "README.md",
}
# Tests in other binaries that read a guide.
GUIDE_TESTS = {
    "custom_harness_flow": ("the_guides_do_not_repeat_retired_claims",
                            "the_sanitizer_guide_says_which_emulated_children_name_each_key_once"),
}
LIB_GUIDE_TESTS = ("the_docs_list_every_config_key", "the_help_and_docs_list_every_cross_lane")
# Tests that pin help text the documentation repeats. They read no page; the
# doc lane runs them with the page tests.
HELP_CONTRACT_BINARIES = ("command_help_cli",)
HELP_CONTRACT_LIB_TESTS = ("auto::config::tests::the_config_help_lists_every_config_key",)
# Tests that read a page through library code, which the scan cannot see: the
# page is named in another crate's code, and the test passes only the
# repository root. Each test (in `source`) and the page that `library` reads.
INDIRECT_DOC_READERS = (
    # bhf license-audit checks THIRD_PARTY.md's rows and GCC RLE boundary text.
    ("bhf", "tests::license_audit_subcommand_exits_zero_for_current_repo", "crates/cli/src/lib.rs",
     "THIRD_PARTY.md", "crates/license_policy/src/lib.rs"),
)


@dataclass(frozen=True)
class RustTest:
    """One Rust test as nextest names it: its package, its target kind (`lib`,
    `bin` or `test`), its binary, and its path inside the binary. A `name` of
    None stands for the binary as a whole."""
    package: str
    kind: str
    binary: str
    name: str | None = None


def bhf_test(binary: str, name: str | None = None) -> RustTest:
    return RustTest("bhf", "test", binary, name)


def lib_test(package: str, name: str | None = None) -> RustTest:
    return RustTest(package, "lib", package.replace("-", "_"), name)


def job(name: str) -> str:
    block = CI.read_text().split(f"\n  {name}:\n", 1)[1]
    return re.split(r"\n  [a-z][a-z0-9-]*:\n", block, maxsplit=1)[0]


def nextest_command(job_text: str) -> str:
    [command] = re.findall(r"(?m)^\s+run: (cargo nextest run --locked (?:--workspace|-p bhf) .*)$", job_text)
    return command


def nextest_filter(job_text: str) -> str:
    return re.search(r"-E '([^']+)'", nextest_command(job_text))[1]


def selected(job_text: str, heavy: str) -> bool:
    """Whether `job_text`'s `if:` runs the job for classifier output `heavy`."""
    condition = re.search(r"(?m)^    if: (.+)$", job_text)[1]
    match = re.fullmatch(r"needs\.changes\.outputs\.heavy == '(true|false)'", condition)
    assert match, f"unsupported lane condition: {condition}"
    return heavy == match[1]


def name_matches(matcher: str, value: str | None, default: str) -> bool:
    """A nextest name matcher: `=` equal, `~` contains, `/re/` a regex search,
    `#` a glob, and a bare one `default`."""
    if value is None:
        return False
    if len(matcher) > 1 and matcher.startswith("/") and matcher.endswith("/"):
        return re.search(matcher[1:-1], value) is not None
    kind, pattern = (matcher[0], matcher[1:]) if matcher[:1] in ("=", "~", "#") else (default, matcher)
    if kind == "=":
        return value == pattern
    if kind == "~":
        return pattern in value
    return fnmatch.fnmatchcase(value, pattern)


FILTER_TOKEN = re.compile(r"\s*(?:(\()|(\))|(\|)|(&)|(not)\b|([a-z_]+)\(([^()]*)\))")
# Each predicate's default matcher, as nextest has them.
PREDICATE_DEFAULTS = {"binary": "#", "test": "~", "kind": "#", "package": "#"}


def filter_selects(expression: str, test: RustTest) -> bool:
    """Whether the nextest filterset `expression` selects `test`; for a `name`
    of None, whether a term that names no test selects its binary. This reads
    the subset these workflows write: `|`, `&`, `not`, parentheses, and the
    `binary()`, `test()`, `kind()` and `package()` predicates."""
    tokens = []
    position, end = 0, len(expression.rstrip())
    while position < end:
        match = FILTER_TOKEN.match(expression, position)
        assert match, f"unsupported filter at {expression[position:]!r}"
        tokens.append(match)
        position = match.end()
    values = {"binary": test.binary, "test": test.name, "kind": test.kind, "package": test.package}

    def alternatives(at: int) -> tuple[bool, int]:
        result, at = conjunction(at)
        while at < len(tokens) and tokens[at][3]:
            right, at = conjunction(at + 1)
            result = result or right
        return result, at

    def conjunction(at: int) -> tuple[bool, int]:
        result, at = factor(at)
        while at < len(tokens) and tokens[at][4]:
            right, at = factor(at + 1)
            result = result and right
        return result, at

    def factor(at: int) -> tuple[bool, int]:
        token = tokens[at]
        if token[5]:
            result, at = factor(at + 1)
            return not result, at
        if token[1]:
            result, at = alternatives(at + 1)
            assert at < len(tokens) and tokens[at][2], f"unbalanced filter: {expression}"
            return result, at + 1
        predicate = token[6]
        assert predicate in PREDICATE_DEFAULTS, f"unsupported predicate {predicate}() in {expression}"
        return name_matches(token[7], values[predicate], PREDICATE_DEFAULTS[predicate]), at + 1

    result, at = alternatives(0)
    assert at == len(tokens), f"unsupported filter: {expression}"
    return result


def lane_runs(command: str, test: RustTest) -> bool:
    """Whether the `cargo nextest run` `command` builds `test`'s binary and its
    filter selects `test`."""
    words = shlex.split(command.split(" -E ", 1)[0])
    packages = [words[i + 1] for i, word in enumerate(words) if word == "-p"]
    targets = [words[i + 1] for i, word in enumerate(words) if word == "--test"]
    # Naming any target limits the build to the named ones.
    limited = bool(targets) or "--lib" in words or "--bins" in words
    if "--workspace" not in words and test.package not in packages:
        return False
    if limited and test.kind == "lib" and "--lib" not in words:
        return False
    if limited and test.kind == "bin" and "--bins" not in words:
        return False
    if limited and test.kind == "test" and not any(fnmatch.fnmatchcase(test.binary, t) for t in targets):
        return False
    return filter_selects(re.search(r"-E '([^']+)'", command)[1], test)


# A Rust source as tokens: comments, raw and plain string literals, char
# literals, identifiers, and everything else.
RUST_TOKEN = re.compile(
    r"""(?P<comment>//[^\n]*|/\*.*?\*/)"""
    r"""|b?r(?P<hashes>#*)"(?P<raw>.*?)"(?P=hashes)"""
    r"""|b?"(?P<string>(?:\\.|[^"\\])*)\""""
    r"""|(?P<char>'(?:\\(?:u\{[0-9A-Fa-f]+\}|x[0-9A-Fa-f]{2}|.)|[^'\\\n])')"""
    r"""|[A-Za-z_][A-Za-z0-9_]*|\s+|.""",
    re.S,
)
# A path naming a documentation page: a file under docs/, or a Markdown page
# at the repository root. Relative to a crate (`../../docs/site/cli.md`,
# `../../README.md`) it is the repository's page; without the `../` it counts
# when the same function calls `repo_root()` or `workspace_root()`. That errs
# toward running a test that only touches a fixture of the same name.
UP_DOC_PATH = re.compile(r"^(?:\.\./)+(docs/\S*|[A-Z][A-Z0-9_]*\.md)$")
ROOT_DOC_PATH = re.compile(r"^(docs/\S+|[A-Z][A-Z0-9_]*\.md)$")
REPO_ROOT_CALL = re.compile(r"\b(?:repo_root|workspace_root)\s*\(")


def names_a_doc_page(path: str) -> bool:
    return path.startswith("docs/") or (ROOT / path).is_file()


def rust_code(text: str) -> tuple[str, list[str]]:
    """`text` with comments blanked, char literals emptied, and each string
    literal replaced by `\\x00N\\x00`, N its index in the returned list."""
    code, literals = [], []
    for match in RUST_TOKEN.finditer(text):
        if match["comment"] is not None:
            code.append(" ")
        elif match["char"] is not None:
            code.append("' '")
        elif match["raw"] is not None or match["string"] is not None:
            code.append(f"\x00{len(literals)}\x00")
            literals.append(match["raw"] if match["raw"] is not None else match["string"])
        else:
            code.append(match[0])
    return "".join(code), literals


def rust_items(code: str) -> list[tuple[str, str, int, int]]:
    """(`fn` or `mod`, name, start, end of body) for each item with a body."""
    items = []
    for match in re.finditer(r"\b(fn|mod)\s+([A-Za-z_][A-Za-z0-9_]*)", code):
        # The body starts at the first `{` outside the signature's brackets
        # (`-> [u8; 4]`); a `;` there first is a declaration without one.
        depth, at = 0, match.end()
        while at < len(code) and not (depth == 0 and code[at] in "{;"):
            if code[at] in "([":
                depth += 1
            elif code[at] in ")]":
                depth -= 1
            at += 1
        if at == len(code) or code[at] == ";":
            continue
        depth, end = 0, at
        while end < len(code):
            if code[end] == "{":
                depth += 1
            elif code[end] == "}":
                depth -= 1
                if depth == 0:
                    break
            end += 1
        items.append((match[1], match[2], match.start(), end))
    return items


def scan_rust_tests(text: str, package: str, kind: str, binary: str, module: list[str]) -> list[RustTest]:
    """The tests of one Rust source that read a documentation page, directly
    or through a function or constant of the same source that does."""
    code, literals = rust_code(text)
    items = rust_items(code)
    functions = [item for item in items if item[0] == "fn"]
    modules = [item for item in items if item[0] == "mod"]

    def reads_doc(body: str) -> bool:
        for index in re.findall(r"\x00(\d+)\x00", body):
            literal = literals[int(index)]
            match = UP_DOC_PATH.match(literal)
            if match and names_a_doc_page(match[1]):
                return True
            match = ROOT_DOC_PATH.match(literal)
            if match and names_a_doc_page(match[1]) and REPO_ROOT_CALL.search(body):
                return True
        return False

    readers = {name for _, name, start, end in functions if reads_doc(code[start:end])}
    constants = {match[1] for match in re.finditer(r"\b(?:const|static)\s+([A-Z_][A-Z0-9_]*)\s*:[^=;]*=([^;]*);", code)
                 if reads_doc(match[2])}
    changed = True
    while changed:
        changed = False
        uses = [rf"(?<![.\w]){re.escape(name)}\s*\(" for name in readers]
        uses += [rf"\b{re.escape(name)}\b" for name in constants]
        if not uses:
            break
        pattern = re.compile("|".join(uses))
        for _, name, start, end in functions:
            if name not in readers and pattern.search(code, start, end):
                readers.add(name)
                changed = True
    found = []
    for _, name, start, end in functions:
        boundary = max(code.rfind(";", 0, start), code.rfind("{", 0, start), code.rfind("}", 0, start))
        if name not in readers or not re.search(r"#\[(?:\w+::)*test\]", code[boundary + 1:start]):
            continue
        inside = [mod for _, mod, mod_start, mod_end in modules if mod_start < start and end <= mod_end]
        found.append(RustTest(package, kind, binary, "::".join(module + inside + [name])))
    return found


def doc_reading_tests() -> list[RustTest]:
    """Every test of the workspace's crates that reads a documentation page."""
    tests = []
    for manifest in sorted(ROOT.glob("crates/*/Cargo.toml")):
        crate = manifest.parent
        package = tomllib.loads(manifest.read_text())["package"]["name"]
        for source in sorted((crate / "src").rglob("*.rs")):
            parts = list(source.relative_to(crate / "src").with_suffix("").parts)
            if parts[0] == "main":
                kind, binary, module = "bin", package, []
            elif parts[0] == "bin":
                kind, binary, module = "bin", parts[1], []
            else:
                kind, binary = "lib", package.replace("-", "_")
                module = parts[:-1] if parts[-1] in ("lib", "mod") else parts
            tests += scan_rust_tests(source.read_text(encoding="utf-8"), package, kind, binary, module)
        for source in sorted((crate / "tests").glob("*.rs")):
            tests += scan_rust_tests(source.read_text(encoding="utf-8"), package, "test", source.stem, [])
    return tests


def classify(*paths: str) -> str:
    """The `heavy` output the classifier step writes for a change to `paths`."""
    workflow = (ROOT / ".github/workflows/classify-ci-scope.yml").read_text()
    step = workflow.split("      - name: Classify changed paths\n", 1)[1]
    script = textwrap.dedent(step.split("        run: |\n", 1)[1])
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        (work / "bin").mkdir()
        (work / "scripts/ci").mkdir(parents=True)
        classifier = work / "scripts/ci/should-run-heavy-ci.sh"
        classifier.write_bytes((ROOT / "scripts/ci/should-run-heavy-ci.sh").read_bytes())
        classifier.chmod(0o755)
        (work / "paths.bin").write_bytes(b"".join(path.encode() + b"\0" for path in paths))
        git = work / "bin/git"
        git.write_text('#!/usr/bin/env bash\nif [[ "$1" == diff ]]; then cat "$FAKE_PATHS"; fi\n')
        git.chmod(0o755)
        output = work / "output"
        env = dict(os.environ, PATH=f"{work / 'bin'}{os.pathsep}{os.environ['PATH']}", EVENT_NAME="pull_request",
                   BASE_SHA="a" * 40, HEAD_SHA="b" * 40, GITHUB_OUTPUT=str(output),
                   GITHUB_STEP_SUMMARY=str(work / "summary"), FAKE_PATHS=str(work / "paths.bin"))
        subprocess.run(["bash", "-e", "-o", "pipefail", "-c", script], cwd=work, env=env,
                       check=True, capture_output=True, timeout=10)
        return re.fullmatch(r"heavy=(true|false)\n", output.read_text())[1]


class DocContractLaneTests(unittest.TestCase):
    def setUp(self):
        self.build_test = job("build-test")
        self.docs = job("doc-contracts")
        self.pr_filter = nextest_filter(self.build_test)
        self.doc_filter = nextest_filter(self.docs)

    def test_a_change_to_only_docs_site_cli_md_selects_the_doc_contract_lane(self):
        heavy = classify("docs/site/cli.md")
        self.assertEqual(heavy, "false")
        self.assertTrue(selected(self.docs, heavy))
        self.assertFalse(selected(self.build_test, heavy))
        self.assertTrue(filter_selects(self.doc_filter, bhf_test("m19_docs_cli_examples")))

    def test_each_contract_runs_for_a_change_to_only_the_file_it_reads(self):
        for binary, path in CONTRACTS.items():
            with self.subTest(binary=binary, path=path):
                self.assertTrue((ROOT / path).is_file(), path)
                self.assertIn(path, (TESTS / f"{binary}.rs").read_text())
                heavy = classify(path)
                lane = self.docs if selected(self.docs, heavy) else self.build_test
                self.assertTrue(selected(lane, heavy))
                self.assertTrue(filter_selects(nextest_filter(lane), bhf_test(binary)), (binary, heavy))

    def test_a_code_change_runs_the_contracts_in_build_test(self):
        heavy = classify("crates/cli/src/lib.rs")
        self.assertEqual(heavy, "true")
        self.assertTrue(selected(self.build_test, heavy))
        self.assertFalse(selected(self.docs, heavy))

    def test_the_per_pr_filter_includes_the_fast_contract_binaries(self):
        binaries = sorted(path.stem for path in TESTS.glob("m19_*.rs")) + ["offline_dist_scripts",
                                                                           "release_bundle_manifest"]
        self.assertGreaterEqual(len(binaries), 6)
        for lane_filter in (self.pr_filter, self.doc_filter):
            for binary in binaries:
                with self.subTest(binary=binary, lane=lane_filter[:40]):
                    self.assertTrue(filter_selects(lane_filter, bhf_test(binary)))
            for binary, tests in GUIDE_TESTS.items():
                source = (TESTS / f"{binary}.rs").read_text()
                for test in tests:
                    with self.subTest(binary=binary, test=test):
                        self.assertIn(f"fn {test}()", source)
                        self.assertTrue(filter_selects(lane_filter, bhf_test(binary, f"linux::{test}")))
                        self.assertFalse(filter_selects(lane_filter, bhf_test(binary, "linux::fuzz_to_finding_x")))
        # The heavy lane already runs every library test; the doc lane runs
        # the ones that read a guide.
        config = (ROOT / "crates/cli/src/auto/config.rs").read_text()
        for test in LIB_GUIDE_TESTS:
            with self.subTest(test=test):
                self.assertIn(f"fn {test}()", config)
                self.assertTrue(filter_selects(self.doc_filter, lib_test("bhf", f"auto::config::tests::{test}")))
        self.assertFalse(filter_selects(self.doc_filter, lib_test("bhf", "auto::config::tests::list_and_selection_keys")))
        self.assertFalse(filter_selects(self.doc_filter, bhf_test("auto_c_common_cli")))

    def test_the_doc_lane_builds_only_and_every_contract_binary(self):
        command = nextest_command(self.docs)
        words = shlex.split(command.split(" -E ", 1)[0])
        targets = [words[i + 1] for i, word in enumerate(words) if word == "--test"]
        self.assertIn("--lib", words)
        self.assertNotIn("--workspace", words)
        binaries = [path.stem for path in TESTS.glob("*.rs")]
        built = sorted(binary for binary in binaries if any(fnmatch.fnmatchcase(binary, t) for t in targets))
        wanted = sorted(binary for binary in binaries if filter_selects(self.doc_filter, bhf_test(binary))
                        or binary in GUIDE_TESTS)
        self.assertEqual(built, wanted)
        self.assertLess(len(built), 20, "the lane builds a handful of binaries, not the suite")

    def test_the_doc_lane_is_bounded_and_has_its_tools(self):
        self.assertIn("    needs: changes\n", self.docs)
        self.assertRegex(self.docs, r"(?m)^    timeout-minutes: [1-9][0-9]*$")
        steps = re.findall(r"(?m)^      - name: (.+)$", self.docs)
        self.assertLess(steps.index("Install cargo-nextest"), steps.index("Test the release and docs contracts"))
        # cli_md_common_flow skips its Ada pipeline without GNAT.
        self.assertLess(steps.index("Install GNAT for the Ada common-flow contract"),
                        steps.index("Test the release and docs contracts"))
        self.assertIn("sudo apt-get install -y --no-install-recommends gnat gprbuild", self.docs)
        self.assertIn("toolchain: 1.99.0", self.docs)


class DocReadingTestCoverageTests(unittest.TestCase):
    """The doc-contracts lane runs every test that reads a documentation page."""

    @classmethod
    def setUpClass(cls):
        cls.tests = doc_reading_tests()
        cls.command = nextest_command(job("doc-contracts"))

    def test_the_scan_finds_the_documentation_contract_tests(self):
        found = set(self.tests)
        for test in [
            bhf_test("auto_exit_codes_docs", "the_exit_tables_match_the_cli"),
            bhf_test("cli_md_common_flow", "the_common_flow_runs_as_written"),
            bhf_test("collector_help", "fuzz_help_collector_text"),
            bhf_test("fuzz_grammar_help", "fuzz_help_describes_grammar_generation_plus_tree_mutation"),
            bhf_test("custom_harness_flow", "linux::the_guides_do_not_repeat_retired_claims"),
            bhf_test("release_bundle_manifest", "packaging_script_stages_every_mandatory_root_file"),
            lib_test("bhf", "auto::config::tests::the_docs_list_every_config_key"),
            lib_test("bhf", "auto::config::tests::the_docs_list_only_config_keys_that_exist"),
            lib_test("bhf", "auto::discovery::tests::auto_md_lists_every_default_skip"),
            lib_test("bhf", "auto::attempt::stamp_tests::"
                            "vulnerability_coverage_names_the_lanes_with_and_without_sink_oracles"),
            lib_test("bhf-daemon", "mcp_docs_tests::the_daemon_docs_list_the_tools_tools_list_advertises"),
            lib_test("lang_profile", "tests::the_readme_names_the_report_only_dialects"),
        ]:
            with self.subTest(test=test):
                self.assertIn(test, found)
        # A test that writes a fixture README.md or reads a report named
        # INDEX.md reads no documentation page.
        self.assertFalse([test for test in self.tests if test.binary in ("auto_static_scan", "results_e2e")])

    def test_the_doc_lane_runs_every_test_that_reads_a_documentation_page(self):
        missing = [test for test in self.tests if not lane_runs(self.command, test)]
        self.assertFalse(missing, "the doc-contracts lane does not build or select these tests:\n" + "\n".join(
            f"  {test.package} {test.kind} {test.binary}: {test.name}" for test in missing))

    def test_the_tests_that_read_a_page_through_library_code_run_for_a_change_to_that_page(self):
        lanes = {"doc-contracts": job("doc-contracts"), "build-test": job("build-test")}
        for package, name, source, page, library in INDIRECT_DOC_READERS:
            test = lib_test(package, name)
            with self.subTest(test=name, page=page):
                self.assertTrue((ROOT / page).is_file(), page)
                self.assertIn(f'"{page}"', (ROOT / library).read_text())
                self.assertIn(f"fn {name.rsplit('::', 1)[1]}()", (ROOT / source).read_text())
                self.assertTrue(lane_runs(self.command, test), "the doc-contracts lane does not run it")
                heavy = classify(page)
                [lane] = [text for text in lanes.values() if selected(text, heavy)]
                self.assertTrue(lane_runs(nextest_command(lane), test), (heavy, page))

    def test_the_doc_lane_runs_the_help_contracts(self):
        for binary in HELP_CONTRACT_BINARIES:
            with self.subTest(binary=binary):
                self.assertTrue((TESTS / f"{binary}.rs").is_file())
                self.assertTrue(lane_runs(self.command, bhf_test(binary)))
        config = (ROOT / "crates/cli/src/auto/config.rs").read_text()
        for name in HELP_CONTRACT_LIB_TESTS:
            with self.subTest(test=name):
                self.assertIn(f"fn {name.rsplit('::', 1)[1]}()", config)
                self.assertTrue(lane_runs(self.command, lib_test("bhf", name)))


class DocReadingScanTests(unittest.TestCase):
    """The scanner on small sources."""

    def scan(self, source: str) -> list[str]:
        return [test.name for test in scan_rust_tests(source, "bhf", "test", "widget", [])]

    def test_a_test_reading_a_page_through_a_helper_is_found(self):
        source = textwrap.dedent('''
            fn doc(name: &str) -> String {
                let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/site").join(name);
                std::fs::read_to_string(path).unwrap()
            }
            fn page() -> String { doc("cli.md") }
            #[test]
            fn the_guide_names_the_flag() { assert!(page().contains("--flag")); }
            #[test]
            fn parse_record_reads_no_page() { assert_eq!(parse_record(b"x"), 1); }
            ''')
        self.assertEqual(self.scan(source), ["the_guide_names_the_flag"])

    def test_a_fixture_readme_or_a_report_page_is_not_a_documentation_page(self):
        source = textwrap.dedent('''
            #[test]
            fn writes_a_fixture_readme() {
                let root = TestDir::new("widget");
                fs::write(root.join("README.md"), "no").unwrap();
            }
            #[test]
            fn reads_the_report_index() {
                let results = repo_root().join("target/widget/results");
                assert!(results.join("INDEX.md").is_file());
            }
            #[test]
            fn reads_the_readme() {
                let readme = fs::read_to_string(repo_root().join("README.md")).unwrap();
                assert!(readme.contains("bhf"));
            }
            ''')
        self.assertEqual(self.scan(source), ["reads_the_readme"])

    def test_braces_in_literals_and_array_types_do_not_end_a_function(self):
        source = textwrap.dedent('''
            fn copy_at(s: &str) -> [u8; 4] { let open = '{'; let close = "}"; let _ = (open, close); [0; 4] }
            mod linux {
                const GUIDE: &str = include_str!("../../../docs/site/sanitizers.md");
                #[test]
                #[ignore = "slow"]
                fn the_guide_lists_widget() { assert!(super::GUIDE.contains("Widget")); }
            }
            #[test]
            fn copy_at_copies() { assert_eq!(copy_at("x"), [0; 4]); }
            ''')
        self.assertEqual(self.scan(source), ["linux::the_guide_lists_widget"])


class FilterSelectsTests(unittest.TestCase):
    def test_negation_conjunction_and_matchers(self):
        expression = ("not (package(bhf) & kind(test)) | binary(/^m19_/) | "
                      "(binary(=custom_harness_flow) & test(/::guide$/)) | (kind(lib) & test(=a::b))")
        self.assertTrue(filter_selects(expression, lib_test("bhf", "x::y")))
        self.assertTrue(filter_selects(expression, RustTest("corpus", "test", "corpus_io", "x")))
        self.assertFalse(filter_selects(expression, bhf_test("auto_c_common_cli", "x")))
        self.assertTrue(filter_selects(expression, bhf_test("m19_docs_site")))
        self.assertTrue(filter_selects(expression, bhf_test("custom_harness_flow", "linux::guide")))
        self.assertFalse(filter_selects(expression, bhf_test("custom_harness_flow", "linux::guide_x")))
        self.assertFalse(filter_selects("kind(lib) & test(=a::b)", lib_test("bhf", "a::bc")))
        self.assertTrue(filter_selects("kind(lib) & test(=a::b)", lib_test("bhf-daemon", "a::b")))

    def test_a_filter_outside_the_subset_is_refused(self):
        with self.assertRaises(AssertionError):
            filter_selects("all() | binary(/^m/)", bhf_test("m19_docs_site"))

    def test_the_lane_must_build_the_binary(self):
        command = "cargo nextest run --locked -p bhf --lib --test 'm19_*' -E 'binary(/^m/) | kind(lib)'"
        self.assertTrue(lane_runs(command, bhf_test("m19_docs_site")))
        self.assertFalse(lane_runs(command, bhf_test("m8_access_param")))
        self.assertFalse(lane_runs(command, lib_test("bhf-daemon", "tests::x")))
        self.assertTrue(lane_runs(command, lib_test("bhf", "tests::x")))


if __name__ == "__main__":
    unittest.main()
