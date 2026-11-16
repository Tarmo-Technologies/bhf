# SPDX-License-Identifier: Apache-2.0
"""scripts/ci/check-network-fetches.sh: a download a transient error fails
the build with, or whose bytes nothing checks, is refused; the tree passes."""
from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
LINT = ROOT / "scripts/ci/check-network-fetches.sh"


def lint(*files: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(LINT), *map(str, files)], capture_output=True, text=True, check=False
    )


class CheckNetworkFetchesTests(unittest.TestCase):
    def check(self, name: str, text: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / name
            path.write_text(text)
            return lint(path)

    def test_the_tree_passes(self) -> None:
        result = lint()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_curl_without_retry_fails(self) -> None:
        result = self.check(
            "Dockerfile",
            "RUN curl -fsSLo /tmp/x.tgz https://example.com/x.tgz \\\n"
            "    && echo \"abc  /tmp/x.tgz\" | sha256sum -c -\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("Dockerfile:1: curl without --retry", result.stdout)

    def test_a_curl_piped_into_a_shell_fails(self) -> None:
        result = self.check(
            "ci.yml",
            "      - run: curl --retry 5 -LsSf https://example.com/install.sh | sh\n",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("no sha256sum/sha512sum check", result.stdout)

    def test_a_wget_without_tries_fails(self) -> None:
        result = self.check("ci.yml", "        run: |\n          wget -O x https://example.com/x\n          sha256sum -c x.sha256\n")
        self.assertEqual(result.returncode, 1)
        self.assertIn("wget without --tries", result.stdout)

    def test_an_add_of_a_url_fails(self) -> None:
        result = self.check(
            "Dockerfile", "ADD --checksum=sha256:abc https://example.com/ca.deb /tmp/ca.deb\n"
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("ADD of a URL cannot retry", result.stdout)

    def test_a_retried_and_checked_fetch_passes(self) -> None:
        result = self.check(
            "Dockerfile",
            "RUN apt-get install -y curl xz-utils \\\n"
            "    && curl --retry 5 -fsSLo /tmp/x.tgz https://example.com/x.tgz \\\n"
            "    && echo \"abc  /tmp/x.tgz\" | sha256sum -c -\n"
            "# curl https://example.com is only a comment\n",
        )
        self.assertEqual(result.returncode, 0, result.stdout)


if __name__ == "__main__":
    unittest.main()
