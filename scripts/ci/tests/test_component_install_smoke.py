# SPDX-License-Identifier: Apache-2.0
"""Check artifact identity against cargo-dist's archive layout."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "component_install", Path(__file__).resolve().parents[1] / "component-install-smoke.py")
INSTALL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALL)


class ArchiveIdentityTests(unittest.TestCase):
    def archive(self, directory, members):
        path = Path(directory) / "bhf.tar.xz"
        with tarfile.open(path, "w:xz") as bundle:
            for name, kind, content in members:
                entry = tarfile.TarInfo(name)
                entry.type = kind
                if kind == tarfile.REGTYPE:
                    entry.size = len(content)
                    bundle.addfile(entry, io.BytesIO(content))
                else:
                    bundle.addfile(entry)
        return path

    def test_license_directory_with_binary_name_is_not_an_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.archive(directory, [
                ("bhf-x86_64/bhf", tarfile.REGTYPE, b"executable"),
                ("bhf-x86_64/licenses/bhf", tarfile.DIRTYPE, b""),
            ])
            self.assertEqual(INSTALL.archive_binary_digest(path, "bhf"),
                             hashlib.sha256(b"executable").hexdigest())

    def test_multiple_executable_files_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.archive(directory, [
                ("one/bhf", tarfile.REGTYPE, b"one"),
                ("two/bhf", tarfile.REGTYPE, b"two"),
            ])
            with self.assertRaises(ValueError):
                INSTALL.archive_binary_digest(path, "bhf")

    def test_directory_cannot_substitute_for_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.archive(directory, [("bhf", tarfile.DIRTYPE, b"")])
            with self.assertRaises(ValueError):
                INSTALL.archive_binary_digest(path, "bhf")


if __name__ == "__main__":
    unittest.main()
