# SPDX-License-Identifier: Apache-2.0
import copy
import hashlib
import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RUST = load("rust-image-inventory")
MERGE = load("merge-image-inventory")


class InventoryTests(unittest.TestCase):
    def test_tree_preserves_edges_across_deduplicated_roots(self):
        packages = [{"id": n, "name": n, "version": "1.0.0"} for n in ("a", "b", "c")]
        selected, edges = RUST.parse_tree("0a v1.0.0|default\n1b v1.0.0|std\n2c v1.0.0|\n0b v1.0.0|std (*)", packages)
        self.assertEqual(edges, {"a": {"b"}, "b": {"c"}})
        self.assertEqual(selected["b"], {"std"})

    def test_ambiguous_package_identity_fails(self):
        p = {"id": "a", "name": "a", "version": "1.0.0"}
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            RUST.parse_tree("0a v1.0.0|", [p, p])

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.binaries = pathlib.Path(self.tmp.name)
        self.receipt = {"source_commit": "a" * 40, "source_archive_sha256": "b" * 64,
                        "version": "0.2.34", "target": "x86_64-unknown-linux-gnu",
                        "features": "default-no-llm", "packages": list(RUST.PACKAGES), "binaries": []}
        for name, path in RUST.ARTIFACTS.items():
            (self.binaries / name).write_bytes(name.encode())
            self.receipt["binaries"].append({"path": path, "sha256": hashlib.sha256(name.encode()).hexdigest()})
        self.inspect = [{"Id": "sha256:" + "c" * 64, "Config": {"Labels": {
            "org.opencontainers.image.version": "0.2.34", "org.opencontainers.image.revision": "a" * 40,
            "io.tarmo.bhf.source-archive-sha256": "b" * 64}}}]
        self.fs = {"metadata": {"component": {"bom-ref": "image"}}, "components": []}
        self.rust = {"metadata": {"properties": [
            {"name": "bhf:source-commit", "value": "a" * 40},
            {"name": "bhf:source-archive-sha256", "value": "b" * 64}]},
            "components": [{"name": p, "bom-ref": p} for p in RUST.PACKAGES], "dependencies": []}

    def merge(self):
        return MERGE.reconcile(copy.deepcopy(self.fs), self.rust, self.receipt, self.inspect, self.binaries)

    def test_matching_inventory_links_runtime_roots(self):
        result = self.merge()
        self.assertEqual(result["dependencies"][0]["dependsOn"], sorted(RUST.PACKAGES))

    def test_changed_binary_fails(self):
        (self.binaries / "bhf").write_bytes(b"different binary")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            self.merge()

    def test_unknown_revision_fails(self):
        self.receipt["source_commit"] = "unknown"
        with self.assertRaisesRegex(ValueError, "source_commit"):
            self.merge()

    def test_mismatched_label_fails(self):
        self.inspect[0]["Config"]["Labels"]["org.opencontainers.image.version"] = "0.2.32"
        with self.assertRaisesRegex(ValueError, "version"):
            self.merge()

    def test_llm_dependency_fails(self):
        self.rust["components"].append({"name": "llm_harness_gen", "bom-ref": "llm"})
        with self.assertRaisesRegex(ValueError, "LLM-enabled"):
            self.merge()

    def test_missing_binary_fails(self):
        self.receipt["binaries"].pop()
        with self.assertRaisesRegex(ValueError, "production binary"):
            self.merge()

    def test_inventory_from_other_revision_fails(self):
        self.rust["metadata"]["properties"][0]["value"] = "d" * 40
        with self.assertRaisesRegex(ValueError, "source identity"):
            self.merge()
