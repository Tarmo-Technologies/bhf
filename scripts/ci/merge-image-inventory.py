#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reconcile filesystem inventory with compiler evidence from that same image."""
import argparse
import hashlib
import json
import pathlib
import re


def reconcile(filesystem, rust, receipt, inspect, binaries):
    labels = inspect[0]["Config"]["Labels"]
    for key, label, pattern in (
        ("source_commit", "org.opencontainers.image.revision", r"[a-f0-9]{40}"),
        ("source_archive_sha256", "io.tarmo.bhf.source-archive-sha256", r"[a-f0-9]{64}"),
        ("version", "org.opencontainers.image.version", r"\d+\.\d+\.\d+(?:[-+][\w.-]+)?"),
    ):
        value = receipt.get(key, "")
        if not re.fullmatch(pattern, value) or labels.get(label) != value:
            raise ValueError(f"invalid or inconsistent {key}")
    if receipt.get("features") != "default-no-llm" or receipt.get("target") != "x86_64-unknown-linux-gnu":
        raise ValueError("unexpected production features/platform")
    expected_paths = {"/usr/local/bin/bhf", "/usr/local/bin/bhf-daemon",
                      "/usr/local/lib/bhf/libbhf_runtrace_shim.so", "/usr/local/lib/bhf/libbhf_cc_intercept.so"}
    if {b["path"] for b in receipt["binaries"]} != expected_paths:
        raise ValueError("missing or unexpected production binary")
    for binary in receipt["binaries"]:
        digest = hashlib.sha256((binaries / pathlib.Path(binary["path"]).name).read_bytes()).hexdigest()
        if digest != binary["sha256"]:
            raise ValueError(f'binary hash mismatch: {binary["path"]}')
    rust_components = rust.get("components", [])
    names = {c["name"] for c in rust_components}
    if not {"bhf", "bhf-daemon", "bhf_runtrace_shim", "bhf_cc_intercept"} <= names or "llm_harness_gen" in names:
        raise ValueError("incomplete or LLM-enabled Cargo inventory")
    properties = {p["name"]: p["value"] for p in rust["metadata"]["properties"]}
    if properties.get("bhf:source-commit") != receipt["source_commit"] or properties.get("bhf:source-archive-sha256") != receipt["source_archive_sha256"]:
        raise ValueError("Cargo inventory source identity mismatch")
    refs = {c["bom-ref"] for c in filesystem.get("components", [])}
    for c in rust_components:
        if c["bom-ref"] in refs:
            raise ValueError("conflicting SBOM component identity")
        refs.add(c["bom-ref"])
    filesystem.setdefault("components", []).extend(rust_components)
    filesystem.setdefault("dependencies", []).extend(rust["dependencies"])
    root = filesystem["metadata"]["component"]
    root["version"] = receipt["version"]
    root.setdefault("properties", []).extend([
        {"name": "bhf:image-config-digest", "value": inspect[0]["Id"]},
        {"name": "bhf:source-commit", "value": receipt["source_commit"]},
        {"name": "bhf:source-archive-sha256", "value": receipt["source_archive_sha256"]},
        {"name": "bhf:features", "value": receipt["features"]},
    ])
    runtime_roots = [c["bom-ref"] for c in rust_components if c["name"] in receipt["packages"]]
    dependency = next((d for d in filesystem["dependencies"] if d["ref"] == root["bom-ref"]), None)
    if dependency is None:
        dependency = {"ref": root["bom-ref"], "dependsOn": []}
        filesystem["dependencies"].append(dependency)
    dependency["dependsOn"] = sorted(set(dependency["dependsOn"] + runtime_roots))
    return filesystem


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=pathlib.Path)
    parser.add_argument("binaries", type=pathlib.Path)
    args = parser.parse_args()
    def read(name):
        return json.loads((args.evidence / name).read_text())
    result = reconcile(read("filesystem.cyclonedx.json"), read("rust.cyclonedx.json"),
                       read("build-receipt.json"), read("image-inspect.json"), args.binaries)
    (args.evidence / "image.cyclonedx.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
