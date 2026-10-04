#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Inventory the selected Cargo runtime graph and hash the stripped artifacts.

Run inside the builder after compilation. cargo tree uses the SAME package,
target and feature selection as cargo build. Compiler messages independently
confirm every runtime package was compiled; Cargo.lock alone is not evidence.
Build scripts/proc macros stay in the separate build-input receipt.
"""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import tomllib
from urllib.parse import quote

PACKAGES = ("bhf", "bhf-daemon", "bhf_runtrace_shim", "bhf_cc_intercept")
ARTIFACTS = {
    "bhf": "/usr/local/bin/bhf",
    "bhf-daemon": "/usr/local/bin/bhf-daemon",
    "libbhf_runtrace_shim.so": "/usr/local/lib/bhf/libbhf_runtrace_shim.so",
    "libbhf_cc_intercept.so": "/usr/local/lib/bhf/libbhf_cc_intercept.so",
}


def parse_tree(tree, packages):
    """Return Cargo package IDs/features and normal-dependency edges."""
    selected, edges, stack = {}, {}, []
    for line in tree.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"(\d+)(\S+) v([^\s|]+)(.*?)\|(.*?)(?: \(\*\))?", line)
        if not match:
            raise ValueError(f"unrecognized cargo tree line: {line!r}")
        depth, name, version, location, features = match.groups()
        candidates = [p for p in packages if p["name"] == name and p["version"] == version]
        # Ambiguity must fail rather than inventing an identity from a name.
        if len(candidates) != 1:
            raise ValueError(f"ambiguous package identity: {name} {version} {location}")
        package_id = candidates[0]["id"]
        selected.setdefault(package_id, set()).update(filter(None, features.split(",")))
        depth = int(depth)
        if depth > len(stack):
            raise ValueError("invalid dependency depth")
        stack = stack[:depth]
        if stack:
            edges.setdefault(stack[-1], set()).add(package_id)
        stack.append(package_id)
    if not selected:
        raise ValueError("empty runtime dependency graph")
    return selected, edges


def generate(metadata, tree, messages, lock, artifact_dir, commit, source_sha, target):
    by_id = {p["id"]: p for p in metadata["packages"]}
    selected, edges = parse_tree(tree, metadata["packages"])
    compiled = {}
    for message in messages:
        if message.get("reason") == "compiler-artifact":
            compiled.setdefault(message["package_id"], set()).update(message["features"])
    missing = selected.keys() - compiled.keys()
    if missing:
        raise ValueError(f"runtime packages absent from compiler receipt: {sorted(missing)}")
    names = {by_id[p]["name"] for p in selected}
    if not set(PACKAGES) <= names or "llm_harness_gen" in names:
        raise ValueError("incorrect production package selection or LLM dependency present")
    checksums = {(p["name"], p["version"], p.get("source")): p.get("checksum")
                 for p in lock["package"]}
    refs, components = {}, []
    for package_id in sorted(selected):
        p = by_id[package_id]
        purl = f'pkg:cargo/{quote(p["name"], safe="")}@{quote(p["version"], safe="")}'
        if p["source"] is None:
            purl += f"?vcs_url={quote('git+https://github.com/Tarmo-Technologies/bhf@' + commit, safe='')}"
        elif not p["source"].startswith("registry+https://github.com/rust-lang/crates.io-index"):
            raise ValueError(f"unhandled Cargo source: {p['source']}")
        refs[package_id] = purl
        c = {"type": "library", "bom-ref": purl, "name": p["name"],
             "version": p["version"], "purl": purl,
             "properties": [{"name": "bhf:cargo-features", "value": ",".join(sorted(selected[package_id]))}]}
        if p.get("license"):
            c["licenses"] = [{"expression": p["license"]}]
        checksum = checksums.get((p["name"], p["version"], p["source"]))
        if p["source"] and not checksum:
            raise ValueError(f"missing registry checksum: {package_id}")
        if checksum:
            c["hashes"] = [{"alg": "SHA-256", "content": checksum}]
        components.append(c)
    dependencies = [{"ref": refs[p], "dependsOn": sorted(refs[d] for d in edges.get(p, set()))}
                    for p in sorted(selected)]
    binaries = []
    for name, installed_path in ARTIFACTS.items():
        digest = hashlib.sha256((artifact_dir / name).read_bytes()).hexdigest()
        binaries.append({"path": installed_path, "sha256": digest})
    version = next(by_id[p]["version"] for p in selected if by_id[p]["name"] == "bhf")
    receipt = {"schema_version": 1, "version": version, "source_commit": commit, "source_archive_sha256": source_sha,
               "target": target, "features": "default-no-llm", "packages": list(PACKAGES),
               "binaries": binaries, "rustc": subprocess.check_output(["rustc", "-vV"], text=True).strip(),
               "compiled_packages": [{"id": p, "features": sorted(f), "runtime": p in selected}
                                     for p, f in sorted(compiled.items())]}
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"properties": [
                {"name": "bhf:source-commit", "value": commit},
                {"name": "bhf:source-archive-sha256", "value": source_sha},
                {"name": "bhf:target", "value": target},
                {"name": "bhf:scope", "value": "selected normal Cargo dependencies; build inputs in build-receipt.json"}]},
            "components": components, "dependencies": dependencies}
    return sbom, receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=pathlib.Path, required=True)
    parser.add_argument("--messages", type=pathlib.Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--target", default="x86_64-unknown-linux-gnu")
    args = parser.parse_args()
    selection = [v for p in PACKAGES for v in ("-p", p)]
    metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--offline", "--no-deps", "--format-version", "1"], text=True))
    tree = subprocess.check_output(["cargo", "tree", "--locked", "--offline", *selection,
                                   "--target", args.target, "--edges", "normal,no-proc-macro",
                                   "--prefix", "depth", "--format", "{p}|{f}"], text=True)
    messages = [json.loads(line) for line in args.messages.read_text().splitlines() if line.strip()]
    known = {p["id"] for p in metadata["packages"]}
    for message in messages:
        if message.get("reason") != "compiler-artifact" or message["package_id"] in known:
            continue
        package_id = message["package_id"]
        # Published crate manifests are normalized by Cargo. Read only the
        # manifests named by the compiler, avoiding a workspace-wide resolve
        # that would include disabled features and foreign platform packages.
        package = tomllib.loads(pathlib.Path(message["manifest_path"]).read_text())["package"]
        metadata["packages"].append({"id": package_id, "name": package["name"],
                                     "version": package["version"], "license": package.get("license"),
                                     "source": package_id.split("#", 1)[0]})
        known.add(package_id)
    sbom, receipt = generate(metadata, tree, messages, tomllib.loads(pathlib.Path("Cargo.lock").read_text()),
                             args.artifacts, args.commit, args.source_sha, args.target)
    out = args.artifacts / "inventory"
    out.mkdir(exist_ok=True)
    (out / "rust.cyclonedx.json").write_text(json.dumps(sbom, indent=2) + "\n")
    (out / "build-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
