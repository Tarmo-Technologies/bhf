#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Inventory standalone tools that filesystem catalogers cannot always identify.

Runs in the tested image, without network or writable root. Installed Rust
component manifests provide versions and file hashes for its prebuilt toolchain.
The parent binds this output to the immutable image digest.
"""
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tomllib
from urllib.parse import quote


def output(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL, timeout=30).strip()


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def component(name, version, purl, files, **details):
    return {"type": "application", "name": name, "version": version,
            "bom-ref": "bhf:installed-tool:" + name, "purl": purl,
            "properties": [{"name": "bhf:installed-files-sha256", "value": json.dumps(files, sort_keys=True)},
                           *[{"name": "bhf:" + k, "value": str(v)} for k, v in details.items()]]}


def rust_component_name(installed_name, rustc_details):
    host = next(line.removeprefix("host: ") for line in rustc_details.splitlines()
                if line.startswith("host: "))
    return installed_name.removesuffix("-" + host)


def inventory(flavor):
    if flavor not in ("core", "ada", "runtime"):
        raise ValueError("unknown flavor")
    result = {"schema_version": 1, "flavor": flavor, "components": []}
    if flavor != "runtime":
        return result
    selection_path = pathlib.Path("/usr/local/share/bhf/selected-languages.txt")
    languages = selection_path.read_text().strip().split(",") if selection_path.exists() else None
    if languages is not None:
        result["languages"] = languages
    commands = []
    if languages is None or {"javascript", "typescript"} & set(languages):
        commands.append(("node", "node", output("node", "--version").removeprefix("v")))
    if languages is None or "typescript" in languages:
        commands.append(("esbuild", "esbuild", output("esbuild", "--version")))
    if languages is None or "go" in languages:
        commands.append(("go", "go", output("go", "version").split()[2].removeprefix("go")))
    if languages is None or "rust" in languages:
        commands.append(("rustup", "rustup", output("rustup", "--version").split()[1]))
    for name, command, version in commands:
        path = pathlib.Path(shutil.which(command)).resolve(strict=True)
        ecosystem = "npm" if name == "esbuild" else "generic"
        result["components"].append(component(name, version, f"pkg:{ecosystem}/{name}@{quote(version, safe='')}",
                                              {str(path): digest(path)}))
    if languages is not None and "rust" not in languages:
        return result
    rustc = pathlib.Path(output("rustup", "which", "rustc"))
    root = rustc.parent.parent.resolve()
    manifest_path = root / "lib/rustlib/multirust-channel-manifest.toml"
    manifest = tomllib.loads(manifest_path.read_text())
    installed = (root / "lib/rustlib/components").read_text().splitlines()
    channel = os.environ["BHF_RUST_NIGHTLY"]
    result["observed_rustc"] = output(str(rustc), "-Vv")
    result["observed_cargo"] = output("cargo", "--version")
    for installed_name in installed:
        name = rust_component_name(installed_name, result["observed_rustc"])
        version_text = manifest["pkg"][name]["version"]
        version = version_text.split()[0]
        files = {}
        for entry in (root / "lib/rustlib" / ("manifest-" + installed_name)).read_text().splitlines():
            if entry.startswith("file:"):
                path = (root / entry[5:]).resolve(strict=True)
                if not path.is_relative_to(root):
                    raise ValueError("Rust manifest path leaves toolchain")
                files[str(path)] = digest(path)
        if not files:
            raise ValueError("installed Rust component has no files")
        result["components"].append(component(name, version, f"pkg:generic/{name}@{quote(version, safe='')}", files,
            channel=channel, upstream_version=version_text, channel_manifest_sha256=digest(manifest_path)))
    return result


if __name__ == "__main__":
    print(json.dumps(inventory(sys.argv[1]), indent=2))
