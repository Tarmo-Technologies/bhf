#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Seal successful acceptance evidence; verify it again before packaging."""
import argparse
import hashlib
import json
import pathlib

COMMON = {"build.log", "identity.txt", "image-inspect.json", "build-receipt.json",
          "image.cyclonedx.json", "grype.json", "inventory-summary.json", "toolchains.json",
          "os-package-count.txt", "native-fuzz-replay.log", "no-llm-environment.log", "daemon-invalid.log", "termination.log"}
FLAVOR_LOGS = {
    "core": {"auto.log", "nonroot.log", "result.log", "version.log", "daemon-help.log", "daemon-version.log"},
    "ada": {"compiler-smoke.log"},
    "runtime": {"java-auto.log", "nonroot-java-agent.log", "result.log", "version.log",
                "java-dependency-staging.log", "java-offline-build.log", "java-missing-cache.log", "language-smoke.log",
                "java-auto-no-consent.log", "java-auto-offline.log", "java-auto-missing-cache.log", "java-auto-results.json"},
}


def receipt(root):
    image = json.loads((root / "image-inspect.json").read_text())[0]
    build = json.loads((root / "build-receipt.json").read_text())
    labels = image["Config"]["Labels"]
    flavor = labels["io.tarmo.bhf.flavor"]
    if labels["org.opencontainers.image.revision"] != build["source_commit"]:
        raise ValueError("image and compiler source disagree")
    platform = f'{image["Os"]}/{image["Architecture"]}'
    if platform not in ("linux/amd64", "linux/arm64"):
        raise ValueError("unsupported container platform")
    files = {}
    for name in sorted(COMMON | FLAVOR_LOGS[flavor]):
        path = root / name
        if path.is_symlink():
            raise ValueError("acceptance evidence cannot be a symlink")
        files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {"schema_version": 1, "result": "PASS", "flavor": flavor,
            "image_config_digest": image["Id"], "platform": platform, "source_commit": build["source_commit"], "files": files}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("record", "verify"))
    parser.add_argument("evidence", type=pathlib.Path)
    args = parser.parse_args()
    expected = receipt(args.evidence)
    path = args.evidence / "acceptance.json"
    if args.mode == "record":
        with path.open("x") as output:
            json.dump(expected, output, indent=2)
            output.write("\n")
    elif json.loads(path.read_text()) != expected:
        raise ValueError("acceptance receipt is missing, stale, or modified")


if __name__ == "__main__":
    main()
