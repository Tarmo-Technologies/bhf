#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Package a tested image, matching source archives, and review evidence.

Produces an unsigned candidate. Publication/signing belongs to the protected
release workflow after exact-revision CI and review. It never runs the image.
"""
import argparse
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import tarfile
import tempfile


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--evidence", required=True, type=pathlib.Path)
    parser.add_argument("--sources", required=True, type=pathlib.Path)
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args()
    subprocess.run(["python3", "scripts/ci/container-evidence.py", "verify", str(args.evidence)], check=True)
    image = json.loads(subprocess.check_output(["docker", "image", "inspect", args.image], text=True))[0]
    evidence_image = json.loads((args.evidence / "image-inspect.json").read_text())[0]
    if image["Id"] != evidence_image["Id"]:
        raise ValueError("evidence belongs to another image")
    receipt = json.loads((args.evidence / "build-receipt.json").read_text())
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if receipt["source_commit"] != commit or not re.fullmatch("[0-9a-f]{40}", commit):
        raise ValueError("image is not the current exact source revision")
    labels = image["Config"]["Labels"]
    if labels["org.opencontainers.image.revision"] != commit:
        raise ValueError("image and compiler source identities disagree")
    flavor = labels["io.tarmo.bhf.flavor"]
    if flavor not in ("core", "ada", "runtime"):
        raise ValueError("unsupported image flavor")
    # Source retrieval must be complete, with checksums for the actual downloads.
    subprocess.run(["sha256sum", "--check", "--strict", "SHA256SUMS"], cwd=args.sources, check=True,
                   stdout=subprocess.DEVNULL)
    if not list(args.sources.glob("*.dsc")):
        raise ValueError("missing corresponding source archives")
    subprocess.run(["python3", "scripts/ci/review-image-scan.py", str(args.evidence)], check=True)
    platform = f'{image["Os"]}/{image["Architecture"]}'
    if platform not in ("linux/amd64", "linux/arm64"):
        raise ValueError("unsupported container platform")
    name = f'bhf-container-{receipt["version"]}-{flavor}-{image["Architecture"]}-{commit[:12]}'
    args.out.mkdir(parents=True, exist_ok=True)
    archive = args.out / f"{name}.tar.gz"
    if archive.exists():
        raise ValueError("candidate archive already exists")
    with tempfile.TemporaryDirectory(prefix="bhf-container-package-") as temporary:
        root = pathlib.Path(temporary) / name
        root.mkdir()
        container = subprocess.check_output(["docker", "create", image["Id"]], text=True).strip()
        try:
            subprocess.run(["docker", "cp", f"{container}:/usr/share/bhf/licenses/COPYLEFT-SOURCES.txt", str(root / "required-sources.txt")], check=True)
            subprocess.run(["docker", "cp", f"{container}:/usr/share/bhf/sbom/rust-notices.json", str(root / "rust-notices.json")], check=True)
        finally:
            subprocess.run(["docker", "rm", container], check=True, stdout=subprocess.DEVNULL)
        def specs(path):
            return {line.strip() for line in path.read_text().splitlines() if line.strip() and not line.startswith("#")}
        if specs(root / "required-sources.txt") != specs(args.sources / "REQUESTED-SOURCES.txt"):
            raise ValueError("source archive does not match the installed OS packages")
        shutil.copytree(args.evidence, root / "evidence", ignore=shutil.ignore_patterns("candidate.json"))
        shutil.copytree(args.sources, root / "corresponding-source")
        with (root / "bhf-source.tar").open("wb") as stream:
            subprocess.run(["git", "archive", "--format=tar", commit], stdout=stream, check=True)
        if sha256(root / "bhf-source.tar") != receipt["source_archive_sha256"]:
            raise ValueError("source archive digest mismatch")
        # docker save emits the tested local config and its immutable layers.
        with (root / "image.docker.tar").open("wb") as stream:
            subprocess.run(["docker", "save", image["Id"]], stdout=stream, check=True)
        manifest = {"schema_version": 1, "state": "requires_detached_signature",
                    "source_commit": commit, "source_archive_sha256": receipt["source_archive_sha256"],
                    "version": receipt["version"], "flavor": flavor, "platform": platform,
                    "image_config_digest": image["Id"], "registry_manifest_digest": None,
                    "features": "default-no-llm", "files": {}}
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                raise ValueError(f"unexpected symlink in candidate material: {path}")
            if path.is_file():
                manifest["files"][str(path.relative_to(root))] = sha256(path)
        (root / "release-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        with archive.open("xb") as output, tarfile.open(fileobj=output, mode="w:gz") as tar:
            tar.add(root, arcname=name)
    digest = sha256(archive)
    (args.out / f"{name}.tar.gz.sha256").write_text(f"{digest}  {archive.name}\n")
    print(json.dumps({"archive": str(archive), "sha256": digest, "source_commit": commit,
                      "archive_bytes": archive.stat().st_size, "platform": platform,
                      "image_config_digest": image["Id"], "state": "unsigned_candidate"}))


if __name__ == "__main__":
    main()
