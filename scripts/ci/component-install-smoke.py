#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise real cargo-dist installers against local release artifacts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def archive_binary_digest(archive, binary):
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as bundle:
            matches = [x for x in bundle.infolist() if Path(x.filename).name == binary]
            if len(matches) != 1 or matches[0].is_dir():
                raise ValueError(f"expected exactly one {binary} in {archive.name}")
            with bundle.open(matches[0]) as stream:
                return hashlib.file_digest(stream, "sha256").hexdigest()
    with tarfile.open(archive) as bundle:
        matches = [x for x in bundle.getmembers() if Path(x.name).name == binary]
        if len(matches) != 1 or not matches[0].isfile():
            raise ValueError(f"expected exactly one {binary} in {archive.name}")
        with bundle.extractfile(matches[0]) as stream:
            return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    artifacts = args.artifacts.resolve()
    windows = os.name == "nt"
    marker = "bhf-installer.ps1" if windows else "bhf-installer.sh"
    if not (artifacts / marker).is_file():
        matches = list(artifacts.rglob(marker))
        if len(matches) != 1:
            raise ValueError("expected one generated CLI installer in artifact directory")
        artifacts = matches[0].parent
    args.evidence.mkdir(parents=True, exist_ok=True)
    receipt = args.evidence / "component-install.json"
    # A retry must not leave a stale success receipt if installation fails.
    result = {"decision": "INCOMPLETE", "source_commit": subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
        "platform": platform.platform(), "attempts": []}
    receipt.write_text(json.dumps(result, indent=2) + "\n")
    version = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    target = "x86_64-pc-windows-msvc" if windows else "x86_64-unknown-linux-gnu"
    components = [("bhf", "bhf.exe" if windows else "bhf"),
                  ("bhf-daemon", "bhf-daemon.exe" if windows else "bhf-daemon")]
    if not windows:
        components += [("bhf_runtrace_shim", "libbhf_runtrace_shim.so"),
                       ("bhf_cc_intercept", "libbhf_cc_intercept.so")]
    shells = ["powershell", "pwsh"] if windows else ["sh"]
    for shell in shells:
        if not shutil.which(shell):
            raise ValueError(f"required installer shell is unavailable: {shell}")
        with tempfile.TemporaryDirectory(prefix="bhf-component-install-") as temporary:
            prefix = Path(temporary) / "installed binaries"
            env = os.environ.copy()
            for key in list(env):
                # Python can inherit PowerShell 7 module paths and pass them to
                # Windows PowerShell 5.1, whose modules cannot load that version.
                if (windows and key.upper() in {"PSMODULEPATH", "WINPSMODULEPATH"}) or (
                        key.upper().endswith("_PROXY")) or key.startswith("INSTALLER_") or (
                        key.startswith("BHF_") and any(x in key for x in (
                            "DOWNLOAD", "INSTALL", "NO_MODIFY", "GITHUB_TOKEN"))):
                    env.pop(key)
            env["XDG_CONFIG_HOME"] = str(Path(temporary) / "receipts")
            installed = []
            for app, binary in components:
                variable = app.upper().replace("-", "_")
                env[f"{variable}_DOWNLOAD_URL"] = artifacts.as_uri()
                env[f"{variable}_UNMANAGED_INSTALL"] = str(prefix)
                env[f"{variable}_NO_MODIFY_PATH"] = "1"
                installer = artifacts / f"{app}-installer.{'ps1' if windows else 'sh'}"
                archive = artifacts / f"{app}-{target}.{'zip' if windows else 'tar.xz'}"
                # Verify the actual archive against cargo-dist's sidecar first.
                expected = Path(str(archive) + ".sha256").read_text().split()[0]
                archive_hash = digest(archive)
                if archive_hash != expected:
                    raise ValueError(f"archive checksum mismatch: {archive.name}")
                command = ([shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
                            "Bypass", "-File", str(installer)] if windows else
                           [shell, str(installer)])
                subprocess.run(command, env=env, check=True, timeout=180)
                installed_path = prefix / binary
                expected_binary = archive_binary_digest(archive, binary)
                if digest(installed_path) != expected_binary:
                    raise ValueError(f"installed binary differs from archive: {binary}")
                installed.append({"component": app, "archive_sha256": archive_hash,
                                  "installer_sha256": digest(installer),
                                  "installed_sha256": expected_binary})
            for binary in ("bhf", "bhf-daemon"):
                exe = prefix / (binary + ".exe" if windows else binary)
                output = subprocess.check_output([str(exe), "--version"], text=True, timeout=30)
                if f"commit: {result['source_commit']}" not in output.splitlines():
                    raise ValueError(f"installed {binary} source identity disagrees")
                if binary == "bhf" and output.splitlines()[0] != f"bhf v{version}":
                    raise ValueError("installed CLI version disagrees with release version")
            if not windows:
                for _, binary in components:
                    output = subprocess.check_output(["ldd", str(prefix / binary)], text=True)
                    if "not found" in output:
                        raise ValueError(f"installed binary has missing libraries: {binary}")
            result["attempts"].append({"shell": shell, "components": installed,
                                       "decision": "PASS"})
            receipt.write_text(json.dumps(result, indent=2) + "\n")
    result["decision"] = "PASS_COMPONENT_INSTALL"
    receipt.write_text(json.dumps(result, indent=2) + "\n")
    print(f"{result['decision']}: {len(components)} components, {len(shells)} installer shells")


if __name__ == "__main__":
    main()
