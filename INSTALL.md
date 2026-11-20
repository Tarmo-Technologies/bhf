<!-- SPDX-License-Identifier: Apache-2.0 -->

# Installing a BHF Release

This guide installs the published release files: the full Linux bundle with
its `install.sh`, the Linux component archives, and the Windows CLI. To build
bhf from source, or for the toolchain each language needs, see
[Installing bhf](docs/site/install.md). For the Docker image, see
[Running bhf in Docker](docs/site/docker.md).

Use files of one version and one target triple together. The commands below
use the x86_64 GNU/Linux files. On 64-bit ARM Linux, use the component
archives with `aarch64-unknown-linux-gnu` in place of
`x86_64-unknown-linux-gnu`; the full bundle is built for x86_64 only.

## What each package contains

The full bundle, `bhf-dist-<version>-x86_64-unknown-linux-gnu.tar.gz`,
extracts to a directory of the same name:

| Path | Contents |
|---|---|
| `install.sh` | The installer |
| `tool/` | `bhf`, `bhf-daemon`, both Linux shims, `bhf-bug-report` and the harness runtimes |
| `content/packs/current/` | The signed content pack: the static-analysis rule catalog, an SBOM CVE database, a binary CVE database and a seed archive. The release workflow builds the bundle without CVE data or seeds, so those three are empty; [Offline deployment](docs/site/offline-deployment.md) shows how to add them |
| `README.md`, `RUN-BHF.md` | What bhf does, and how to run it after installing |
| `docs/` | The user documentation; start at `docs/site/index.md` |
| `examples/`, `schemas/` | Example projects, and the JSON schemas of bhf's output files |
| `INSTALL.md`, `README-DIST.md` | This guide, and a summary of the bundle and installer options |
| `RELEASE_NOTES.md`, `CHANGELOG.md` | The current release, and every change release by release |
| `LICENSE`, `NOTICE`, `THIRD_PARTY.md` | License and third-party notices |
| `benchmarks/` | The benchmark write-ups and their results |
| `smoke/c/` | The C fixture the installer's smoke test fuzzes |
| `VERSION` | Package name, version, target triple, build time and commit |

Each component archive (`bhf-*.tar.xz`, `bhf-daemon-*`, `bhf_runtrace_shim-*`,
`bhf_cc_intercept-*`, and the Windows `.zip` files) holds one component with
`README.md`, `INSTALL.md`, `LICENSE` and `CHANGELOG.md`. The `bhf` archive
also holds the harness runtimes and `bhf-bug-report.sh`.

## Choice 1: all-in-one `install.sh` bundle

### What you need before you start

The bundle is signed with the publisher's Ed25519 key. Before you run
anything from it, check the signature with a verifier and key that did not
come with the download. Get these three files through a separate trusted
channel, such as a contact at the publisher or your organization's software
administrator, and keep them outside the extracted bundle:

- **The verifier**:
  [`scripts/verify-offline-dist.py`](https://github.com/Tarmo-Technologies/bhf/blob/main/scripts/verify-offline-dist.py)
  from the bhf repository. It needs Python 3.8 or newer and OpenSSL with
  Ed25519 support. RHEL 7's OpenSSL lacks Ed25519, so verify on a newer host
  or with a newer OpenSSL there.
- **The publisher's public key**: 64 hexadecimal characters, and its key ID.
  Save the key as `publisher.pub`.
- **A trust policy**: `operator-policy.json`, naming that key. Replace both
  placeholders with the key ID and the public key:

```json
{
  "schema_version": "bhf.policy.v1",
  "policy_id": "local-install",
  "update_packs": {
    "require_signature": true,
    "trusted_public_keys": {
      "REPLACE_WITH_KEY_ID": "REPLACE_WITH_64_CHARACTER_PUBLIC_KEY"
    }
  }
}
```

The `.sha256` file published beside the archive detects a damaged download.
The signature, checked against a key you obtained separately, identifies the
publisher. `install.sh` checks the content pack's signature against the
policy before it changes anything on the host.

### Verify and install

Download the archive, its `.sha256` file and its `.sig` file from the same
release. Set `ARCHIVE` to the file name, with the version in place of
`<version>`, then run from the download directory:

```sh
ARCHIVE='bhf-dist-<version>-x86_64-unknown-linux-gnu.tar.gz'
sha256sum -c "$ARCHIVE.sha256"
python3 /trusted/verify-offline-dist.py \
  --archive "$ARCHIVE" --signature "$ARCHIVE.sig" \
  --trusted-public-key /trusted/publisher.pub \
  --verified-copy bhf-verified.tar.gz
tar xzf bhf-verified.tar.gz
cd "${ARCHIVE%.tar.gz}"
./install.sh --trust-policy /trusted/operator-policy.json
```

`--verified-copy` writes the exact bytes the verifier checked to a new
file, so you extract what was verified.

The interactive installer asks which language toolchains, targets, fuzzers
and extras to set up, installs the system packages they need, and runs the
bundled C smoke test before it activates the new install. By default it
installs to `/opt/bhf` and links `bhf`, `bhf-daemon` and `bhf-bug-report`
into `/usr/local/bin`.

For automation, or for an offline host whose system packages you staged
separately:

```sh
./install.sh --non-interactive --trust-policy /trusted/operator-policy.json \
  --languages c,cpp,rust \
  --targets native \
  --fuzzers builtin \
  --extras build-recovery,archives

# On a host that must not contact package or Rust servers, also pass:
#   --no-system-packages --no-rustup
```

`./install.sh --help` lists every option: the prefix, the symlink directory,
package-manager control, seed installation and the smoke test. A content
pack built in the older checksum-only format installs only with
`--allow-legacy-integrity-only` in place of `--trust-policy`; that format
carries no publisher signature.

### After installing

The install prefix (`/opt/bhf` by default) holds:

| Path | Contents |
|---|---|
| `bhf`, `bhf-daemon` | The CLI and the JSON-RPC/MCP daemon |
| `libbhf_runtrace.so`, `libbhf_runtrace_shim.so`, `libbhf_cc_intercept.so` | The runtime shim (under both names) and the compiler-interception shim |
| `bhf-bug-report` | The scrubbed support-report collector |
| `packs/` | Installed content packs |
| `README.md`, `RUN-BHF.md`, `docs/` | The documentation; start at `docs/site/index.md` |

Run `bhf --help`, then follow `RUN-BHF.md` in the bundle or
[First run](README.md#first-run) in the README.

To update, run `install.sh` from the newer bundle. It replaces the binaries,
runtimes and documentation, keeps `<prefix>/packs/` and `<prefix>/corpora/`,
and moves the previous install to `<prefix>.backup.<timestamp>`. Work
directories live outside the prefix and are left alone.

## Choice 2: manually co-locate component archives

Download the CLI and the two Linux shims with their `.sha256` files:

```text
bhf-x86_64-unknown-linux-gnu.tar.xz
bhf_runtrace_shim-x86_64-unknown-linux-gnu.tar.xz
bhf_cc_intercept-x86_64-unknown-linux-gnu.tar.xz
```

The daemon archive is needed only for an IDE, JSON-RPC or MCP. Verify and
extract the archives in their download directory:

```sh
sha256sum -c bhf-x86_64-unknown-linux-gnu.tar.xz.sha256
sha256sum -c bhf_runtrace_shim-x86_64-unknown-linux-gnu.tar.xz.sha256
sha256sum -c bhf_cc_intercept-x86_64-unknown-linux-gnu.tar.xz.sha256

tar xf bhf-x86_64-unknown-linux-gnu.tar.xz
tar xf bhf_runtrace_shim-x86_64-unknown-linux-gnu.tar.xz
tar xf bhf_cc_intercept-x86_64-unknown-linux-gnu.tar.xz
```

Copy both libraries into the CLI directory, where bhf finds them:

```sh
CLI_DIR=bhf-x86_64-unknown-linux-gnu

install -m 0755 \
  bhf_runtrace_shim-x86_64-unknown-linux-gnu/libbhf_runtrace_shim.so \
  "$CLI_DIR/"
install -m 0755 \
  bhf_cc_intercept-x86_64-unknown-linux-gnu/libbhf_cc_intercept.so \
  "$CLI_DIR/"

"./$CLI_DIR/bhf" --version
```

Run bhf from that directory, or copy the directory to a permanent prefix:

```sh
PREFIX="${BHF_PREFIX:-$HOME/.local/share/bhf}"
BIN_DIR="${BHF_BIN_DIR:-$HOME/.local/bin}"

mkdir -p "$PREFIX" "$BIN_DIR"
cp -a "$CLI_DIR/." "$PREFIX/"
ln -sfn "$PREFIX/bhf" "$BIN_DIR/bhf"
install -m 0755 "$CLI_DIR/bhf-bug-report.sh" "$PREFIX/bhf-bug-report"
ln -sfn "$PREFIX/bhf-bug-report" "$BIN_DIR/bhf-bug-report"
```

To add the daemon, extract its archive, copy `bhf-daemon` into the same
prefix, and link it:

```sh
tar xf bhf-daemon-x86_64-unknown-linux-gnu.tar.xz
install -m 0755 \
  bhf-daemon-x86_64-unknown-linux-gnu/bhf-daemon "$PREFIX/"
ln -sfn "$PREFIX/bhf-daemon" "$BIN_DIR/bhf-daemon"
```

If the libraries must stay somewhere else, set their absolute paths instead
of copying them:

```sh
export BHF_RUNTRACE_SHIM=/absolute/path/libbhf_runtrace_shim.so
export BHF_CC_INTERCEPT=/absolute/path/libbhf_cc_intercept.so
```

The runtrace shim provides the runtime audit, the sink and behavioural
oracles, and fake resources. The compiler-interception shim records the
compiler commands of a C/C++ build, including compilers started by absolute
path or through `posix_spawn`, for `--probe-build` and `--build-command`.
bhf also finds the runtrace shim in its extracted archive directory beside
the CLI directory. The compiler-interception shim must sit beside `bhf`, or
`BHF_CC_INTERCEPT` must name it.

The component archives carry `README.md` and this guide. The complete
documentation is in the full bundle's `docs/` directory and in the
[source repository](https://github.com/Tarmo-Technologies/bhf);
[Installing bhf](docs/site/install.md) lists the supported operating systems
and each language's prerequisites.

## Windows

`bhf-installer.ps1` and `bhf-daemon-installer.ps1` install the native x64 CLI
and daemon. For an offline host, verify `bhf-x86_64-pc-windows-msvc.zip`
against its `.sha256` file and extract it. The [Windows guide](docs/site/windows.md)
covers the Visual Studio Build Tools, LLVM and make that C and C++ fuzzing
needs, and how each language lane runs on Windows.

## Support reports

When bhf itself fails on a tree, `bhf-bug-report` collects a scrubbed support
report from the work directory. Both forms run the CLI's built-in
collector:

```sh
bhf-bug-report /path/to/bhf_work
bhf bug-report /path/to/bhf_work --stdout

# Bundle the scrubbed diagnostics into an archive to share with a
# maintainer. `--preview` first shows exactly what the archive would hold:
bhf bug-report /path/to/bhf_work --preview
bhf bug-report /path/to/bhf_work --bundle bhf-bug-report.tar.gz
```

The bundle is built offline. It holds the compact support report, bhf's own
internal-issue log when there is one, and a manifest describing every field.
Source, corpus, finding inputs, environment values, user names, host names
and absolute paths are left out, and a self-test scans the archive for the
work-directory path, user name and host name and refuses to write it if any
appears.

## Selected language installations

All sixteen languages are installed by default; LLM features are a separate
build option. Choosing languages at install time decides which toolchains
are installed, while `bhf auto --languages` limits one run. In a source
checkout, build a container image with only the Java and Python toolchains:

```sh
scripts/build-container-release.sh bhf:java-python --languages java,python
```

From the extracted full bundle:

```sh
./install.sh --non-interactive --no-content --languages java,python
```

[Installation selection versus run selection](docs/site/docker.md#installation-selection-versus-run-selection)
lists the aliases, conflicts, shared dependencies and engine opt-outs.
