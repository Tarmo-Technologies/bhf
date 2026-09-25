<!-- SPDX-License-Identifier: Apache-2.0 -->

# Installing a BHF Release

Linux releases provide two complete installation choices. Use the all-in-one
bundle when you want `install.sh` to install the CLI, daemon, both Linux shims,
harness runtimes, and the checksum-verified content pack together. The pack's
SHA-256 digests detect accidental changes but do not authenticate its publisher.
Use the component
archives when you want to choose and place the files yourself.

Every all-in-one bundle also carries `INSTALL.md`, `LICENSE`, `README.md`, and
`RELEASE_NOTES.md` at its root. These are required release payloads, not optional
source-tree documentation.

Do not mix versions or target triples. The commands below use the published
64-bit GNU/Linux artifacts.

## Choice 1: all-in-one `install.sh` bundle

Download `bhf-dist-<version>-x86_64-unknown-linux-gnu.tar.gz` and its
`.sha256` sidecar from the same release, then:

```sh
sha256sum -c bhf-dist-*.tar.gz.sha256
# Authenticate the whole archive with a separately trusted verifier and
# publisher public key before extracting or executing bundle code.
tar xzf bhf-dist-*.tar.gz
cd bhf-dist-*-x86_64-unknown-linux-gnu
./install.sh --trust-policy /trusted/operator-policy.json
```

The interactive installer selects language toolchains, targets, fuzzers, and
optional extras. Its default install prefix is `/opt/bhf`, with `bhf`
and `bhf-daemon` plus the `bhf-bug-report` scrubbed diagnostic collector
symlinked in `/usr/local/bin`.

For automation or an offline host whose system dependencies were staged
separately:

```sh
./install.sh --non-interactive --trust-policy /trusted/operator-policy.json \
  --languages c,cpp,rust \
  --targets native \
  --fuzzers builtin \
  --extras build-recovery,archives

# Add these when the offline host must not contact package or Rust servers:
#   --no-system-packages --no-rustup
```

Run `./install.sh --help` for custom prefixes, dependency controls, seed
installation, smoke-test controls, and every available language profile.
The policy must independently pin a publisher public key under
`update_packs.trusted_public_keys` and set `require_signature: true`.
Checksum-only legacy content requires explicit `--allow-legacy-integrity-only`
instead; neither it nor a same-channel `.sha256` sidecar authenticates the
publisher or the unverified installer.

## Choice 2: manually co-locate component archives

Download the CLI plus the two Linux shims and their checksum sidecars:

```text
bhf-x86_64-unknown-linux-gnu.tar.xz
bhf_runtrace_shim-x86_64-unknown-linux-gnu.tar.xz
bhf_cc_intercept-x86_64-unknown-linux-gnu.tar.xz
```

The daemon archive is optional and is needed only for IDE, JSON-RPC, or MCP
use. Verify and extract the selected archives from their download directory:

```sh
sha256sum -c bhf-x86_64-unknown-linux-gnu.tar.xz.sha256
sha256sum -c bhf_runtrace_shim-x86_64-unknown-linux-gnu.tar.xz.sha256
sha256sum -c bhf_cc_intercept-x86_64-unknown-linux-gnu.tar.xz.sha256

tar xf bhf-x86_64-unknown-linux-gnu.tar.xz
tar xf bhf_runtrace_shim-x86_64-unknown-linux-gnu.tar.xz
tar xf bhf_cc_intercept-x86_64-unknown-linux-gnu.tar.xz
```

Copy the two libraries into the CLI directory. This gives both components one
reliable automatic-discovery layout:

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

You can run in place or copy the co-located directory to a permanent prefix:

```sh
PREFIX="${BHF_PREFIX:-$HOME/.local/share/bhf}"
BIN_DIR="${BHF_BIN_DIR:-$HOME/.local/bin}"

mkdir -p "$PREFIX" "$BIN_DIR"
cp -a "$CLI_DIR/." "$PREFIX/"
ln -sfn "$PREFIX/bhf" "$BIN_DIR/bhf"
install -m 0755 "$CLI_DIR/bhf-bug-report.sh" "$PREFIX/bhf-bug-report"
ln -sfn "$PREFIX/bhf-bug-report" "$BIN_DIR/bhf-bug-report"
```

The wrapper runs the CLI's built-in collector. Either form works:

```sh
bhf-bug-report /path/to/bhf_work
bhf bug-report /path/to/bhf_work --stdout

# Bundle the scrubbed diagnostics into an offline archive to share with a
# maintainer. `--preview` first shows exactly what would be included:
bhf bug-report /path/to/bhf_work --preview
bhf bug-report /path/to/bhf_work --bundle bhf-bug-report.tar.gz
```

The bundle works entirely offline. It carries only scrubbed, bounded
diagnostics — the compact support report, bhf's own internal-issue log if
any, and a manifest describing every field — and never source, corpus, findings
inputs, environment values, usernames, hostnames, or absolute paths. A built-in
self-test scans every field for the work-dir path, username, and hostname and
refuses to write an archive that leaks any.

To add the optional daemon, extract its archive, copy `bhf-daemon` into the
same prefix, and create a matching symlink:

```sh
tar xf bhf-daemon-x86_64-unknown-linux-gnu.tar.xz
install -m 0755 \
  bhf-daemon-x86_64-unknown-linux-gnu/bhf-daemon "$PREFIX/"
ln -sfn "$PREFIX/bhf-daemon" "$BIN_DIR/bhf-daemon"
```

If policy requires the libraries to remain elsewhere, set absolute paths
instead of copying them:

```sh
export BHF_RUNTRACE_SHIM=/absolute/path/libbhf_runtrace_shim.so
export BHF_CC_INTERCEPT=/absolute/path/libbhf_cc_intercept.so
```

The runtrace shim provides runtime auditing, behavioral/taint oracles, and fake
resources. The compiler-interception shim enables complex C/C++ build recovery
for compiler processes launched by absolute path or `posix_spawn`.

The runtrace shim can also be found in its sibling extracted archive directory.
The compiler-interception shim cannot: keep it directly beside `bhf` or set
`BHF_CC_INTERCEPT` to its absolute path.

See `README.md` in the same archive and the
[online installation guide](https://github.com/Tarmo-Technologies/bhf/blob/main/docs/site/install.md)
for supported operating systems and per-language toolchain prerequisites.
