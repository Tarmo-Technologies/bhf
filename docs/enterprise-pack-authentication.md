<!-- SPDX-License-Identifier: Apache-2.0 -->

# Authenticated offline update packs

An update pack is a manifest plus payload files (rules, seed corpora and other content) that you carry to an offline host and install with `bhf pack install`. This page describes how packs and the offline distribution archive are signed and verified. [Release packaging](release-packaging.md) and [INSTALL.md](../INSTALL.md) show where these steps fit in a release and an install.

## Pack signature format

A pack manifest carries one of two integrity schemes:

| Scheme | What it proves |
|---|---|
| `ed25519-json-v1` | The manifest was signed by the holder of an Ed25519 private key. |
| `sha256-items-v1` (legacy) | The payload files match the digests in the manifest. Its `key_id` is a label only, and it never satisfies an authentication policy. |

An `ed25519-json-v1` signature covers the whole manifest (schema, pack ID, version, root, the ordered item array, every item metadata field, the signature algorithm, and the key ID) except the signature bytes. The signature object has exactly `algorithm`, `key_id`, and `signature` (lowercase 128-character hex). The signed bytes are ASCII `BHF.UPDATE_PACK.ED25519.V1\0` followed by compact UTF-8 JSON of the manifest with only `signature.signature` removed. Object keys are sorted recursively, array order is preserved, and strings use `serde_json` escaping. Because `key_id` is signed, a pack cannot be relabeled from a revoked key ID to a trusted alias, even when both IDs map to the same public key. Unknown fields, duplicate fields, invalid types, and malformed signatures are rejected.

## Keys and trust policy

- The private key is a local Ed25519 PKCS#8 v2 DER file, created with exclusive, owner-only permissions by `bhf pack keygen`.
- `bhf pack create --signing-key FILE --key-id ID` signs with it. The older `--sign-key ID` is a deprecated digest label for `sha256-items-v1`; it does not sign, and it conflicts with `--signing-key`.
- bhf never prints private key material or signatures in diagnostics.
- The trusted public key is the raw 32-byte Ed25519 key as lowercase 64-character hex. It is configured only in a policy file on the receiving host, as `update_packs.trusted_public_keys: {"ID": "HEX"}`. `update_packs.revoked_keys` optionally lists revoked IDs.
- The key ID in a manifest is a lookup hint. Trust comes only from the policy.

Example. Install the policy on the receiving host through a separate channel, and keep the private key out of the pack:

```sh
bhf pack keygen --private-key keys/publisher.der --public-key keys/publisher.pub
bhf pack create --root packs/current --pack-id rules-1 --version 1 \
  --item rules:rules.json --signing-key keys/publisher.der --key-id publisher-v1 \
  --out packs/current/pack.json
bhf pack verify packs/current/pack.json --root packs/current --policy policy.json
bhf pack install packs/current/pack.json --root packs/current --policy policy.json \
  --install-dir installed-packs
```

```json
{
  "schema_version": "bhf.policy.v1",
  "policy_id": "offline-publisher-policy",
  "update_packs": {
    "require_signature": true,
    "trusted_public_keys": {"publisher-v1": "<contents of keys/publisher.pub>"},
    "revoked_keys": []
  }
}
```

`bhf pack verify` and `bhf pack install` also take `--require-authenticated`, which rejects any pack without a verified signature from a trusted key.

## Verification rules

- An `ed25519-json-v1` pack verifies only with a matching trusted public key, a valid signature, intact payload hashes, and a key ID that is not revoked, whether or not the policy sets `require_signature`.
- An unknown key, a malformed policy or key, a revoked key, a malformed signed manifest, a changed payload or metadata field, or an unsupported algorithm makes the pack invalid.
- `require_signature: true`, or any trust or revocation setting, rejects unsigned and legacy digest packs, so a signed pack cannot be downgraded to an unsigned one.
- With no authentication policy, legacy digest packs keep their integrity-only behavior.
- Item paths that resolve outside the pack root are rejected.
- Installation verifies before it writes. `install.json` records the authenticated status, algorithm, key ID, and trusted public-key fingerprint.

A valid signature shows which trusted key signed the pack. Whether the content is safe to use, and how the publisher keeps the key, are operational decisions.

**Key rotation:** add the new ID and public key beside the old one, issue new packs, then list the old ID in `revoked_keys` or remove it. Revocation takes precedence over trust. Distribute and protect the policy file separately from the pack. Never commit a private key or put one in a release artifact.

## Installer behavior and limits

- The installer copies the pack into a stage it owns and verifies the staged bytes again before publishing them. The pack identity, signature and item results from both checks must agree, so a payload changed during the copy is rejected.
- On Linux the final directory is published with a no-clobber `renameat2`; an existing destination is rejected.
- Install into a parent directory that other users cannot write. A writable ancestor directory can be swapped between the path checks and the filesystem operations.
- Pack creation and verification hash payloads in fixed-size buffers. On Unix, files are opened with `O_NOFOLLOW | O_NONBLOCK`, and a signing key or pack input that is not a regular file (a FIFO, for example) is rejected without blocking.
- Limits: a manifest is at most 64 MiB, a pack has at most 10,000 items, each payload is at most 2 GiB, and all payloads together at most 20 GiB. Snapshot copying enforces the same byte limits.
- bhf does not hold the source path's ancestor directories open, so a concurrent replacement of an ancestor can redirect a read. Archive signing and hashing read release inputs as they are, so keep them unchanged while you sign.

### Seed archives

`install.sh --install-seeds` extracts the bundled seed corpus into `<prefix>/corpora/seeds` and needs Python 3. When content installation is on, it reads the archive from the verified, installed pack copy, copies at most 2 GiB into an owned snapshot, and validates and extracts that snapshot. Validation allows only regular files and directories, and rejects absolute, traversing or control-character names, more than 100,000 members, any file over 2 GiB, and a declared uncompressed total over 20 GiB. Extraction runs in a staged directory before activation; existing seed content moves to `corpora/seeds.previous.<timestamp>`. With `--no-content`, the installer skips content-pack verification and installation. Recovery from an interrupted seed extraction has not been qualified.

## Distribution packaging

`scripts/package-offline-dist.sh` takes a private signing key and key ID, signs the content pack with `bhf pack create --signing-key/--key-id`, and bundles only the manifest, the payloads, and public, nonsecret metadata. The private key never goes into the distribution. `--legacy-integrity-only` builds an unauthenticated checksum-only pack and must be chosen explicitly.

The installer (`install.sh`) takes the receiving operator's own trust policy with `--trust-policy FILE`, or `--allow-legacy-integrity-only` for a checksum-only pack; it never takes trust from a key or policy inside the pack. An authenticated install verifies in the owned staging prefix before activation. On a bad signature, a changed payload or metadata field, an unknown or revoked key, or a policy downgrade, it leaves the previous prefix and its symlinks unchanged.

## Whole-distribution signature

The pack signature cannot vouch for the `bhf` binary or `install.sh` that checks it, because a hostile bundle could ship a hostile verifier. Authenticate the whole distribution before you run any code from it.

The detached signature covers the exact compressed `bhf-dist-*.tar.gz` bytes:

- `ARCHIVE.tar.gz.sig` holds a raw 64-byte Ed25519 signature over `ASCII("BHF.DIST.TARBALL.ED25519.V1\0") || SHA256(archive bytes)`, where `SHA256` is the 32 binary bytes.
- `bhf pack sign-archive --archive ARCHIVE --signing-key FILE --out SIG` creates it, with the same PKCS#8 v2 key as the content pack. The package script runs it and also writes `.tar.gz.sha256` and `.tar.gz.sig.sha256` sidecars.
- The sidecars detect accidental corruption; they do not authenticate anything.
- The archive holds no private key and no trust policy. You pin the public key yourself.

Verify with `scripts/verify-offline-dist.sh`, obtained through a channel you trust and not from the tarball being checked. It wraps system OpenSSL `pkeyutl` and `dgst` (no BHF executable, no custom cryptography) and takes your raw public-key hex. It checks input types and the exact signature length, converts the public key to an RFC 8410 SubjectPublicKeyInfo, hashes the archive, and verifies the signature before anything is extracted or run. Fetching the wrapper and the public key from the same place as the archive gives no assurance. bhf does not define a signed rotation or rollback policy for the release key.

## Release workflow

The tag-only `sign-linux-bundle` job in `.github/workflows/release.yml` runs in the protected `production-release` environment and needs the secret `BHF_RELEASE_SIGNING_KEY_PKCS8_B64` and the variables `BHF_RELEASE_KEY_ID` and `BHF_RELEASE_PUBLIC_KEY_HEX`. It fails if any is missing or malformed. It decodes the private key only into an owner-only temporary directory outside the upload paths, verifies `.tar.gz.sig` with OpenSSL before extraction, installs with an external trust policy, and uploads the archive, the signature, and both hash sidecars. The PR matrix builds unsigned platform binaries without access to the signing environment. Global checksums and publication run only after the signing job succeeds.

Repository administrators must set protected tag rules, limit the environment to reviewed release refs and approvers, and provision the key before a tag can publish; a workflow run from an attacker-controlled tag could otherwise read the signing secret. Never use a generated CI key for production signing, and never select `--legacy-integrity-only` in a release.

## Tests

- Ring 0.17.14 provides the Ed25519 primitive (`Apache-2.0 AND ISC` in its package metadata). The RFC 8032 section 7.1 test vector verifies against it.
- The governance tests cover metadata and payload tampering, duplicate and unknown fields, malformed policy, a forged trusted key, rotation, revocation, and downgrade.
- `crates/cli/tests/pack_auth_cli.rs` runs key generation, signing, verification, install receipts, tampering, and revocation with temporary keys.
- `crates/cli/tests/offline_dist_scripts.rs` runs the packaging and install scripts with temporary keys and fake bundle fixtures, for both success and rejection. One fixture changes the incoming seed archive after pack installation and checks that extraction uses the installed copy.
