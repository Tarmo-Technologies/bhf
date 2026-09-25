<!-- SPDX-License-Identifier: Apache-2.0 -->

# Authenticated offline update packs (E1 design and handoff)

Status: governance and CLI implementation complete; distribution packaging integration remains a separate gate. This contract was recorded before code changes.

## Threat model and format

`sha256-items-v1` remains a legacy, unkeyed transport-integrity digest. Its caller-supplied `key_id` is only a label. It must never satisfy an authentication policy. A new `ed25519-json-v1` signature authenticates the entire manifest (schema, pack ID, version, root, ordered item array, every item metadata field, signature algorithm, and key ID) except the signature **bytes** field. The signature object has exactly `algorithm`, `key_id`, and `signature` (lowercase 128-character hex). The signed bytes are ASCII `BHF.UPDATE_PACK.ED25519.V1\0` followed by compact UTF-8 JSON of the manifest with only `signature.signature` removed; object keys are lexicographically sorted recursively and array order is preserved. JSON strings use `serde_json` escaping. Binding `key_id` prevents relabeling a revoked ID to a still-trusted alias, even if both IDs map to the same public key. Unknown fields, duplicate fields, invalid types, and malformed signatures in this version must be rejected, not silently omitted from signed bytes.

The private key is a local Ed25519 PKCS#8 v2 DER file, created with exclusive, owner-only permissions. `bhf pack create --signing-key FILE --key-id ID` signs with it; the old `--sign-key ID` remains a deprecated digest-label option and conflicts with `--signing-key`. Neither private key material nor signatures are printed in diagnostics. The trusted public key is the raw 32-byte Ed25519 public key encoded as lowercase 64-character hex, configured **only** in an installer-controlled policy as `update_packs.trusted_public_keys: {"ID": "HEX"}`. `update_packs.revoked_keys` optionally lists IDs. A manifest-declared key ID is only a lookup hint, never evidence of trust.

Example (the policy is installed independently on the receiving host; never put the private key in the pack):

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

Verification of `ed25519-json-v1` requires an explicit matching trusted public key, valid signature, intact payload hashes, and a non-revoked ID, even without `require_signature`. An unknown key, malformed policy/key, revoked key, malformed signed manifest, payload or metadata tamper, or unsupported algorithm is invalid. `require_signature: true` or any authentication-specific trust/revocation setting rejects unsigned and legacy digest packs (downgrade prevention). Without that policy, legacy digest packs retain their existing integrity-only behavior. Installation verifies before writes; `install.json` must record authenticated status, algorithm, key ID, and trusted public-key fingerprint for audit. This does not make an untrusted pack executable-safe; publication, distribution, and key custody remain operational responsibilities.

Key rotation: add the new ID/public key alongside the old one, issue new packs, then list the old ID in `revoked_keys` (or remove it). Revocation takes precedence over trust. Policy files must be distributed and protected independently of the pack. Private keys must not be committed or included in release artifacts.

Acceptance: independent Ed25519 known-vector or OpenSSL interoperability check; CLI create/verify/install success; metadata and payload tampering fail; forged key ID, unknown key, malformed key, revocation, rotation, and unsigned/legacy downgrade fail under auth policy; legacy integrity-only packs remain installable without auth policy. Signed install identity appears in receipt. No release signing or production credential use in tests.

Implementation evidence: Ring 0.17.14 provides the Ed25519 primitive (`Apache-2.0 AND ISC` in its local package metadata). The RFC 8032 section 7.1 test vector verifies independently; governance tests cover metadata/payload tampering, duplicate and unknown fields, malformed policy, forged trusted key, rotation, revocation and downgrade. `crates/cli/tests/pack_auth_cli.rs` exercises key generation, signing, verification, install receipt, tamper and revocation with temporary keys. The verifier rejects item paths resolving outside the pack root and checks policy before installation writes.

Remaining security gates: the installer now copies into an owned stage and re-verifies the staged bytes before publishing. Linux uses no-clobber `renameat2` for the final directory; a pre-existing destination is rejected. The initial and staged pack identity, signature, and item verification results must agree. This closes the ordinary mutable-payload verify/copy race, with deterministic mutation and concurrent-installer tests. A writable ancestor can still be substituted between path checks and filesystem operations, and non-Linux rename behavior needs native qualification. A controlled, non-world-writable install parent remains part of the deployment threat model. This work does not sign an official release or establish BHF publisher key custody/recovery procedures.

## E1 distribution integration handoff (recorded before script edits)

The offline packager will accept explicit private signing-key and key-ID inputs, sign the content pack with `bhf pack create --signing-key/--key-id`, and bundle **only** the manifest, payloads, and public/nonsecret metadata. It must never copy the private key into the distribution. Checksum-only package generation remains an explicitly selected legacy mode, clearly labeled unauthenticated. The installer will accept an **external** trust policy path supplied by the receiving operator; it must not infer trust from any pack-contained key or policy. Auth-required install must verify in the owned staging prefix before activation and leave the prior prefix and symlinks unchanged on bad signature, tampered payload or metadata, unknown/revoked key, or policy downgrade. Tests will use only temporary keys and fake bundle fixtures and exercise both success and rejection. The scripts' existing staged rollback rules still apply.

Bootstrap limitation: running an unverified `install.sh` or `bhf` binary from an untrusted artifact is not made safe by a public key supplied in the same artifact—the code doing verification could itself be hostile. Receiving operators must authenticate the complete distribution and its verifier out of band, using the detached whole-tarball signature and independently pinned public key **before** executing bundle code. The content-pack signature protects pack data only after that trusted bootstrap. The local signing and verification flow is tested; the protected release workflow and public-key distribution channel remain unexercised operational gates.

Verifier hardening completed: content-pack creation and verification stream SHA-256 in fixed-size buffers. On Unix, regular-file open uses `O_NOFOLLOW | O_NONBLOCK`, and nonregular/FIFO signing-key and pack input files are rejected without blocking. Pack manifests are capped at 64 MiB, item count at 10,000, each payload at 2 GiB, and aggregate payload at 20 GiB; snapshot copying enforces the same payload byte caps. Staged install re-verification ensures published payloads match the signed manifest even if the source changes while copying. The original source path and its ancestors are not held by directory descriptors, so hostile concurrent ancestor replacement can still redirect a read; archive signing/hashing also does not freeze a concurrently mutable release input. These limits are not solved by Ed25519 authentication alone.

Seed archive audit: GNU tar on this host rejected a symlink-following `pivot/marker` member with `Cannot open: Not a directory`, so that attempted outside write was **not** reproduced. It did accept and create a FIFO member (`seed.pipe`) under the extraction directory, which can hang consumers and is unsuitable pack content. The installer now requires Python 3 for `--install-seeds`, reads the archive from the verified installed pack copy when content installation is enabled, copies at most 2 GiB into an owned exclusive archive snapshot, then validates and extracts that same snapshot. A deterministic fixture changes the incoming bundle archive after pack installation and confirms extraction still uses the installed copy. Explicit `--no-content` keeps the unauthenticated bundle source behavior. Validation permits regular files/directories only and rejects absolute/traversing/control-character names, more than 100,000 members, individual files over 2 GiB, and total declared uncompressed size over 20 GiB. Extraction happens in an owned staged directory before activation; existing seed content is retained under `corpora/seeds.previous.<timestamp>`. Uncompressed extraction disk use and interruption/recovery need further qualification.

## E1 whole-distribution bootstrap signature (contract before implementation)

The pack signature alone cannot authenticate the binary that verifies it. A detached archive signature therefore covers the exact compressed `bhf-dist-*.tar.gz` bytes. Format: a raw 64-byte Ed25519 signature in `ARCHIVE.tar.gz.sig`, over `ASCII("BHF.DIST.TARBALL.ED25519.V1\0") || SHA256(archive bytes)` where `SHA256` is exactly 32 binary bytes. The package script signs with the same PKCS#8 v2 private key specified for the content pack and emits `.tar.gz.sha256` and `.tar.gz.sig.sha256` provenance sidecars. No private material or public-key trust policy goes in the archive. The sidecars remain useful for accidental corruption but are not authentication factors. The signature is detached so it cannot refer to itself; no JSON/key-ID metadata is needed for verification. The operator pins the public key independently.

Verification uses a separately obtained, trusted `scripts/verify-offline-dist.sh` wrapper around system OpenSSL `pkeyutl` and `dgst` (no BHF executable or custom cryptography), with the operator's externally provisioned raw public-key hex. The wrapper checks input types and exact signature length, converts the raw public key to RFC 8410 SubjectPublicKeyInfo, computes the archive SHA-256, and verifies the detached Ed25519 signature before tar extraction or installer execution. It must not be sourced from the unverified tarball; fetching the wrapper and public key from the same untrusted release location leaves bootstrap untrusted. A signed key-rotation/rollback policy and trusted verifier distribution channel remain release-operations gates.

Release workflow integration: a separate tag-only `sign-linux-bundle` job requires the protected `production-release` environment's `BHF_RELEASE_SIGNING_KEY_PKCS8_B64` secret and `BHF_RELEASE_KEY_ID` / `BHF_RELEASE_PUBLIC_KEY_HEX` variables. It fails closed if any is absent or malformed, decodes the private key only into an owner-only temporary directory outside upload paths, verifies `.tar.gz.sig` with OpenSSL before extraction, installs with an external trust policy, and uploads archive, signature, and both hash sidecars. The existing PR matrix still builds unsigned platform binaries without access to the signing environment. Global checksums and publication depend on signed-job success. Repository administrators must configure protected tag rules, constrain the environment to reviewed release refs/approvers, and provision the key before tags can publish: a workflow checked out from an attacker-controlled tag could otherwise read the signing secret. Never substitute a generated CI key for production signing and never silently select `--legacy-integrity-only` in a release. No production secret is being created or used in this worktree.
