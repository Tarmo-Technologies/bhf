#!/bin/bash
set -euo pipefail
release_repo_root=/home/ubuntu/vuln_research/tools/bhf
release_proof_dir=$(mktemp -d /tmp/bhf-published-0.3.0.XXXXXX)
release_bundle=bhf-dist-0.3.0-x86_64-unknown-linux-gnu
release_commit=acc63b9951d23411300b188710ad0643dd1a6241
gh api repos/Tarmo-Technologies/bhf/releases/tags/0.3.0 > "$release_proof_dir/release-api.json"
jq -e '.tag_name == "0.3.0" and .draft == false and .prerelease == false and .published_at != null' \
  "$release_proof_dir/release-api.json" >/dev/null
jq -e '[.assets[] | select(.state != "uploaded" or .size <= 0)] | length == 0' \
  "$release_proof_dir/release-api.json" >/dev/null
gh api repos/Tarmo-Technologies/bhf/git/ref/tags/0.3.0 > "$release_proof_dir/tag-ref.json"
jq -e '.object.type == "tag" and .object.sha == "d04a61e7c2b3598b65465fba819af16936d16617"' \
  "$release_proof_dir/tag-ref.json" >/dev/null
gh api repos/Tarmo-Technologies/bhf/git/tags/d04a61e7c2b3598b65465fba819af16936d16617 \
  > "$release_proof_dir/tag-object.json"
jq -e --arg commit "$release_commit" '.object.type == "commit" and .object.sha == $commit' \
  "$release_proof_dir/tag-object.json" >/dev/null
gh release download 0.3.0 --repo Tarmo-Technologies/bhf \
  --pattern "$release_bundle.tar.gz*" --pattern linux-bundle-verification.json \
  --dir "$release_proof_dir"
cd "$release_proof_dir"
sha256sum --check "$release_bundle.tar.gz.sha256"
sha256sum --check "$release_bundle.tar.gz.sig.sha256"
mkdir "$release_proof_dir/verified"
python3 "$release_repo_root/scripts/verify-offline-dist.py" \
  --archive "$release_proof_dir/$release_bundle.tar.gz" \
  --signature "$release_proof_dir/$release_bundle.tar.gz.sig" \
  --trusted-public-key /tmp/bhf-v0.3.0-trusted-public-key.hex \
  --max-archive-bytes 536870912 \
  --verified-copy "$release_proof_dir/verified/bundle.tar.gz" --json \
  > "$release_proof_dir/signature-verification.json"
tar -xzf "$release_proof_dir/verified/bundle.tar.gz" -C "$release_proof_dir/verified"
"$release_proof_dir/verified/$release_bundle/tool/bhf" --version \
  | tee "$release_proof_dir/version.txt"
rg -Fx 'bhf v0.3.0' "$release_proof_dir/version.txt" >/dev/null
rg -Fx "commit: $release_commit" "$release_proof_dir/version.txt" >/dev/null
jq '{published_at,html_url,tag_name,asset_count:(.assets|length)}' \
  "$release_proof_dir/release-api.json"
jq . "$release_proof_dir/signature-verification.json"
printf 'release_proof_dir=%s\n' "$release_proof_dir"
