#!/usr/bin/env bash
set -euo pipefail

# Keep CI deterministic and verify the release asset independently of the
# optional digest field in GitHub's release API.
version="v1.19.34"
asset="mihomo-linux-amd64-v1.19.34.gz"
sha256="223fab877e5795ce780ba39902e5f0b1113c1256ae244a7160f1165e017e9ccc"
output="${1:-/tmp/mihomo}"
archive="$(mktemp)"
trap 'rm -f "$archive"' EXIT

mkdir -p "$(dirname "$output")"
curl --fail --location --silent --show-error --retry 3 \
  "https://github.com/MetaCubeX/mihomo/releases/download/${version}/${asset}" \
  -o "$archive"
echo "${sha256}  ${archive}" | sha256sum --check
gzip -dc "$archive" > "$output"
chmod 0755 "$output"
"$output" -v
