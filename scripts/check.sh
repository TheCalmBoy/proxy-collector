#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

python3 run_tests.py
node --test workers/proxy-chain-subscription/test/*.test.mjs workers/proxy-pipeline-heartbeat/test/*.test.mjs
node workers/proxy-chain-subscription/scripts/render-mihomo-smoke.mjs > /tmp/smoke.yaml
bash scripts/install-mihomo.sh /tmp/mihomo
/tmp/mihomo -t -f /tmp/smoke.yaml -d /tmp
