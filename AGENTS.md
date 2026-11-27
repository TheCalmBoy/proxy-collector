# Repository guide

## Layout

- `main.py` and `tools/` collect, probe, verify, and publish the proxy pool.
- `tests/` and `run_tests.py` cover the Python pipeline.
- `workers/` contains the Cloudflare subscription, egress, and heartbeat Workers.
- `dashboard/` holds the static pool dashboard copied into the published site.
- `scripts/` contains maintainer commands, including the pinned Mihomo installer.
- `.github/workflows/` contains the test, update, probe, and deployment workflows.

## Baseline check

Before and after each task, run:

```bash
python3 run_tests.py
node --test workers/proxy-chain-subscription/test/*.test.mjs workers/proxy-pipeline-heartbeat/test/*.test.mjs
node workers/proxy-chain-subscription/scripts/render-mihomo-smoke.mjs > /tmp/smoke.yaml
bash scripts/install-mihomo.sh /tmp/mihomo && /tmp/mihomo -t -f /tmp/smoke.yaml -d /tmp
```

`bash scripts/check.sh` runs the same baseline.

## Invariants

- GitHub workflows have no `schedule:` triggers. The Cloudflare heartbeat is the only clock.
- Pool publication, the `gh-pages` deploy, and the chained probe dispatch run only on `refs/heads/main`.
- Raw source URLs, query strings, tokens, and credentials must not appear in logs, manifests, or published files.
- Probe endpoints must resolve to globally routable IPs and be pinned before probes connect.
- One unsupported proxy type must not invalidate a whole Mihomo profile; validate rendered profiles with `mihomo -t`.
- Do not edit `triggers.crons` in any `wrangler.json`.
- Do not rename the `test` job in `.github/workflows/test.yml`; it is the required status check protecting `main`.

## Branches and protection

The `protect-main` ruleset blocks direct pushes to `main`. Work on an `agent/<task-slug>` branch and open one focused PR per task. The owner reviews and merges PRs. Use a merge commit for larger changes when keeping commit history matters.

The `cloudflare-production` GitHub Environment contains `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`. Never print or log those secrets. Merging to `main` publishes the pool and deploys the Workers.

Keep PRs small and focused: one concern each.
