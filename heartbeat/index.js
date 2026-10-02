// External heartbeat for the proxy-collector pipeline.
//
// GitHub's free-tier schedule: crons are best-effort and stopped ticking for
// this repo on 2026-10-01, freezing the pipeline: the watchdog that was
// supposed to recover it lived on the same scheduler, so a second GitHub
// cron could not back it up. This Worker lives on Cloudflare's cron -- a
// different platform -- and POSTs one repository_dispatch to the watchdog
// every 5 minutes. The watchdog's freshness gate does the rest (pool >50
// min -> update, health >70 min -> probe, both fresh -> no-op), so this
// handler is deliberately stateless: one POST, no decisions.
//
// Secrets: GITHUB_TOKEN -- a classic PAT with the `workflow` scope (or a
// GitHub App token). 288 dispatches/day is negligible against the 5000/h
// API rate limit.

const REPO = "TheCalmBoy/proxy-collector";

async function beat(env) {
  const res = await fetch(`https://api.github.com/repos/${REPO}/dispatches`, {
    method: "POST",
    headers: {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${env.GITHUB_TOKEN}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ event_type: "heartbeat" }),
  });
  if (res.status !== 204) {
    const text = await res.text();
    // A 401 means the token was rotated/expired: visible in the Workers
    // log, and the pipeline keeps running on GitHub's own schedule until
    // the secret is refreshed. No retry loop: the next 5-min tick is the
    // retry.
    console.error(`heartbeat dispatch failed: ${res.status} ${text.slice(0, 200)}`);
  }
}

export default {
  async scheduled(event, env) {
    await beat(env);
  },
  async fetch(request, env) {
    // Dashboard/manual trigger: fire one beat immediately.
    if (request.method === "POST") {
      await beat(env);
      return new Response("beat sent", { status: 202 });
    }
    return new Response(
      "proxy-pipeline-heartbeat: POST to fire a beat",
      { status: 200 },
    );
  },
};
