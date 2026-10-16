// The pipeline's only clock.
//
// Cloudflare fires this Worker every 30 minutes (see wrangler.json crons) and
// it POSTs one repository_dispatch(update-now). update.yml then fetches,
// verifies and publishes the pool, and chains probe-egress.yml so the probe
// measures the pool that was just published. Nothing else starts a run: there
// is no GitHub `schedule:` cron anywhere in this repo.
//
// Why 30 minutes and not 15: the chain is update (~6.5 min median, 12.5 max)
// plus probe (~5.2 min). At a 15-minute beat the next tick landed mid-chain,
// the update queued on its concurrency group instead of running, and its
// chained probe landed ~6 min after the previous one with no new pool in
// between. A 30-minute beat leaves the chain ~11 minutes of margin.
//
// There is deliberately no alternation and no KV counter. The earlier design
// dispatched a standalone probe on "odd" beats, but nothing subscribed to that
// event type (probe-egress.yml is workflow_dispatch only), and the KV
// namespace the counter needed was never declared in this config, so every
// beat took the "even" branch: update-now, every time.
//
// Secret: GITHUB_TOKEN -- a classic PAT with the `workflow` scope.
const REPO = "TheCalmBoy/proxy-collector";

async function beat(env) {
  const eventType = env.UPDATE_EVENT || "update-now";
  const res = await fetch(`https://api.github.com/repos/${REPO}/dispatches`, {
    method: "POST",
    headers: {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${env.GITHUB_TOKEN}`,
      "content-type": "application/json",
      // GitHub's API rejects any request without a User-Agent (403: "Request
      // forbidden by administrative rules"). Cloudflare's fetch sends none.
      "user-agent": "proxy-pipeline-heartbeat (Cloudflare Worker)",
    },
    body: JSON.stringify({ event_type: eventType }),
  });
  if (res.status === 204) {
    console.log(`dispatched ${eventType}`);
  } else {
    const detail = (await res.text()).split("\n")[0].slice(0, 200);
    console.error(`dispatch failed: HTTP ${res.status} ${detail}`);
  }
  return res.status;
}

export default {
  async scheduled(_event, env, _ctx) {
    await beat(env);
  },

  // Kept so a beat can be fired by hand when testing (POST the worker URL),
  // and so an accidental GET explains itself instead of erroring.
  async fetch(request, env) {
    if (request.method !== "POST") {
      return new Response(
        "proxy-pipeline-heartbeat: POST here to fire one beat (update-now).\n",
        { status: 200 },
      );
    }
    const status = await beat(env);
    return new Response(
      status === 204 ? "beat sent\n" : `dispatch failed: HTTP ${status}\n`,
      { status: status === 204 ? 202 : 502 },
    );
  },
};
