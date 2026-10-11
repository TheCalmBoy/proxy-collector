var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// index.js
var REPO = "TheCalmBoy/proxy-collector";
// Heartbeat: fires every 15 min via CF cron.
// Odd runs (1st, 3rd, ...): dispatch probe-egress workflow directly.
// Even runs (2nd, 4th, ...): dispatch update-now workflow, which chains
//   to probe-egress after db update completes (via gh workflow run in update.yml).
// This achieves probe every 15m minimum, db update every 30m.
async function beat(env) {
  var runCounter = 0;
  if (env.KV) {
    var stored = await env.KV.get(env.RUN_COUNTER_KEY || "run-counter");
    if (stored !== null) runCounter = parseInt(stored, 10) || 0;
  }
  var isEven = runCounter % 2 === 0;
  var eventType = isEven ? "update-now" : "probe-egress";
  var phase = isEven ? "database-update + chained probe" : "probe-only";
  var res = await fetch(`https://api.github.com/repos/${REPO}/dispatches`, {
    method: "POST",
    headers: {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${env.GITHUB_TOKEN}`,
      "content-type": "application/json",
      "user-agent": "proxy-pipeline-heartbeat (Cloudflare Worker)"
    },
    body: JSON.stringify({
      event_type: eventType,
      client_payload: {
        run_index: String(runCounter),
        phase: phase,
        dispatch_source: "heartbeat"
      }
    })
  });
  var nextCounter = runCounter + 1;
  if (env.KV) {
    await env.KV.put(env.RUN_COUNTER_KEY || "run-counter", String(nextCounter));
  }
  if (res.status !== 204) {
    const text = await res.text();
    console.error(`heartbeat dispatch failed (run ${runCounter}, ${phase}): ${res.status} ${text.slice(0, 200)}`);
  } else {
    console.log(`Heartbeat run ${runCounter}: dispatched ${eventType} (${phase})`);
  }
  return { status: res.status, runCounter: runCounter, phase: phase };
}
__name(beat, "beat");
var heartbeat_default = {
  async scheduled(event, env) {
    await beat(env);
  },
  async fetch(request, env) {
    if (request.method === "POST") {
      var result = await beat(env);
      return new Response(
        result.status === 204
          ? `beat sent (run ${result.runCounter}: ${result.phase})`
          : `dispatch failed: HTTP ${result.status}`,
        { status: result.status === 204 ? 202 : 502 }
      );
    }
    return new Response(
      "proxy-pipeline-heartbeat: POST to fire a beat. Every 15m: odd=probe, even=db update + chained probe.",
      { status: 200 }
    );
  }
};
export {
  heartbeat_default as default
};
//# sourceMappingURL=index.js.map
