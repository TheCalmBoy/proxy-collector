import test from "node:test";
import assert from "node:assert/strict";
import worker from "../index.js";

// Two plain-text in-transit exits. plain http => never depends on the health index.
const FEED = "http://1.2.3.4:8080#DE-1\nhttp://5.6.7.8:8080#NL-1\n";
const ENTRY_URI =
  "vless://11111111-2222-3333-4444-555555555555@9.9.9.9:443?encryption=none&type=tcp&security=none#entry";

function entry64(uri) {
  let bin = "";
  for (const b of new TextEncoder().encode(uri)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const ENTRY = encodeURIComponent(entry64(ENTRY_URI));
const DAY = 86400e3;

function stub({ healthStatus = 404, health = null } = {}) {
  globalThis.fetch = async (input) => {
    const u = String(input);
    if (u.includes("egress-health.json"))
      return healthStatus === 200
        ? new Response(JSON.stringify(health), { status: 200 })
        : new Response("", { status: healthStatus });
    if (u.includes("enriched-configs.json")) return new Response("", { status: 404 });
    return new Response(FEED, { status: 200 });
  };
}

const call = () =>
  worker.fetch(new Request(`https://w.example/sub?format=mihomo&entry64=${ENTRY}`), {});

test("missing health doc serves instead of 503", async () => {
  stub({ healthStatus: 404 });
  const res = await call();
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("x-health-index"), "missing");
  assert.match(await res.text(), /^proxies:/m);
});

test("aged health doc (3 days) serves with an age header", async () => {
  stub({
    healthStatus: 200,
    health: { generated_at: new Date(Date.now() - 3 * DAY).toISOString(), configs: {} },
  });
  const res = await call();
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("x-health-index"), "aged");
  const age = Number(res.headers.get("x-health-age"));
  assert.ok(Math.abs(age - 3 * 86400) < 120, `age header was ${age}`);
});

test("unparseable generated_at degrades instead of 503", async () => {
  stub({ healthStatus: 200, health: { generated_at: "not-a-date", configs: {} } });
  const res = await call();
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("x-health-index"), "unusable");
});

test("health endpoint 500 degrades instead of 503", async () => {
  stub({ healthStatus: 500 });
  const res = await call();
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("x-health-index"), "unavailable");
});

test("older than the 7-day ceiling is ignored, still serves", async () => {
  stub({
    healthStatus: 200,
    health: { generated_at: new Date(Date.now() - 8 * DAY).toISOString(), configs: {} },
  });
  const res = await call();
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("x-health-index"), "unusable");
});

test("just inside 24h still applies the index (boundary, filtered)", async () => {
  stub({
    healthStatus: 200,
    health: { generated_at: new Date(Date.now() - 23 * 3600e3).toISOString(), configs: {} },
  });
  const res = await call();
  assert.equal(res.status, 503);
  assert.equal(res.headers.get("x-health-index"), "fresh");
  assert.equal((await res.json()).error, "no_recently_verified_proxies");
});

test("the 503 explains itself via headers", async () => {
  stub({ healthStatus: 500 });
  const res = await call();
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("x-health-index"), "unavailable");
});

test("fresh data that verifies nothing still 503s (preserved)", async () => {
  stub({
    healthStatus: 200,
    health: { generated_at: new Date().toISOString(), configs: {} },
  });
  const res = await call();
  assert.equal(res.status, 503);
  assert.equal((await res.json()).error, "no_recently_verified_proxies");
});

test("successful aged response still produces a usable mihomo config", async () => {
  stub({
    healthStatus: 200,
    health: { generated_at: new Date(Date.now() - 2 * DAY).toISOString(), configs: {} },
  });
  const res = await call();
  const body = await res.text();
  assert.match(body, /proxy-groups:/);
  assert.match(body, /rules:/);
  assert.match(body, /dialer-proxy/);
});
