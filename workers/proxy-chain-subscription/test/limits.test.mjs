import test from "node:test";
import assert from "node:assert/strict";
import worker, { reply } from "../index.js";

// The worker deliberately has NO size caps: no per-entry byte limit, no entry
// count limit, and no response byte budget. This file pins that contract, so
// re-adding a cap has to be a deliberate act rather than an accident.
//
// The fixture below is 110 countries x 60 exits. It used to exceed the old
// 900 KB budget and get trimmed to a prefix; it must now arrive whole.

const byteLength = (text) => new TextEncoder().encode(text).length;

const code = (i) => String.fromCharCode(65 + Math.floor(i / 26)) + String.fromCharCode(65 + (i % 26));
const CODES = Array.from({ length: 110 }, (_, i) => code(i));
const PER_COUNTRY = 60; // per-country capping is a separate knob, still in force
const TOTAL_EXITS = CODES.length * PER_COUNTRY; // 6600

const FEED = CODES.flatMap((c, ci) =>
  Array.from({ length: PER_COUNTRY }, (_, k) => `http://203.0.${ci}.${k + 1}:8080#${c}-${k + 1}`)
).join("\n");

const ENTRY_URI =
  "vless://11111111-2222-3333-4444-555555555555@9.9.9.9:443?encryption=none&type=tcp&security=none#entry";

function entry64(uri) {
  let bin = "";
  for (const b of new TextEncoder().encode(uri)) bin += String.fromCharCode(b);
  return encodeURIComponent(btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""));
}

function serveFeed() {
  globalThis.fetch = async (input) => {
    const u = String(input);
    if (u.includes("egress-health.json") || u.includes("enriched-configs.json"))
      return new Response("", { status: 404 });
    return new Response(FEED, { status: 200 });
  };
}

// ---------- reply() no longer trims ----------

test("reply returns a body of any size untouched", async () => {
  const body = "x".repeat(2_000_000);
  const res = reply(body);
  assert.equal(res.headers.get("x-body-truncated"), null);
  assert.equal(res.status, 200);
  assert.equal(byteLength(await res.text()), 2_000_000);
});

test("reply keeps multibyte text whole", async () => {
  const body = "\u20ac".repeat(300_001); // 900_003 bytes
  const res = reply(body);
  assert.equal(res.headers.get("x-body-truncated"), null);
  assert.equal(await res.text(), body);
});

// ---------- an oversized feed arrives whole ----------

test("a feed past the old 900 KB budget renders every exit, not a prefix", async () => {
  serveFeed();
  const started = Date.now();
  const res = await worker.fetch(
    new Request(`https://w.example/sub?format=mihomo&entry64=${entry64(ENTRY_URI)}`), {});
  const elapsed = Date.now() - started;
  const body = await res.text();

  assert.equal(res.status, 200);
  // Nothing reports a trim, because nothing is trimmed any more.
  assert.equal(res.headers.get("x-body-truncated"), null);
  assert.equal(res.headers.get("x-exits-dropped"), null);

  // Every exit is present: one dialer-proxy line per chained exit.
  const chained = [...body.matchAll(/^    dialer-proxy: (".*")$/gm)].length;
  assert.equal(chained, TOTAL_EXITS, `expected ${TOTAL_EXITS} exits, saw ${chained}`);

  // And the body really is past the budget that used to bind here.
  assert.ok(byteLength(body) > 900_000, `body was only ${byteLength(body)} bytes`);

  // Every exit stays reachable: no group may reference a proxy that is gone.
  const proxyNames = [...body.matchAll(/^    name: (".*")$/gm)].map((m) => m[1]);
  const groupNames = [...body.matchAll(/^  - name: (".*")$/gm)].map((m) => m[1]);
  const defined = new Set([...proxyNames, ...groupNames]);
  for (const [, ref] of body.matchAll(/^      - (".*")$/gm))
    assert.ok(defined.has(ref), `group references a missing proxy: ${ref}`);

  console.log(`      (${chained} exits, ${byteLength(body)} bytes, ${elapsed}ms)`);
});

// ---------- no entry count cap ----------

test("more entrypoints than the old 90 cap are all kept", async () => {
  serveFeed();
  const params = Array.from({ length: 200 }, (_, i) =>
    `entry64=${entry64(`socks://10.0.${Math.floor(i / 256)}.${i % 256}:1080#e${i}`)}`).join("&");
  const res = await worker.fetch(new Request(`https://w.example/sub?format=mihomo&${params}`), {});
  const body = await res.text();

  assert.equal(res.status, 200);
  assert.ok(body.includes("ET200"), "entry 200 should have been kept");
  assert.equal(body.includes("ET201"), false, "the request only carried 200 entries");
});

// ---------- no per-entry byte cap ----------

test("an entry longer than the old 9000-byte cap is accepted", async () => {
  serveFeed();
  const long = `vless://11111111-2222-3333-4444-555555555555@9.9.9.9:443?type=ws&path=/${"a".repeat(15_000)}#long`;
  assert.ok(byteLength(long) > 9000, "the fixture must exceed the removed cap");

  const res = await worker.fetch(new Request(`https://w.example/sub?format=mihomo&entry64=${entry64(long)}`), {});
  assert.equal(res.status, 200);
  assert.ok((await res.text()).includes("ET1"), "the long entry should be rendered");
});

// ---------- what is still rejected ----------

test("an empty entry64 is still an error", async () => {
  serveFeed();
  const res = await worker.fetch(new Request("https://w.example/sub?format=mihomo&entry64="), {});
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error, "invalid_entry64");
});
