import test from "node:test";
import assert from "node:assert/strict";
import worker from "/home/pedi/proxy-collector-ech/workers/proxy-chain-subscription/index.js";

const FEED = "http://1.2.3.4:8080#DE-1\nhttp://5.6.7.8:8080#NL-1\nhttp://6.6.6.6:8080#FR-1\n";

function entry64For(uri) {
  let bin = "";
  for (const b of new TextEncoder().encode(uri)) bin += String.fromCharCode(b);
  return encodeURIComponent(btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""));
}

const uriFor = (host, tag) =>
  `vless://11111111-2222-3333-4444-55555555555${host}@${host}:443?encryption=none&type=tcp&security=none#${tag}`;

function stub() {
  globalThis.fetch = async (input) => {
    const u = String(input);
    if (u.includes("egress-health.json") || u.includes("enriched-configs.json"))
      return new Response("", { status: 404 });
    return new Response(FEED, { status: 200 });
  };
}

async function render(entries) {
  stub();
  const qs = entries.map((e) => `&entry64=${entry64For(e)}`).join("");
  const res = await worker.fetch(new Request(`https://w.example/sub?format=mihomo${qs}`), {});
  return { status: res.status, body: res.status === 200 ? await res.text() : "" };
}

// Names of defined proxies:   "    name: \"...\""   at exactly 4 spaces.
// Group names use a different form:   "  - name: \"...\""   so they never match.
const proxyNames = (body) => [...body.matchAll(/^    name: (".*")$/gm)].map((m) => m[1]);
const dialerRefs = (body) => [...body.matchAll(/^    dialer-proxy: (".*")$/gm)].map((m) => m[1]);

test("every dialer-proxy references a proxy that actually exists", async () => {
  const { status, body } = await render([uriFor("9.9.9.9", "entry")]);
  assert.equal(status, 200);
  const names = proxyNames(body);
  const refs = dialerRefs(body);
  assert.ok(refs.length >= 3, `expected 3 chained exits, saw ${refs.length} refs`);
  for (const ref of refs) assert.ok(names.includes(ref), `dangling dialer-proxy: ${ref}`);
});

test("with several entries the exits round-robin and still all resolve", async () => {
  const { status, body } = await render([uriFor("9.9.9.9", "e1"), uriFor("8.8.8.8", "e2")]);
  assert.equal(status, 200);
  const names = proxyNames(body);
  const refs = dialerRefs(body);
  const entryNames = names.filter((n) => n.includes("ET"));
  assert.equal(entryNames.length, 2, "expected two entrypoints");
  assert.equal(new Set(refs).size, 2, "expected the exits to spread over both entries");
  for (const ref of refs) assert.ok(names.includes(ref), `dangling dialer-proxy: ${ref}`);
});

test("the entrypoints themselves carry no dialer-proxy", async () => {
  const { body } = await render([uriFor("9.9.9.9", "entry")]);
  const blocks = body.split("\n  -\n").slice(1);
  for (const block of blocks) {
    if (/name: "ET\d/.test(block))
      assert.doesNotMatch(block, /dialer-proxy/, "an entrypoint must not dial through anything");
  }
});

test("rules keep a catch-all and never leave a gap", async () => {
  const { body } = await render([uriFor("9.9.9.9", "entry")]);
  const rules = body.split("\nrules:\n")[1].split("\n").filter((l) => l.trim().startsWith("-"));
  assert.ok(rules.length > 0, "expected rules");
  assert.ok(rules.some((r) => r.includes("MATCH")), "expected a MATCH catch-all");
});
