import test from "node:test";
import assert from "node:assert/strict";
import worker from "../index.js";

const FEED = [
  "trojan://trojpass@203.0.113.7:443?security=tls#DE-1",
  "vless://11111111-2222-3333-4444-555555555555@203.0.113.8:443?encryption=none&type=tcp&security=none#DE-2",
  "ss://YWVzLTI1Ni1nY206cGFzcw==@203.0.113.9:8388#DE-3",
].join("\n") + "\n";

const ENTRY = "vless://11111111-2222-3333-4444-555555555555@9.9.9.9:443"
  + "?encryption=none&type=ws&security=tls&sni=e.example&host=e.example&path=%2F#entry";

function entry64(uri) {
  let bin = "";
  for (const b of new TextEncoder().encode(uri)) bin += String.fromCharCode(b);
  return encodeURIComponent(btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""));
}

globalThis.fetch = async (input) => {
  const u = String(input);
  if (u.includes("egress-health.json") || u.includes("enriched-configs.json"))
    return new Response("", { status: 404 });
  return new Response(FEED, { status: 200 });
};

const render = async (extra) => {
  const res = await worker.fetch(
    new Request(`https://w.example/sub?format=mihomo&entry64=${entry64(ENTRY)}${extra}`),
    {},
  );
  return { status: res.status, body: await res.text() };
};

test("?secure=1 drops non-TLS hops and keeps TLS ones", async () => {
  const all = await render("");
  const secure = await render("&secure=1");
  const count = (b) => (b.match(/^    dialer-proxy:/gm) || []).length;

  assert.equal(count(all.body), 3, "unfiltered should keep all three exits");
  assert.equal(count(secure.body), 1, "only the trojan exit is a TLS hop");
  assert.ok(secure.body.includes("203.0.113.7"), "kept exit should be the trojan one");
  assert.ok(!secure.body.includes("203.0.113.8"), "plain vless should be dropped");
  assert.ok(!secure.body.includes("203.0.113.9"), "plain shadowsocks should be dropped");
});

test("?secure=1 reports 503 when the feed has no TLS exits", async () => {
  const saved = globalThis.fetch;
  globalThis.fetch = async (input) => {
    const u = String(input);
    if (u.includes("egress-health.json") || u.includes("enriched-configs.json"))
      return new Response("", { status: 404 });
    return new Response("http://203.0.113.5:8080#DE-5\nhttp://203.0.113.6:8080#DE-6\n", { status: 200 });
  };
  const res = await worker.fetch(
    new Request(`https://w.example/sub?format=mihomo&entry64=${entry64(ENTRY)}&secure=1`),
    {},
  );
  globalThis.fetch = saved;
  assert.equal(res.status, 503);
  assert.match(await res.text(), /no_tls_exits_in_feed/);
});
