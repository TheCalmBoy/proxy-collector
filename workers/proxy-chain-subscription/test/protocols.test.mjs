import test from "node:test";
import assert from "node:assert/strict";
import worker from "../index.js";

const FEED = [
  "hysteria2://secret@192.0.2.1:443?obfs=salamander&obfs-password=pad&sni=front.example&alpn=h3#hy2",
  "tuic://11111111-2222-3333-4444-555555555555:secret@192.0.2.2:443?congestion_control=bbr&udp-relay-mode=native#tuic",
  "anytls://secret@192.0.2.3:443?sni=front.example&fp=chrome#anytls",
  "ss://not-a-cipher:secret@192.0.2.4:8388#invalid-cipher",
  "vless://@192.0.2.5:443?security=tls#missing-uuid",
  "vless://11111111-2222-3333-4444-555555555555@192.0.2.6:443?security=tls&sni=front.example#valid-vless",
].join("\n");

const originalFetch = globalThis.fetch;

async function subscription(format) {
  globalThis.fetch = async (input) => {
    const url = String(input);
    if (url.includes("egress-health.json") || url.includes("enriched-configs.json"))
      return new Response("", { status: 404 });
    return new Response(FEED, { status: 200 });
  };
  return worker.fetch(new Request(`https://w.example/sub?format=${format}`), {});
}

test("Mihomo renders verified Hysteria2, TUIC, and AnyTLS nodes", async () => {
  try {
    const response = await subscription("mihomo");
    const body = await response.text();
    assert.equal(response.status, 200);
    for (const type of ["hysteria2", "tuic", "anytls"])
      assert.match(body, new RegExp(`type: "${type}"`));
    assert.match(body, /obfs-password: "pad"/);
    assert.match(body, /congestion-controller: "bbr"/);
    assert.match(body, /client-fingerprint: "chrome"/);
    assert.doesNotMatch(body, /invalid-cipher|missing-uuid/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("sing-box output maps TLS credentials for the added protocols", async () => {
  try {
    const response = await subscription("sing-box");
    const body = await response.json();
    assert.equal(response.status, 200);
    const outbounds = body.outbounds.filter((item) => ["hysteria2", "tuic", "anytls"].includes(item.type));
    assert.deepEqual(new Set(outbounds.map((item) => item.type)), new Set(["hysteria2", "tuic", "anytls"]));
    for (const outbound of outbounds) {
      assert.equal(outbound.tls.enabled, true);
      assert.equal(outbound.password, "secret");
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Xray output omits proxy types it cannot represent", async () => {
  try {
    const response = await subscription("xray");
    const body = Buffer.from(await response.text(), "base64").toString("utf8");
    assert.equal(response.status, 200);
    assert.doesNotMatch(body, /hysteria2|anytls|tuic/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("malformed proxy fields are discarded without breaking the subscription", async () => {
  try {
    const response = await subscription("mihomo");
    const body = await response.text();
    assert.equal(response.status, 200);
    assert.doesNotMatch(body, /uuid: ""|type: "ss"/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
