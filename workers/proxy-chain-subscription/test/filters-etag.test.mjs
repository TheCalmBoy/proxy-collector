import test from "node:test";
import assert from "node:assert/strict";
import worker from "../index.js";

const FEED = [
  "vless://11111111-2222-3333-4444-555555555555@1.1.1.1:443?encryption=none&type=tcp&security=none#US-RES-Test-AAAA1111",
  "trojan://password@2.2.2.2:443?sni=example.com#DE-DC-Test-BBBB2222",
  "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@3.3.3.3:8388#JP-DC-Test-CCCC3333",
].join("\n");
const BASE_TIME = Date.UTC(2026, 0, 1);

function stubFeed() {
  globalThis.fetch = async (input) => {
    const path = new URL(String(input)).pathname;
    if (path === "/all.txt") return new Response(FEED, { status: 200 });
    return new Response("", { status: 404 });
  };
}

function request(query = "") {
  return new Request(`https://worker.example/sub?format=mihomo${query}`);
}

function conditionalRequest(tag) {
  return new Request("https://worker.example/sub?format=mihomo", {
    headers: { "If-None-Match": tag },
  });
}

function stubStableInputs({ feed = FEED, feedEtag = '"feed-v1"', healthGeneratedAt = BASE_TIME - 60e3 } = {}) {
  const health = {
    generated_at: new Date(healthGeneratedAt).toISOString(),
    configs: { AAAA1111: {}, BBBB2222: {}, CCCC3333: {} },
  };
  globalThis.fetch = async (input) => {
    const path = new URL(String(input)).pathname;
    if (path === "/all.txt") return new Response(feed, { status: 200, headers: { etag: feedEtag } });
    if (path === "/egress-health.json") {
      return new Response(JSON.stringify(health), { status: 200, headers: { etag: '"health-v1"' } });
    }
    if (path === "/enriched-configs.json") {
      return new Response(JSON.stringify({ configs: [] }), { status: 200, headers: { etag: '"enriched-v1"' } });
    }
    return new Response("", { status: 404 });
  };
}

async function withDateNow(timestamp, callback) {
  const originalNow = Date.now;
  Date.now = () => timestamp;
  try {
    return await callback();
  } finally {
    Date.now = originalNow;
  }
}

test("protocol filter keeps only matching exits and accepts aliases", async () => {
  stubFeed();
  const response = await worker.fetch(request("&protocol=trojan"), { FEED_ORIGIN: "https://feed.example" });
  const body = await response.text();
  assert.equal(response.status, 200);
  assert.match(body, /2\.2\.2\.2/);
  assert.doesNotMatch(body, /1\.1\.1\.1/);

  const alias = await worker.fetch(request("&protocol=shadowsocks"), { FEED_ORIGIN: "https://feed.example" });
  const aliasBody = await alias.text();
  assert.equal(alias.status, 200);
  assert.match(aliasBody, /3\.3\.3\.3/);
  assert.doesNotMatch(aliasBody, /1\.1\.1\.1/);
});

test("exclude filter removes exits in the listed country", async () => {
  stubFeed();
  const response = await worker.fetch(request("&exclude=DE"), { FEED_ORIGIN: "https://feed.example" });
  const body = await response.text();
  assert.equal(response.status, 200);
  assert.match(body, /1\.1\.1\.1/);
  assert.doesNotMatch(body, /2\.2\.2\.2/);
});

test("invalid filter values are rejected", async () => {
  stubFeed();
  const protocol = await worker.fetch(request("&protocol=unknown"), { FEED_ORIGIN: "https://feed.example" });
  const country = await worker.fetch(request("&exclude=DEU"), { FEED_ORIGIN: "https://feed.example" });
  assert.equal(protocol.status, 400);
  assert.equal(country.status, 400);
});

test("matching If-None-Match returns a bodyless 304", async () => {
  stubFeed();
  const first = await worker.fetch(request(), { FEED_ORIGIN: "https://feed.example" });
  const tag = first.headers.get("etag");
  assert.ok(tag);
  assert.match(first.headers.get("cache-control"), /private/);

  const conditional = new Request("https://worker.example/sub?format=mihomo", {
    headers: { "If-None-Match": tag },
  });
  const second = await worker.fetch(conditional, { FEED_ORIGIN: "https://feed.example" });
  assert.equal(second.status, 304);
  assert.equal(second.headers.get("etag"), tag);
  assert.equal(await second.text(), "");
});

test("unchanged mihomo input keeps its ETag for 30 minutes", async () => {
  stubStableInputs();
  const first = await withDateNow(BASE_TIME, () => worker.fetch(request(), { FEED_ORIGIN: "https://feed.example" }));
  const tag = first.headers.get("etag");
  assert.ok(tag);

  const later = await withDateNow(BASE_TIME + 30 * 60e3, () =>
    worker.fetch(conditionalRequest(tag), { FEED_ORIGIN: "https://feed.example" }),
  );
  assert.equal(later.status, 304);
  assert.equal(later.headers.get("etag"), tag);
});

test("a changed feed ETag invalidates the conditional response", async () => {
  stubStableInputs({ feedEtag: '"feed-v1"' });
  const first = await worker.fetch(request(), { FEED_ORIGIN: "https://feed.example" });
  const tag = first.headers.get("etag");
  assert.ok(tag);

  stubStableInputs({ feedEtag: '"feed-v2"' });
  const changed = await worker.fetch(conditionalRequest(tag), { FEED_ORIGIN: "https://feed.example" });
  assert.equal(changed.status, 200);
  assert.notEqual(changed.headers.get("etag"), tag);
});

test("a fresh-to-aged health transition invalidates the conditional response", async () => {
  stubStableInputs({ healthGeneratedAt: BASE_TIME - 23.75 * 60 * 60e3 });
  const first = await withDateNow(BASE_TIME, () => worker.fetch(request(), { FEED_ORIGIN: "https://feed.example" }));
  const tag = first.headers.get("etag");
  assert.equal(first.headers.get("x-health-index"), "fresh");
  assert.ok(tag);

  const aged = await withDateNow(BASE_TIME + 30 * 60e3, () =>
    worker.fetch(conditionalRequest(tag), { FEED_ORIGIN: "https://feed.example" }),
  );
  assert.equal(aged.status, 200);
  assert.equal(aged.headers.get("x-health-index"), "aged");
  assert.notEqual(aged.headers.get("etag"), tag);
});
