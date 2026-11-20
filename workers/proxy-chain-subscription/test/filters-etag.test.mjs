import test from "node:test";
import assert from "node:assert/strict";
import worker from "../index.js";

const FEED = [
  "vless://11111111-2222-3333-4444-555555555555@1.1.1.1:443?encryption=none&type=tcp&security=none#US-RES-Test-AAAA1111",
  "trojan://password@2.2.2.2:443?sni=example.com#DE-DC-Test-BBBB2222",
  "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@3.3.3.3:8388#JP-DC-Test-CCCC3333",
].join("\n");

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
