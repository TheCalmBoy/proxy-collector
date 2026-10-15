import test from "node:test";
import assert from "node:assert/strict";
import { mihomo, parseEch } from "../index.js";

const entryProxy = {
  type: "vless", name: "e", server: "1.2.3.4", port: 443, uuid: "u",
  tls: true, network: "ws", udp: true,
  ech: "cloudflare-ech.com+udp://208.67.220.220:443",
  "ws-opts": { path: "/", headers: { Host: "h.example" } },
};

test("mihomo emits ech-opts, never tls-opts", () => {
  const out = mihomo([{ proxy: entryProxy, tag: "ET1" }], [], {}, null);
  assert.match(out, /ech-opts:\n      enable: true\n      query-server-name: "cloudflare-ech\.com"/);
  assert.doesNotMatch(out, /tls-opts/);
  assert.doesNotMatch(out, /\n    ech: /);
});

test("no ech-opts when the entry has no tls", () => {
  const out = mihomo([{ proxy: { ...entryProxy, tls: false }, tag: "ET1" }], [], {}, null);
  assert.doesNotMatch(out, /ech-opts/);
});

test("parseEch shapes", () => {
  assert.deepEqual(parseEch("cloudflare-ech.com"), { queryServerName: "cloudflare-ech.com" });
  assert.deepEqual(parseEch("cloudflare-ech.com udp://1.1.1.1:443"), { queryServerName: "cloudflare-ech.com" });
  assert.deepEqual(parseEch("A".repeat(44)), { config: "A".repeat(44) });
  assert.equal(parseEch(""), null);
  assert.equal(parseEch(undefined), null);
  assert.equal(parseEch("not a domain!"), null);
});
