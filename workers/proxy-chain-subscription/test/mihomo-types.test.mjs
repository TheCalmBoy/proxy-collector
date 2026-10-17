import test from "node:test";
import assert from "node:assert/strict";
import { mihomo } from "../index.js";

// mihomo has no `socks` proxy type, only `socks5`, and it refuses the whole
// profile when one proxy names a type it cannot build:
//
//   mihomo -t: level=error msg="proxy 74: unsupport proxy type: socks"
//   configuration file test failed
//
// So a single SOCKS5 exit node made the entire subscription unloadable in every
// client, which reads as "the subscription is broken", not "one node is bad".
// Our parser and the sing-box emitter both call the protocol `socks`; only the
// mihomo dialect differs.

const socks = {
  type: "socks",
  name: "ET1 - socks exit",
  server: "91.107.247.193",
  port: 7001,
  username: "user",
  password: "pass",
  udp: true,
};

const yamlOf = (proxy) => mihomo([{ proxy, tag: "ET1" }], [], {}, null);

test("a socks5 node renders as `socks5`, which is the only spelling mihomo has", () => {
  const out = yamlOf(socks);
  assert.match(out, /    type: "socks5"\n/);
  assert.doesNotMatch(out, /    type: "socks"\n/);
});

test("the exact string mihomo rejects never reaches the profile", () => {
  // `type: "socks"` is what produced "unsupport proxy type: socks".
  for (const proxy of [socks, { ...socks, username: undefined, password: undefined }])
    assert.doesNotMatch(yamlOf(proxy), /^    type: "socks"$/m);
});

test("only the type name changes: credentials and port survive the rewrite", () => {
  const out = yamlOf(socks);
  assert.match(out, /    server: "91\.107\.247\.193"\n/);
  assert.match(out, /    port: 7001\n/);
  assert.match(out, /    username: "user"\n/);
  assert.match(out, /    password: "pass"\n/);
  assert.match(out, /    udp: true\n/);
});

test("other proxy types pass through untouched", () => {
  const passthrough = [
    { type: "vless", server: "1.2.3.4", port: 443, uuid: "u", tls: true },
    { type: "trojan", server: "1.2.3.4", port: 443, password: "p", tls: true },
    { type: "ss", server: "1.2.3.4", port: 8388, cipher: "aes-256-gcm", password: "p" },
    { type: "masque", server: "162.159.198.222", port: 443, ip: "172.16.0.2", network: "h2" },
  ];
  for (const proxy of passthrough) {
    const out = yamlOf(proxy);
    assert.match(out, new RegExp(`    type: "${proxy.type}"\\n`), proxy.type + " should pass through");
  }
  // A node that already says socks5 stays socks5, not socks5socks5.
  assert.match(yamlOf({ ...socks, type: "socks5" }), /    type: "socks5"\n/);
});

test("a socks node keeps its dialer-proxy (it is a chained exit, not an entry)", () => {
  const out = mihomo([], [{ code: "DE", variants: [{ proxy: socks, name: "DE exit", dialerProxy: "ET1 - WARP-MASQUE-h2" }] }], {}, null);
  assert.match(out, /    type: "socks5"\n/);
  assert.match(out, /    dialer-proxy: "ET1 - WARP-MASQUE-h2"\n/);
});
