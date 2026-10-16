import test from "node:test";
import assert from "node:assert/strict";
import { mihomo } from "../index.js";

const entry = {
  type: "vless", name: "e", server: "1.2.3.4", port: 443, uuid: "u",
  tls: true, network: "ws", udp: true,
  "ws-opts": { path: "/", headers: { Host: "h.example" } },
};
const yamlOf = (options) => mihomo([{ proxy: entry, tag: "ET1" }], [], {}, null, options);

test("mihomo profile carries its own DNS so a client needs no DNS setup", () => {
  const out = yamlOf();
  assert.match(out, /\ndns:\n  enable: true\n/);
  assert.match(out, /  enhanced-mode: fake-ip\n/);
  assert.match(out, /  proxy-server-nameserver:\n    - 223\.5\.5\.5\n/);
  assert.ok(out.indexOf("\ndns:\n") < out.indexOf("\nproxies:"), "dns block must precede proxies");
});

test("nameserver and proxy-server-nameserver hold the clean resolvers in order", () => {
  const out = yamlOf();
  const resolvers = (key) => {
    const block = out.match(new RegExp("  " + key + ":\\n((?:    - .*\\n)+)"));
    assert.ok(block, key + " block missing");
    return block[1].trim().split("\n").map((line) => line.replace(/^\s*- /, ""));
  };
  for (const key of ["nameserver", "proxy-server-nameserver"])
    assert.deepEqual(resolvers(key), ["223.5.5.5", "223.6.6.6", "178.22.122.100"]);
});

test("dns: false omits the block entirely (?dns=0 opt-out)", () => {
  const out = yamlOf({ dns: false });
  assert.doesNotMatch(out, /^dns:/m);
  assert.doesNotMatch(out, /proxy-server-nameserver/);
  assert.match(out, /^proxies:$/m, "proxies must still render");
});

test("dns defaults to on when no options are passed", () => {
  assert.match(mihomo([{ proxy: entry, tag: "ET1" }], [], {}, null), /^dns:$/m);
});
