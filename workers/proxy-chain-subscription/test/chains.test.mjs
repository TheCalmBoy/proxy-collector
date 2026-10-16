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

test("an exit gets one variant per entry, prefixed with the entry it dials", async () => {
  const { status, body } = await render([uriFor("9.9.9.9", "e1"), uriFor("8.8.8.8", "e2")]);
  assert.equal(status, 200);
  const blocks = body.split("\n  -\n").slice(1);
  const entryBlocks = blocks.filter((block) => !block.includes("dialer-proxy"));
  const exitBlocks = blocks.filter((block) => block.includes("dialer-proxy"));
  assert.equal(entryBlocks.length, 2, "expected two entrypoints");
  assert.equal(exitBlocks.length, 6, "3 feed exits x 2 entries = 6 variants");
  for (const block of exitBlocks) {
    const prefix = /name: "(ET\d+) - /.exec(block)?.[1];
    const dialer = /dialer-proxy: "([^"]+)"/.exec(block)?.[1];
    assert.ok(prefix, `variant name is not prefixed with ETn: ${block.trim()}`);
    assert.ok(dialer && dialer.startsWith(prefix), `variant ${prefix} dials through ${dialer}`);
  }
  const bases = exitBlocks.map((block) => /name: "ET\d+ - ([^"]+)"/.exec(block)[1]);
  for (const name of new Set(bases))
    assert.equal(bases.filter((base) => base === name).length, 2, `${name} needs one variant per entry`);
  const names = proxyNames(body);
  for (const ref of dialerRefs(body)) assert.ok(names.includes(ref), `dangling dialer-proxy: ${ref}`);
});

test("every dialer-proxy target is an entrypoint that dials through nothing", async () => {
  const { body } = await render([uriFor("9.9.9.9", "entry")]);
  const blocks = body.split("\n  -\n").slice(1);
  const entryNames = new Set(blocks.filter((b) => !b.includes("dialer-proxy"))
    .map((b) => /name: "([^"]+)"/.exec(b)[1]));
  const targets = new Set(blocks.filter((b) => b.includes("dialer-proxy"))
    .map((b) => /dialer-proxy: "([^"]+)"/.exec(b)[1]));
  assert.ok(targets.size > 0, "expected chained exits");
  for (const target of targets)
    assert.ok(entryNames.has(target), `${target} is not a dialer-free entrypoint`);
});

test("rules keep a catch-all and never leave a gap", async () => {
  const { body } = await render([uriFor("9.9.9.9", "entry")]);
  const rules = body.split("\nrules:\n")[1].split("\n").filter((l) => l.trim().startsWith("-"));
  assert.ok(rules.length > 0, "expected rules");
  assert.ok(rules.some((r) => r.includes("MATCH")), "expected a MATCH catch-all");
});

// Without these, the router, NAS and loopback get tunnelled to a foreign exit.
const LOCAL_CIDRS = ["10.0.0.0/8", "127.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                     "169.254.0.0/16", "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10"];

test("local ranges are routed DIRECT, before the catch-all", async () => {
  const { status, body } = await render([uriFor("9.9.9.9", "entry")]);
  assert.equal(status, 200);
  const rules = body.split("\nrules:\n")[1].split("\n").filter((l) => l.trim().startsWith("-"));
  for (const cidr of LOCAL_CIDRS) {
    const idx = rules.findIndex((r) => r.includes(`,${cidr},DIRECT`));
    assert.ok(idx >= 0, `no DIRECT rule for ${cidr}`);
    assert.ok(idx < rules.findIndex((r) => r.includes("MATCH")), `${cidr} must precede MATCH`);
  }
});

test("every DIRECT rule uses no-resolve so it cannot cause a lookup", async () => {
  const { body } = await render([uriFor("9.9.9.9", "entry")]);
  const rules = body.split("\nrules:\n")[1].split("\n").filter((l) => l.includes("DIRECT"));
  for (const r of rules)
    assert.match(r, /no-resolve|DOMAIN-SUFFIX/, `missing no-resolve: ${r.trim()}`);
});

test("the multi-country layout carries the same DIRECT rules", async () => {
  const many = Array.from({ length: 60 }, (_, i) =>
    `http://203.0.113.${i + 1}:8080#${i < 30 ? "DE" : "NL"}-${i + 1}`).join("\n");
  globalThis.fetch = async (input) => {
    const u = String(input);
    if (u.includes("egress-health.json") || u.includes("enriched-configs.json"))
      return new Response("", { status: 404 });
    return new Response(many, { status: 200 });
  };
  const res = await worker.fetch(
    new Request(`https://w.example/sub?format=mihomo&entry64=${entry64For(uriFor("9.9.9.9", "entry"))}`), {});
  const body = await res.text();
  assert.equal(res.status, 200);
  assert.match(body, /IP-CIDR,10\.0\.0\.0\/8,DIRECT,no-resolve/);
  assert.match(body, /IP-CIDR,192\.168\.0\.0\/16,DIRECT,no-resolve/);
});

// A MASQUE (Cloudflare WARP over HTTP/2) entry. Keys are throwaway test values:
// the worker only transcodes them into the mihomo proxy block, it never dials them.
const MASQUE_URI =
  "masque://162.159.198.222:443?private-key=" +
  encodeURIComponent("MHcCAQEEIAEinTfHVKkgO5bHkLFXQD8rSH0bhdetggo4EmIou6rToAoGCCqGSM49AwEHoUQDQgAEMyiUzrpK74Ayox+USj463bp99iDCwYimcppC3QvVsXzX6GcLhEpLRnqOwBLLQbjtYeStuGe6qKnicUty9V6WOg==") +
  "&public-key=" +
  encodeURIComponent("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w==") +
  "&ip=172.16.0.2&ipv6=2606:4700:110:8ed8:2224:87f9:c17b:3358&sni=www.cloudflare.com" +
  "&network=h2&mtu=1400&handshake-timeout=15#WARP-MASQUE-h2";

test("a masque entry renders as a mihomo masque proxy with the keys mihomo needs", async () => {
  const { status, body } = await render([MASQUE_URI]);
  assert.equal(status, 200);
  assert.match(body, /^    type: "?masque"?$/m);
  for (const key of ["private-key", "public-key", "ip", "ipv6", "sni", "network",
                     "skip-cert-verify", "udp", "mtu", "handshake-timeout"])
    assert.match(body, new RegExp(`^    ${key}: `, "m"), `masque proxy is missing ${key}`);
  assert.match(body, /^    network: "?h2"?$/m);
  assert.match(body, /^    skip-cert-verify: "?true"?$/m);
});

test("every exit dials through the masque entry", async () => {
  const { status, body } = await render([MASQUE_URI]);
  assert.equal(status, 200);
  const entry = proxyNames(body).find((n) => n.includes("MASQUE"));
  assert.ok(entry, "expected an entry named ET1 - MASQUE");
  const refs = dialerRefs(body);
  assert.ok(refs.length >= 3, "expected the feed's exits to be chained");
  for (const ref of refs) assert.equal(ref, entry);
});

test("a masque entry is refused in formats that cannot express it", async () => {
  stub();
  for (const format of ["links", "xray"]) {
    const res = await worker.fetch(
      new Request(`https://w.example/sub?format=${format}&entry64=${entry64For(MASQUE_URI)}`), {});
    assert.equal(res.status, 406, `format=${format} must be refused`);
  }
});
