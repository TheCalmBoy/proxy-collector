import test from "node:test";
import assert from "node:assert/strict";
import worker, {
  MAX_BODY_BYTES,
  byteLength,
  cutToBytes,
  reply,
} from "/home/pedi/proxy-collector-ech/workers/proxy-chain-subscription/index.js";

// ---------- reply(): never exceed the byte budget, never cut mid-line ----------

test("reply trims an over-long single line to within the budget", async () => {
  const res = reply("x".repeat(MAX_BODY_BYTES + 50_000));
  assert.equal(res.headers.get("x-body-truncated"), "true");
  assert.ok(byteLength(await res.text()) <= MAX_BODY_BYTES);
});

test("reply cuts on a line boundary, not mid-line", async () => {
  const line = "y".repeat(99) + "\n";
  const res = reply(line.repeat(Math.ceil((MAX_BODY_BYTES + 5000) / line.length)));
  const body = await res.text();
  assert.ok(byteLength(body) <= MAX_BODY_BYTES);
  assert.ok(body.endsWith("\n"), "expected the cut to land on a newline");
  assert.ok(body.split("\n").every((l) => l === "" || l.length === 99));
});

test("reply counts bytes, not characters, on multibyte text", async () => {
  // 300_001 euro signs = 900_003 bytes: over the budget, on one line, with no
  // newline available to cut on. Only a real byte count catches this.
  const res = reply("\u20ac".repeat(300_001));
  assert.equal(res.headers.get("x-body-truncated"), "true");
  assert.ok(byteLength(await res.text()) <= MAX_BODY_BYTES);
});

test("reply leaves an in-budget body untouched", async () => {
  const res = reply("small body\n");
  assert.equal(res.headers.get("x-body-truncated"), null);
  assert.equal(await res.text(), "small body\n");
});

test("cutToBytes never splits a surrogate pair", () => {
  const text = "\u{1F600}".repeat(200_000); // 800k units, 800k bytes
  const cut = cutToBytes(text, 400_000);
  assert.ok(cut % 2 === 0, `cut landed inside a surrogate pair: ${cut}`);
  assert.ok(byteLength(text.slice(0, cut)) <= 400_000);
});

// ---------- end to end: a feed that genuinely exceeds the cap ----------

const code = (i) => String.fromCharCode(65 + Math.floor(i / 26)) + String.fromCharCode(65 + (i % 26));
const CODES = Array.from({ length: 110 }, (_, i) => code(i));
const PER_COUNTRY = 60;
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

test("an oversized feed is trimmed by whole exits and stays consistent", async () => {
  globalThis.fetch = async (input) => {
    const u = String(input);
    if (u.includes("egress-health.json") || u.includes("enriched-configs.json"))
      return new Response("", { status: 404 });
    return new Response(FEED, { status: 200 });
  };

  const started = Date.now();
  const res = await worker.fetch(
    new Request(`https://w.example/sub?format=mihomo&entry64=${entry64(ENTRY_URI)}`), {});
  const elapsed = Date.now() - started;
  const body = await res.text();

  assert.equal(res.status, 200);
  // The whole point: the body is inside the budget...
  assert.ok(byteLength(body) <= MAX_BODY_BYTES, `body was ${byteLength(body)} bytes`);
  // ...because whole exits were dropped, not because the text was sliced.
  assert.equal(res.headers.get("x-body-truncated"), null, "should not need a byte slice");
  const dropped = Number(res.headers.get("x-exits-dropped"));
  assert.ok(dropped > 0, "expected exits to be dropped");

  const kept = [...body.matchAll(/^    dialer-proxy: (".*")$/gm)].length;
  assert.equal(kept + dropped, TOTAL_EXITS, "every exit is either kept or counted as dropped");

  // No group may reference a proxy that was trimmed away.
  const proxyNames = [...body.matchAll(/^    name: (".*")$/gm)].map((m) => m[1]);
  const groupNames = [...body.matchAll(/^  - name: (".*")$/gm)].map((m) => m[1]);
  const defined = new Set([...proxyNames, ...groupNames]);
  for (const [, ref] of body.matchAll(/^      - (".*")$/gm))
    assert.ok(defined.has(ref), `group references a missing proxy: ${ref}`);

  // Binary search, not a per-exit re-render loop: this must stay fast.
  assert.ok(elapsed < 20_000, `took ${elapsed}ms - the fit loop may be quadratic`);
  console.log(`      (kept ${kept}/${TOTAL_EXITS} exits, dropped ${dropped}, ${byteLength(body)} bytes, ${elapsed}ms)`);
});
