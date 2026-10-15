import test from "node:test";
import assert from "node:assert/strict";
import worker from "../index.js";

// A real Cloudflare HTTPS RR (type 65) response, captured from DNS.
const DNS_RESPONSE_HEX = "1234818000010001000000000e636c6f7564666c6172652d65636803636f6d0000410001c00c00410001000000aa00880001000001000602683302683200040008bc726200bc726300000500470045fe0d00415a002000203bc6c1116038c37c22e40e22f627668523f0f1bc9d6cf16f33cb4863d158a9770004000100010012636c6f7564666c6172652d6563682e636f6d0000000600202a0698c13122000000000000000000002a0698c1312300000000000000000000";
const EXPECTED_ECH = "AEX+DQBBWgAgACA7xsERYDjDfCLkDiL2J2aFI/DxvJ1s8W8zy0hj0VipdwAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=";

const ENTRY = "vless://11111111-2222-3333-4444-555555555555@9.9.9.9:443"
  + "?encryption=none&type=ws&security=tls&sni=e.example&host=e.example&path=%2F"
  + "&ech=cloudflare-ech.com+udp://208.67.220.220:443#entry";
// an exit that carries its own ech=, the case the entry-only loop missed
const FEED = "vless://11111111-2222-3333-4444-555555555555@203.0.113.5:443"
  + "?encryption=none&type=tcp&security=tls&sni=x.example&ech=cloudflare-ech.com#DE-1\n";

function entry64(uri) {
  let bin = "";
  for (const b of new TextEncoder().encode(uri)) bin += String.fromCharCode(b);
  return encodeURIComponent(btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""));
}

let dohCalls = 0;
globalThis.fetch = async (input) => {
  const u = String(input);
  if (u.includes("cloudflare-dns.com")) {
    dohCalls += 1;
    const bytes = Uint8Array.from(DNS_RESPONSE_HEX.match(/../g).map((h) => parseInt(h, 16)));
    return new Response(bytes, { status: 200, headers: { "content-type": "application/dns-message" } });
  }
  if (u.includes("egress-health.json") || u.includes("enriched-configs.json"))
    return new Response("", { status: 404 });
  return new Response(FEED, { status: 200 });
};

test("?ech=embed pins the key for exits as well as for the entrypoint", async () => {
  dohCalls = 0;
  const res = await worker.fetch(
    new Request(`https://w.example/sub?format=mihomo&entry64=${entry64(ENTRY)}&ech=embed`),
    {},
  );
  const body = await res.text();

  assert.equal(res.headers.get("x-ech-mode"), "embedded:2", "both the entry and the exit were pinned");
  assert.equal((body.match(/^      config: "/gm) || []).length, 2, "two pinned configs emitted");
  assert.equal((body.match(/query-server-name/g) || []).length, 0, "no lookup left for the client");
  assert.ok(body.includes(EXPECTED_ECH), "the fetched key is the one emitted");
  assert.equal(dohCalls, 1, "one DoH query serves every proxy that wants the same name");
});

test("without ?ech=embed the lookup is left to the client", async () => {
  const res = await worker.fetch(
    new Request(`https://w.example/sub?format=mihomo&entry64=${entry64(ENTRY)}`),
    {},
  );
  const body = await res.text();
  assert.equal(res.headers.get("x-ech-mode"), null, "no ech header unless asked");
  assert.equal((body.match(/query-server-name/g) || []).length, 2, "both keep the query form");
});
