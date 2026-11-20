import test from "node:test";
import assert from "node:assert/strict";
import { friendlyExitName, qualityScore } from "../index.js";

const proxy = { type: "vless", name: "US-RES-X-ABCDEF12", server: "1.1.1.1", port: 443 };
const baseHealth = {
  server: proxy.server,
  server_port: proxy.port,
  risk: "low",
  classification: { min_fraud_score: 10, connection_type: "residential" },
};

test("Gemini label names the HTTP evidence without claiming usability", () => {
  const name = friendlyExitName("US", 0, proxy, {
    node: { ...baseHealth, gemini: { clean: true, flagged: false } },
  });
  assert.match(name, /Gemini HTTP 2xx\/3xx/);
  assert.doesNotMatch(name, /usable|Gem web/i);
});

test("Gemini status does not change proxy ranking", () => {
  const clean = qualityScore({ ...baseHealth, gemini: { clean: true, flagged: false } }, 20);
  const blocked = qualityScore({ ...baseHealth, gemini: { clean: false, flagged: true } }, 20);
  assert.equal(clean, blocked);
});
