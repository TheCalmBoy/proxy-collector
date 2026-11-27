import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../..", import.meta.url));
const renderer = `${root}/workers/proxy-chain-subscription/scripts/render-mihomo-golden.mjs`;
const fixture = `${root}/workers/proxy-chain-subscription/test/fixtures/mihomo-golden.yaml`;

test("a fixed feed renders exactly the committed Mihomo golden file", () => {
  const actual = execFileSync(process.execPath, [renderer], { cwd: root, encoding: "utf8" });
  const expected = readFileSync(fixture, "utf8");
  assert.equal(actual, expected);
});
