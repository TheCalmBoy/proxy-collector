import test from "node:test";
import assert from "node:assert/strict";
import worker from "../index.js";

test("GET /version returns the deployed Git SHA as JSON", async () => {
  const response = await worker.fetch(
    new Request("https://worker.example/version"),
    { GIT_SHA: "a1b2c3d4" },
  );

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "application/json; charset=utf-8");
  assert.equal(response.headers.get("access-control-allow-origin"), "*");
  assert.deepEqual(await response.json(), { sha: "a1b2c3d4" });
});
