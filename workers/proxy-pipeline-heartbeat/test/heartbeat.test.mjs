import test from "node:test";
import assert from "node:assert/strict";
import worker from "../index.js";

const originalFetch = globalThis.fetch;

test("manual POST without the dedicated trigger secret cannot dispatch", async () => {
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    return new Response(null, { status: 204 });
  };

  try {
    const response = await worker.fetch(
      new Request("https://heartbeat.example/", { method: "POST" }),
      { GITHUB_TOKEN: "github-pat" },
    );
    assert.equal(response.status, 404);
    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("manual POST with the dedicated trigger secret dispatches", async () => {
  let authorization;
  globalThis.fetch = async (_input, init) => {
    authorization = init.headers.authorization;
    return new Response(null, { status: 204 });
  };

  try {
    const response = await worker.fetch(
      new Request("https://heartbeat.example/", {
        method: "POST",
        headers: { authorization: "Bearer manual-secret" },
      }),
      { GITHUB_TOKEN: "github-pat", MANUAL_TRIGGER_TOKEN: "manual-secret" },
    );
    assert.equal(response.status, 202);
    assert.equal(authorization, "Bearer github-pat");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("scheduled dispatch remains independent of manual HTTP authentication", async () => {
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    return new Response(null, { status: 204 });
  };

  try {
    await worker.scheduled({}, { GITHUB_TOKEN: "github-pat" }, {});
    assert.equal(calls, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("non-POST requests are rejected", async () => {
  const response = await worker.fetch(new Request("https://heartbeat.example/"), {});
  assert.equal(response.status, 405);
  assert.equal(response.headers.get("allow"), "POST");
});
