import { readFile } from "node:fs/promises";
import worker from "../index.js";

const feed = await readFile(new URL("../test/fixtures/mihomo-golden-feed.txt", import.meta.url), "utf8");
globalThis.fetch = async (input) => {
  const path = new URL(String(input)).pathname;
  if (path === "/all.txt") {
    return new Response(feed, { status: 200, headers: { etag: '"golden-feed-v1"' } });
  }
  return new Response("", { status: 404 });
};

const response = await worker.fetch(
  new Request("https://worker.example/sub?format=mihomo"),
  { FEED_ORIGIN: "https://feed.example" },
);
if (!response.ok) {
  throw new Error(`mihomo golden render failed with HTTP ${response.status}`);
}
process.stdout.write(await response.text());
