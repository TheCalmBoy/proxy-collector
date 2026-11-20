import { readFile } from "node:fs/promises";
import worker from "../index.js";

const feedPath = process.argv[2];
if (!feedPath) {
  throw new Error("usage: render-mihomo-feed.mjs <feed-file>");
}

const files = new Map([
  ["/all.txt", feedPath],
  ["/egress-health.json", "output/egress-health.json"],
  ["/enriched-configs.json", "output/enriched-configs.json"],
]);
globalThis.fetch = async (input) => {
  const pathname = new URL(String(input)).pathname;
  const file = files.get(pathname);
  if (!file) return new Response("", { status: 404 });
  try {
    const body = await readFile(file);
    const type = pathname.endsWith(".json") ? "application/json" : "text/plain";
    return new Response(body, { status: 200, headers: { "content-type": type } });
  } catch (error) {
    if (error.code === "ENOENT") return new Response("", { status: 404 });
    throw error;
  }
};

const entry = "vless://11111111-2222-3333-4444-555555555555@9.9.9.9:443?encryption=none&type=tcp&security=none#ci-entry";
const encodedEntry = Buffer.from(entry).toString("base64url");
const request = new Request(`https://worker.invalid/sub?format=mihomo&entry64=${encodedEntry}`);
const response = await worker.fetch(request, { FEED_ORIGIN: "https://feed.invalid" });
if (!response.ok) {
  throw new Error(`Production renderer returned HTTP ${response.status}: ${await response.text()}`);
}
process.stdout.write(await response.text());
