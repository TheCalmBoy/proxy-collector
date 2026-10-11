var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/index.js
var FFRAUD_ORIGIN = "https://api.ffraud.com";
var CACHE_SECONDS = 6 * 60 * 60;
var CACHE_SALT = "v1";
var MAX_DOWNLOAD_BYTES = 5e6;
var DOWNLOAD_CHUNK_BYTES = 64 * 1024;
function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...headers }
  });
}
__name(json, "json");
function isIpAddress(value) {
  if (typeof value !== "string" || value.length > 45) return false;
  if (value.includes(":")) {
    return /^[0-9a-f:.]+$/i.test(value) && value.split(":").length >= 3;
  }
  const parts = value.split(".");
  return parts.length === 4 && parts.every(
    (part) => /^\d{1,3}$/.test(part) && Number(part) <= 255
  );
}
__name(isIpAddress, "isIpAddress");
function addressFamily(ip) {
  return ip.includes(":") ? "ipv6" : "ipv4";
}
__name(addressFamily, "addressFamily");
function downloadResponse(metadata, byteCount) {
  const prefix = new TextEncoder().encode(`${JSON.stringify(metadata)}
`);
  const chunk = new Uint8Array(DOWNLOAD_CHUNK_BYTES);
  crypto.getRandomValues(chunk);
  let sent = 0;
  let prefixSent = false;
  const body = new ReadableStream({
    pull(controller) {
      if (!prefixSent) {
        prefixSent = true;
        controller.enqueue(prefix);
        return;
      }
      if (sent >= byteCount) {
        controller.close();
        return;
      }
      const length = Math.min(DOWNLOAD_CHUNK_BYTES, byteCount - sent);
      crypto.getRandomValues(chunk);
      controller.enqueue(chunk.slice(0, length));
      sent += length;
    }
  });
  return new Response(body, {
    headers: {
      "content-type": "application/octet-stream",
      "content-length": String(prefix.byteLength + byteCount),
      "cache-control": "no-store, no-transform",
      "x-content-type-options": "nosniff"
    }
  });
}
__name(downloadResponse, "downloadResponse");
function cacheKey(ip) {
  return new Request(`https://ip-fraud-cache.invalid/${CACHE_SALT}/${encodeURIComponent(ip)}`);
}
__name(cacheKey, "cacheKey");
async function getFfraud(ip, env, ctx) {
  const key = cacheKey(ip);
  const cache = caches.default;
  const cached = await cache.match(key);
  if (cached) return { result: await cached.json(), cached: true };
  const headers = { accept: "application/json" };
  const url = new URL(`${FFRAUD_ORIGIN}/public/ip/${encodeURIComponent(ip)}`);
  let method = "GET";
  let body;
  if (env.FFRAUD_API_KEY) {
    url.pathname = "/v1/ip/check";
    method = "POST";
    headers["X-API-Key"] = env.FFRAUD_API_KEY;
    headers["content-type"] = "application/json";
    body = JSON.stringify({ ip });
  }
  const response = await fetch(url, {
    method,
    headers,
    body,
    signal: AbortSignal.timeout(5e3)
  });
  if (!response.ok) throw new Error(`FFraud returned HTTP ${response.status}`);
  const result = await response.json();
  if (result.success === false || result.ip !== ip) {
    throw new Error("FFraud response did not match the requested IP");
  }
  const cacheResponse = json(result, 200, {
    "cache-control": `public, max-age=${CACHE_SECONDS}`
  });
  ctx.waitUntil(cache.put(key, cacheResponse));
  return { result, cached: false };
}
__name(getFfraud, "getFfraud");
var index_default = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method !== "GET") {
      return json({ error: "method_not_allowed" }, 405, { allow: "GET" });
    }
    if (url.pathname !== "/ip" && url.pathname !== "/me") {
      return json({ error: "not_found", usage: "GET /ip" }, 404);
    }
    if (!env.API_BEARER_TOKEN) {
      return json({ error: "service_not_configured" }, 503);
    }
    const auth = request.headers.get("authorization") || "";
    if (auth !== `Bearer ${env.API_BEARER_TOKEN}`) {
      return json({ error: "unauthorized" }, 401, { "www-authenticate": "Bearer" });
    }
    const ip = request.headers.get("CF-Connecting-IP");
    if (!isIpAddress(ip)) return json({ error: "client_ip_unavailable" }, 503);
    let downloadBytes = null;
    if (url.searchParams.has("download_bytes")) {
      downloadBytes = Number(url.searchParams.get("download_bytes"));
      if (!Number.isSafeInteger(downloadBytes) || downloadBytes < 1 || downloadBytes > MAX_DOWNLOAD_BYTES) {
        return json({ error: "download_bytes_must_be_between_1_and_5000000" }, 400);
      }
    }
    try {
      const { result: ffraud, cached } = await getFfraud(ip, env, ctx);
      const cf = request.cf || {};
      const data = {
        ip,
        family: addressFamily(ip),
        cloudflare: {
          country: cf.country || null,
          region: cf.region || null,
          city: cf.city || null,
          postalCode: cf.postalCode || null,
          timezone: cf.timezone || null,
          continent: cf.continent || null,
          colo: cf.colo || null,
          asn: cf.asn || null,
          asOrganization: cf.asOrganization || null,
          latitude: cf.latitude || null,
          longitude: cf.longitude || null,
          httpProtocol: cf.httpProtocol || null,
          tlsVersion: cf.tlsVersion || null
        },
        ffraud,
        cache: { ffraud: cached ? "hit" : "miss", ttlSeconds: CACHE_SECONDS }
      };
      if (downloadBytes !== null) return downloadResponse(data, downloadBytes);
      return json(data, 200, { "cache-control": "no-store" });
    } catch (error) {
      return json({ error: "ip_intelligence_unavailable", detail: String(error.message || error) }, 502, {
        "cache-control": "no-store"
      });
    }
  }
};
export {
  index_default as default
};
//# sourceMappingURL=index.js.map
