// index.js
var STALE_HEALTH_MAX_AGE_MS = 24 * 60 * 6e4;
// Above the soft threshold we still serve the index (aged) instead of hard-failing
// the whole subscription; above this we ignore it entirely and serve unfiltered.
var HEALTH_HARD_MAX_AGE_MS = 48 * 60 * 6e4;
var COUNTRY_RE = /^[A-Z]{2}$/;
var PROTOCOL_ALIASES = {
  ss: "ss",
  shadowsocks: "ss",
  socks: "socks5",
  socks5: "socks5",
  hy2: "hysteria2"
};
var FILTERABLE_PROTOCOLS = /* @__PURE__ */ new Set([
  "vless", "vmess", "trojan", "ss", "socks5", "http", "wireguard",
  "masque", "hysteria2", "tuic", "anytls"
]);
function canonicalProtocol(type) {
  return PROTOCOL_ALIASES[type] || type;
}
// Local traffic must never be sent through an exit node. Without these the only
// rule is MATCH,<proxy>, so the router, NAS, printers, mDNS names and loopback
// all get tunnelled to a foreign exit - where they simply fail. no-resolve
// keeps the rule check from triggering a DNS lookup of its own. Verified against
// mihomo: `mihomo -t` accepts this exact set.
var LOCAL_DIRECT_RULES = [
  "IP-CIDR,0.0.0.0/8,DIRECT,no-resolve",
  "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
  "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
  "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
  "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
  "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
  "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
  "IP-CIDR,224.0.0.0/4,DIRECT,no-resolve",
  "IP-CIDR,255.255.255.255/32,DIRECT,no-resolve",
  "IP-CIDR6,::1/128,DIRECT,no-resolve",
  "IP-CIDR6,fc00::/7,DIRECT,no-resolve",
  "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
  "DOMAIN-SUFFIX,local,DIRECT"
];
var ALLOWED_SCHEMES = /* @__PURE__ */ new Set(["vless", "vmess", "trojan", "ss", "socks", "socks5", "http", "wireguard", "masque", "hysteria2", "hy2", "tuic", "anytls"]);
var MIHOMO_SS_CIPHERS = /* @__PURE__ */ new Set(["aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "rc4-md5", "chacha20-ietf", "xchacha20", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "none"]);
function reply(body, status = 200, type = "application/json; charset=utf-8", extra = null) {
  const headers = { "content-type": type, "cache-control": "no-store", "x-content-type-options": "nosniff", ...extra || {} };
  return new Response(body, { status, headers });
}
async function replyWithEtag(request, body, type, extra = null) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body)));
  const encoded = btoa(String.fromCharCode(...digest)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const etag = `"${encoded}"`;
  const headers = {
    "content-type": type,
    "cache-control": "private, no-cache, must-revalidate",
    "x-content-type-options": "nosniff",
    etag,
    ...extra || {}
  };
  const condition = request.headers.get("if-none-match");
  const matches = condition && condition.split(",").some((candidate) => {
    const value = candidate.trim();
    return value === "*" || value.replace(/^W\//, "") === etag;
  });
  return matches ? new Response(null, { status: 304, headers }) : new Response(body, { status: 200, headers });
}
async function digestToken(value) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
  return btoa(String.fromCharCode(...digest)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function requestMatchesEtag(request, etag) {
  const condition = request.headers.get("if-none-match");
  return Boolean(condition && condition.split(",").some((candidate) => {
    const value = candidate.trim();
    return value === "*" || value.replace(/^W\//, "") === etag.replace(/^W\//, "");
  }));
}
async function replyWithStreamEtag(request, body, type, extra = null, seed = "") {
  const etag = `W/"${await digestToken(seed)}"`;
  const headers = {
    "content-type": type,
    "cache-control": "private, no-cache, must-revalidate",
    "x-content-type-options": "nosniff",
    etag,
    ...extra || {}
  };
  if (requestMatchesEtag(request, etag))
    return new Response(null, { status: 304, headers });
  return new Response(body, { status: 200, headers });
}
function fail(error, status = 400, extra = null) {
  return reply(JSON.stringify({ error }), status, "application/json; charset=utf-8", extra);
}
function decodeEntries(url) {
  const values = url.searchParams.getAll("entry64");
  const unique = /* @__PURE__ */ new Set();
  const entries = [];
  for (const encoded of values) {
    if (!encoded)
      throw new Error("invalid_entry64");
    let value;
    try {
      const normalized = encoded.replace(/-/g, "+").replace(/_/g, "/");
      value = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
    } catch {
      throw new Error("invalid_entry64");
    }
    const bytes = Uint8Array.from(value, (c) => c.charCodeAt(0));
    const uri = new TextDecoder("utf-8", { fatal: true }).decode(bytes).trim();
    const scheme = uri.slice(0, uri.indexOf(":")).toLowerCase();
    if (!ALLOWED_SCHEMES.has(scheme))
      throw new Error("unsupported_entry_scheme");
    if (unique.has(uri))
      continue;
    unique.add(uri);
    entries.push({ uri, proxy: parseEntry(uri) });
  }
  return entries.map((item, index) => ({ ...item, tag: entryName(item.proxy, index + 1) }));
}
function safeName(value, fallback) {
  const name = (value || fallback).replace(/[\u0000-\u001f\u007f-\u009f]/g, " ").replace(/["\\]/g, "").trim();
  return name.slice(0, 96) || fallback;
}
function withUriName(uri, name) {
  const base = uri.split("#", 1)[0];
  return `${base}#${encodeURIComponent(name)}`;
}
function buildSpeedIndex(enrichedDocument) {
  const out = {};
  const rows = Array.isArray(enrichedDocument?.configs) ? enrichedDocument.configs : [];
  for (const row of rows) {
    const speed = Number(row?.stages?.download?.speed_mb_s);
    if (!Number.isFinite(speed) || speed <= 0)
      continue;
    const key = endpointKeyOf(row?.server, row?.server_port);
    if (!key)
      continue;
    const prior = out[key];
    if (prior === void 0 || speed > prior)
      out[key] = speed;
  }
  return out;
}
function fnv1a(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = h * 16777619 >>> 0;
  }
  return h >>> 0;
}
function configDisplayName(proxy) {
  const id = feedEntryId(proxy);
  if (id)
    return id.slice(-8).toUpperCase();
  return fnv1a(String(proxy.server || "") + ":" + (proxy.port ?? proxy.server_port ?? "")).toString(16).padStart(8, "0").toUpperCase();
}
function friendlyExitName(country, index, proxy, healthById, entrypointNumber = null, speedByEndpoint = null, endpointIndex = null) {
  const serial = String(index + 1).padStart(2, "0");
  const remark = /^([A-Z]{2})-(RES|DC|UNKNOWN)-(.+)-([A-F0-9]{6,12})$/.exec(proxy.name || "");
  const health = resolveHealthFor({ proxy }, healthById, endpointIndex || buildEndpointIndex(healthById)) || (remark ? healthById[remark[4]] : null);
  const healthClassification = health && typeof health.classification === "object" ? health.classification : health;
  const rotatesAcrossCountries = !!healthClassification && (String(healthClassification.type || "").startsWith("dynamic") || String(healthClassification.subgroup || "").startsWith("dynamic")) && String(healthClassification.same_country) === "false";
  const flag = countryFlag(country, rotatesAcrossCountries);
  const displayName = configDisplayName(proxy);
  const label = displayName ? `${displayName} \xB7 ${countryName(country)}${flag ? " " + flag : ""} ${serial}` : flag ? `${countryName(country)} ${flag} ${serial}` : `${countryName(country)} ${serial}`;
  const prefix = entrypointNumber === null ? "" : `ET${entrypointNumber} - `;
  if (health) {
    const classification = health.classification && typeof health.classification === "object" ? health.classification : health;
    const riskRaw = health.risk ?? classification.risk;
    const riskValue = typeof riskRaw === "string" ? riskRaw.toLowerCase().trim() : "";
    const fraud = Number(classification.min_fraud_score);
    const riskFromScore = Number.isFinite(fraud) ? fraud < 20 ? "low" : fraud < 50 ? "medium" : fraud < 80 ? "high" : "critical" : "";
    const risk = { low: "Low", medium: "Med", high: "High", critical: "Crit" }[riskValue || riskFromScore] || "Unrated";
    const gemini = health.gemini && typeof health.gemini === "object" ? health.gemini : null;
    const geminiTag = gemini?.flagged === true ? "Gemini HTTP 401/403" : gemini?.clean === true ? "Gemini HTTP 2xx/3xx" : "";
    const kindRaw = classification.connection_type ?? health.connection_type;
    const kindValue = typeof kindRaw === "string" ? kindRaw.replace(/[^a-z0-9 -]/gi, "").trim() : "";
    const kind = /resi/i.test(kindValue) ? "Resi" : /data.?center|hosting/i.test(kindValue) ? "DC" : "";
    const tags = [`${risk}${kind ? " " + kind : ""}`];
    if (health.stale === true)
      tags.push("Stale health");
    if (geminiTag)
      tags.push(geminiTag);
    const stability = health.stability || (String(classification.type || "").startsWith("dynamic") ? "Changed" : null);
    if (stability === "Changed" || String(classification.subgroup || "").startsWith("dynamic"))
      tags.push("Dynamic");
    if (String(classification.same_country) === "false")
      tags.push("Multi-country");
    const stage3Speed = speedByEndpoint ? Number(speedByEndpoint[endpointKeyOf(proxy.server, Number(proxy?.port ?? proxy?.server_port))]) : NaN;
    if (Number.isFinite(stage3Speed) && stage3Speed >= 0.01) {
      tags.push(`${stage3Speed.toFixed(3).replace(/\.?0+$/, "")} MB/s`);
    }
    return `${prefix}${label} \xB7 ${tags.join(" \xB7 ")}`;
  }
  if (!remark) {
    const protocol = { vmess: "VMess", vless: "VLESS", trojan: "Trojan", ss: "Shadowsocks", socks: "SOCKS", socks5: "SOCKS", http: "HTTP" }[proxy.type] || "Proxy";
    return `${prefix}${label} \xB7 ${protocol}`;
  }
  if (remark[2] === "UNKNOWN" || remark[3] === "UNKNOWN") {
    const protocol = { vmess: "VMess", vless: "VLESS", trojan: "Trojan", ss: "Shadowsocks", socks: "SOCKS", socks5: "SOCKS", http: "HTTP" }[proxy.type] || "Proxy";
    return `${prefix}${label} \xB7 ${protocol}`;
  }
  const category = remark[2] === "RES" ? "Resi" : remark[2] === "DC" ? "DC" : "Unclassified";
  const network = remark[3] === "UNKNOWN" ? "" : ` \xB7 ${remark[3]}`;
  return `${prefix}${label} \xB7 ${category}${network}`;
}
function feedEntryId(proxy) {
  const name = proxy.name || "";
  const tail = name.split("|").pop().trim();
  if (/^[A-F0-9]{6,12}$/i.test(tail))
    return tail.toUpperCase();
  return /-([A-F0-9]{8,12})$/.exec(name)?.[1] || null;
}
function resolveHealth(healthById, id, endpoint) {
  if (!healthById || typeof healthById !== "object")
    return null;
  if (endpoint) {
    const hit = healthByEndpoint(healthById, endpoint);
    if (hit)
      return hit;
  }
  if (!id)
    return null;
  if (Object.hasOwn(healthById, id))
    return healthById[id];
  const upper = id.toUpperCase();
  if (Object.hasOwn(healthById, upper))
    return healthById[upper];
  const matches = Object.keys(healthById).filter(
    (key) => upper.startsWith(key.toUpperCase()) || key.toUpperCase().startsWith(upper)
  );
  return matches.length === 1 ? healthById[matches[0]] : null;
}
function endpointKeyOf(server, port) {
  return `${String(server).trim().toLowerCase()}:${Number(port)}`;
}
var endpointIndexDoc = null;
var endpointIndexCache = /* @__PURE__ */ new Map();
function buildEndpointIndex(healthById) {
  if (healthById === endpointIndexDoc)
    return endpointIndexCache;
  const index = /* @__PURE__ */ new Map();
  if (healthById && typeof healthById === "object") {
    for (const [key, row] of Object.entries(healthById)) {
      if (!row || typeof row !== "object")
        continue;
      const server = row.server;
      const port = Number(row.server_port);
      if (typeof server !== "string" || !Number.isFinite(port))
        continue;
      const endpointKey = endpointKeyOf(server, port);
      if (!index.has(endpointKey))
        index.set(endpointKey, { key, row });
    }
  }
  endpointIndexDoc = healthById;
  endpointIndexCache = index;
  return index;
}
function resolveHealthFor(item, healthById, endpointIndex) {
  const proxy = item?.proxy || item;
  const server = proxy?.server;
  const port = Number(proxy?.port ?? proxy?.server_port);
  if (typeof server === "string" && Number.isFinite(port) && endpointIndex) {
    const hit = endpointIndex.get(endpointKeyOf(server, port));
    if (hit)
      return hit.row;
  }
  return resolveHealth(healthById, feedEntryId(proxy || {}), null);
}
function healthByEndpoint(healthById, endpoint) {
  const [server, port] = String(endpoint).split(":");
  const direct = healthById[`${server}:${port}`];
  if (direct)
    return direct;
  const row = Object.values(healthById).find(
    (r) => r && typeof r === "object" && endpointKeyOf(r.server, Number(r.server_port)) === endpointKeyOf(server, Number(port))
  );
  return row || null;
}
function parseProxy(uri, index) {
  const scheme = uri.slice(0, uri.indexOf(":")).toLowerCase();
  if (scheme === "vmess") {
    let data;
    const [payload, fragment = ""] = uri.slice(8).split("#", 2);
    const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
    try {
      const binary = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
      const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
      data = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    } catch {
      return null;
    }
    if (!data || typeof data !== "object" || Array.isArray(data) || typeof data.add !== "string" || typeof data.id !== "string")
      return null;
    const port2 = Number(data.port);
    const alterId = Number(data.aid || 0);
    if (!data.add.trim() || !data.id.trim() || !Number.isInteger(port2) || port2 < 1 || port2 > 65535 || !Number.isInteger(alterId) || alterId < 0)
      return null;
    let displayName = fragment || data.ps;
    try {
      displayName = decodeURIComponent(displayName);
    } catch {
    }
    const proxy = {
      type: "vmess",
      name: safeName(displayName, `exit-${index}`),
      server: data.add,
      port: port2,
      uuid: data.id,
      alterId,
      cipher: data.scy || "auto",
      tls: data.tls === "tls",
      network: data.net || "tcp",
      host: data.host || "",
      path: data.path || "",
      servername: data.sni || void 0
    };
    if (proxy.network === "ws")
      proxy["ws-opts"] = { path: proxy.path || "/", headers: { Host: proxy.host || proxy.server } };
    return proxy;
  }
  let u;
  try {
    u = new URL(uri);
  } catch {
    return null;
  }
  const type = u.protocol.slice(0, -1).toLowerCase();
  if (!["vless", "trojan", "ss", "socks", "socks5", "http", "wireguard", "masque", "hysteria2", "hy2", "tuic", "anytls"].includes(type))
    return null;
  const server = u.hostname;
  const port = Number(u.port);
  if (!server || !port)
    return null;
  let decodedName = u.hash.slice(1).replace(/\+/g, " ");
  try {
    decodedName = decodeURIComponent(decodedName);
  } catch {
  }
  const name = safeName(decodedName, `exit-${index}`);
  if (type === "wireguard") {
    const first = (...keys) => keys.map((key) => u.searchParams.get(key)).find((value) => value !== null && value !== "") || "";
    const address = first("address", "ip").split(",").map((value) => value.trim()).filter(Boolean);
    const publicKey = first("publickey", "publicKey", "public-key");
    if (!u.username || !server || !port || !address.length || !publicKey)
      return null;
    const reservedValue = first("reserved");
    const reserved = reservedValue ? reservedValue.split(",").map((value) => Number(value.trim())) : [];
    return {
      type,
      name,
      server,
      port,
      secretKey: decodeURIComponent(u.username),
      address,
      publicKey,
      ...first("presharedkey", "preSharedKey") ? { preSharedKey: first("presharedkey", "preSharedKey") } : {},
      ...Number(first("mtu")) ? { mtu: Number(first("mtu")) } : {},
      ...Number(first("keepalive", "keepAlive")) ? { keepAlive: Number(first("keepalive", "keepAlive")) } : {},
      ...reserved.length && reserved.every(Number.isInteger) ? { reserved } : {},
      ...first("wnoise") ? { wnoise: first("wnoise") } : {},
      ...first("wnoisecount") ? { wnoisecount: first("wnoisecount") } : {},
      ...first("wnoisedelay") ? { wnoisedelay: first("wnoisedelay") } : {},
      ...first("wpayloadsize") ? { wpayloadsize: first("wpayloadsize") } : {}
    };
  }
  if (type === "masque") {
    const first = (...keys) => keys.map((key) => u.searchParams.get(key)).find((value) => value !== null && value !== "") || "";
    const privateKey = first("private-key", "privatekey", "secret") || (u.username ? decodeURIComponent(u.username) : "");
    const publicKey = first("public-key", "publickey", "publicKey");
    const ip = first("ip", "ipv4", "address").split(",")[0].trim();
    const ipv6 = first("ipv6").split(",")[0].trim();
    if (!server || !port || !privateKey || !publicKey)
      return null;
    const handshakeTimeout = Number(first("handshake-timeout", "handshakeTimeout"));
    return {
      type,
      name,
      server,
      port,
      "private-key": privateKey,
      "public-key": publicKey,
      ...ip ? { ip } : {},
      ...ipv6 ? { ipv6 } : {},
      sni: first("sni") || "www.cloudflare.com",
      network: (first("network") || "h2").toLowerCase(),
      "skip-cert-verify": first("skip-cert-verify", "skipCertVerify", "insecure") !== "false",
      udp: first("udp") !== "false",
      mtu: Number(first("mtu")) || 1400,
      ...handshakeTimeout ? { "handshake-timeout": handshakeTimeout } : {},
      ...first("uri") ? { uri: first("uri") } : {}
    };
  }
  if (type === "hysteria2" || type === "hy2") {
    let password;
    try {
      password = decodeURIComponent(u.username || "") || u.searchParams.get("password") || u.searchParams.get("auth") || "";
    } catch {
      return null;
    }
    if (!password)
      return null;
    const obfs = u.searchParams.get("obfs") || "";
    const obfsPassword = u.searchParams.get("obfs-password") || u.searchParams.get("obfs_password") || "";
    const insecure = /^(1|true|yes|on)$/i.test(u.searchParams.get("insecure") || u.searchParams.get("skip-cert-verify") || "");
    const alpn = (u.searchParams.get("alpn") || "").split(",").map((value) => value.trim()).filter(Boolean);
    const up = u.searchParams.get("up") || u.searchParams.get("upmbps") || "";
    const down = u.searchParams.get("down") || u.searchParams.get("downmbps") || "";
    return {
      type: "hysteria2", name, server, port, password,
      ...obfs ? { obfs } : {},
      ...obfsPassword ? { "obfs-password": obfsPassword } : {},
      sni: u.searchParams.get("sni") || u.searchParams.get("servername") || server,
      "skip-cert-verify": insecure,
      ...alpn.length ? { alpn } : {},
      ...up ? { up } : {},
      ...down ? { down } : {},
      udp: true
    };
  }
  if (type === "tuic") {
    let uuid, password;
    try {
      uuid = decodeURIComponent(u.username || "") || u.searchParams.get("uuid") || u.searchParams.get("id") || "";
      password = decodeURIComponent(u.password || "") || u.searchParams.get("password") || "";
    } catch {
      return null;
    }
    const token = u.searchParams.get("token") || "";
    if (!token && (!uuid || !password))
      return null;
    const alpn = (u.searchParams.get("alpn") || "").split(",").map((value) => value.trim()).filter(Boolean);
    const heartbeat = Number(u.searchParams.get("heartbeat-interval") || 0);
    const insecure = /^(1|true|yes|on)$/i.test(u.searchParams.get("insecure") || u.searchParams.get("skip-cert-verify") || "");
    const proxy = {
      type, name, server, port,
      ...uuid ? { uuid } : {},
      ...password ? { password } : {},
      ...token ? { token } : {},
      sni: u.searchParams.get("sni") || u.searchParams.get("servername") || server,
      "skip-cert-verify": insecure,
      ...alpn.length ? { alpn } : {},
      ...u.searchParams.get("udp-relay-mode") ? { "udp-relay-mode": u.searchParams.get("udp-relay-mode") } : {},
      ...u.searchParams.get("congestion-controller") || u.searchParams.get("congestion_control") ? { "congestion-controller": u.searchParams.get("congestion-controller") || u.searchParams.get("congestion_control") } : {},
      ...Number.isFinite(heartbeat) && heartbeat > 0 ? { "heartbeat-interval": heartbeat } : {},
      udp: true
    };
    return proxy;
  }
  if (type === "anytls") {
    let password;
    try {
      password = decodeURIComponent(u.username || "") || u.searchParams.get("password") || "";
    } catch {
      return null;
    }
    if (!password)
      return null;
    const alpn = (u.searchParams.get("alpn") || "").split(",").map((value) => value.trim()).filter(Boolean);
    const insecure = /^(1|true|yes|on)$/i.test(u.searchParams.get("insecure") || u.searchParams.get("skip-cert-verify") || "");
    return {
      type, name, server, port, password,
      sni: u.searchParams.get("sni") || u.searchParams.get("servername") || server,
      "skip-cert-verify": insecure,
      ...u.searchParams.get("fp") ? { "client-fingerprint": u.searchParams.get("fp") } : {},
      ...alpn.length ? { alpn } : {},
      udp: true
    };
  }
  if (type === "vless") {
    const network = u.searchParams.get("type") || "tcp";
    const tlsMode = u.searchParams.get("security") || "none";
    let uuid;
    try { uuid = decodeURIComponent(u.username); } catch { return null; }
    if (!uuid) return null;
    const proxy = {
      type,
      name,
      server,
      port,
      uuid,
      tls: tlsMode !== "none",
      servername: u.searchParams.get("sni") || u.searchParams.get("servername") || void 0,
      network,
      udp: true,
      alpn: u.searchParams.get("alpn")?.split(",").filter(Boolean),
      grpcServiceName: u.searchParams.get("serviceName") || u.searchParams.get("service_name") || ""
    };
    if (tlsMode === "reality")
      proxy.reality = { "public-key": u.searchParams.get("pbk") || "", "short-id": u.searchParams.get("sid") || "" };
    const fp = u.searchParams.get("fp");
    if (fp)
      proxy["client-fingerprint"] = fp;
    const ech = u.searchParams.get("ech");
    if (ech)
      proxy.ech = ech;
    const flow = u.searchParams.get("flow");
    if (flow)
      proxy.flow = flow;
    const path = u.searchParams.get("path");
    if (path)
      proxy["ws-opts"] = { path, headers: { Host: u.searchParams.get("host") || server } };
    return proxy;
  }
  if (type === "trojan") {
    let password;
    try { password = decodeURIComponent(u.username); } catch { return null; }
    if (!password) return null;
    return {
      type,
      name,
      server,
      port,
      password,
      sni: u.searchParams.get("sni") || void 0,
      udp: true
    };
  }
  if (type === "ss") {
    let credentials;
    if (u.password) {
      try {
        credentials = `${decodeURIComponent(u.username)}:${decodeURIComponent(u.password)}`;
      } catch {
        return null;
      }
    } else {
      try {
        const encoded = decodeURIComponent(u.username).replace(/-/g, "+").replace(/_/g, "/");
        const binary = atob(encoded + "=".repeat((4 - encoded.length % 4) % 4));
        credentials = new TextDecoder("utf-8", { fatal: true }).decode(
          Uint8Array.from(binary, (character) => character.charCodeAt(0))
        );
      } catch {
        return null;
      }
    }
    const colon = credentials.indexOf(":");
    if (colon < 1)
      return null;
    const cipher = credentials.slice(0, colon);
    const password = credentials.slice(colon + 1);
    if (!MIHOMO_SS_CIPHERS.has(cipher) || !password)
      return null;
    return { type, name, server, port, cipher, password, udp: true };
  }
  let user, password;
  try { user = decodeURIComponent(u.username || ""); password = decodeURIComponent(u.password || ""); } catch { return null; }
  return { type: type === "socks5" ? "socks5" : type, name, server, port, ...user ? { username: user } : {}, ...password ? { password } : {}, udp: true };
}
function parseProxySafely(uri, index) {
  try {
    return parseProxy(uri, index);
  } catch {
    return null;
  }
}
function parseEntry(uri) {
  const proxy = parseProxy(uri, 0);
  if (!proxy)
    throw new Error("entry_parse_failed");
  proxy.name = safeName(proxy.name, "entrypoint");
  return proxy;
}
function entryName(entry, index) {
  const protocol = { wireguard: "WARP", masque: "MASQUE", vless: "VLESS", vmess: "VMess", trojan: "Trojan", ss: "Shadowsocks", socks: "SOCKS", socks5: "SOCKS", http: "HTTP" }[entry.type] || "Proxy";
  return safeName(`ET${index} - ${entry.name || protocol}`, `ET${index}`);
}
function countryName(code) {
  if (code === "ZZ")
    return "Unknown";
  if (code === "ZZ-RAINBOW")
    return "Rainbow";
  return /^[A-Z]{2}$/i.test(code || "") ? code.toUpperCase() : code;
}
var RAINBOW_FLAG = "\u{1F308}";
function countryFlag(code, dynamic = false) {
  if (dynamic)
    return RAINBOW_FLAG;
  if (!/^[A-Z]{2}$/i.test(code || "") || code.toUpperCase() === "ZZ")
    return "";
  return String.fromCodePoint(...[...code.toUpperCase()].map((c) => 127397 + c.charCodeAt(0)));
}
function yamlScalar(value) {
  return JSON.stringify(value).replace(/[\u007f-\u009f]/g, (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`);
}
// `socks` is the sing-box spelling of the protocol; mihomo only knows `socks5`.
// mihomo refuses the ENTIRE profile when a single proxy names a type it does not
// have ("proxy 74: unsupport proxy type: socks"), so one SOCKS5 exit node made
// every client fail to load the subscription -- the failure looks like a broken
// subscription, not like one bad node. Translate at the dialect boundary, which
// is here: the sing-box emitter keeps its own spelling.
function mihomoType(type) {
  return type === "socks" ? "socks5" : type;
}
// Normalises the share-link `ech` param. Accepts:
//   base64 ECHConfigList                           -> { config }
//   "cloudflare-ech.com"                           -> { queryServerName }
//   "cloudflare-ech.com+udp://1.2.3.4:443" (Xray)  -> { queryServerName } (resolver dropped)
function parseEch(raw) {
  const value = String(raw ?? "").trim().replace(/ /g, "+"); // '+' may arrive as ' '
  if (!value) return null;
  if (/^[A-Za-z0-9+/]{40,}={0,2}$/.test(value)) return { config: value };
  const name = value.split("+")[0].trim().toLowerCase();
  return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(name) ? { queryServerName: name } : null;
}
function scalarFields(object) {
  return Object.entries(object).filter(([, v]) => v !== void 0 && v !== null && typeof v !== "object").map(([k, v]) => `    ${k}: ${typeof v === "string" ? yamlScalar(v) : v}`).join("\n");
}

// Cloudflare publishes the ECH config for a decoy name as a DNS HTTPS (type 65)
// record. Fetching it is what ?ech=embed does, so a client whose own DNS cannot
// resolve the record never has to ask for it.
var ECH_CONFIG_TTL_MS = 3e5;
var echConfigCache = /* @__PURE__ */ new Map();
function b64Bytes(bytes) {
  let binary = "";
  for (const byte of bytes)
    binary += String.fromCharCode(byte);
  return btoa(binary);
}
function b64urlBytes(bytes) {
  return b64Bytes(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function dnsHTTPSQuery(name, type) {
  const out = [0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
  for (const label of name.split(".")) {
    const bytes = new TextEncoder().encode(label);
    out.push(bytes.length, ...bytes);
  }
  out.push(0, type >> 8, type & 255, 0, 1);
  return new Uint8Array(out);
}
function skipDnsName(buf, offset) {
  for (;;) {
    const len = buf[offset];
    if (len === 0)
      return offset + 1;
    if ((len & 192) === 192)
      return offset + 2;
    offset += len + 1;
  }
}
// Pulls the ech (SvcParam key 5) value out of an HTTPS RR answer.
function echFromDnsAnswer(buf) {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const questions = view.getUint16(4);
  const answers = view.getUint16(6);
  let offset = 12;
  for (let i = 0; i < questions; i += 1)
    offset = skipDnsName(buf, offset) + 4;
  for (let i = 0; i < answers; i += 1) {
    offset = skipDnsName(buf, offset);
    const type = view.getUint16(offset);
    const length = view.getUint16(offset + 8);
    offset += 10;
    const end = offset + length;
    if (type === 65) {
      let cursor = skipDnsName(buf, offset + 2);
      while (cursor + 4 <= end) {
        const key = view.getUint16(cursor);
        const size = view.getUint16(cursor + 2);
        cursor += 4;
        if (key === 5)
          return b64Bytes(buf.subarray(cursor, cursor + size));
        cursor += size;
      }
    }
    offset = end;
  }
  return null;
}
async function fetchEchConfig(name) {
  const cached = echConfigCache.get(name);
  if (cached && Date.now() - cached.at < ECH_CONFIG_TTL_MS)
    return cached.value;
  try {
    const response = await fetch(
      "https://cloudflare-dns.com/dns-query?dns=" + b64urlBytes(dnsHTTPSQuery(name, 65)),
      {
        headers: { accept: "application/dns-message" },
        signal: AbortSignal.timeout(4e3)
      }
    );
    if (response.ok) {
      const value = echFromDnsAnswer(new Uint8Array(await response.arrayBuffer()));
      if (value) {
        echConfigCache.set(name, { value, at: Date.now() });
        return value;
      }
    }
  } catch {
  }
  return cached ? cached.value : null;
}

// ?secure=1 keeps only exits whose client-to-exit hop is wrapped in TLS, which
// is what decides whether the ISP sees an ordinary TLS handshake. Plain
// shadowsocks and bare vmess/vless are encrypted but not TLS, so they go.
var TLS_ALWAYS_TYPES = /* @__PURE__ */ new Set(["trojan", "hysteria", "hysteria2", "tuic", "anytls"]);
function isTlsHop(proxy) {
  return TLS_ALWAYS_TYPES.has(proxy.type) || proxy.tls === true;
}
var AMNEZIA_JMIN = 50;
var AMNEZIA_JMAX = 100;
var WARP_SERVER_KEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";
function amneziaWgOption(proxy) {
  if (!proxy.wnoise && proxy.publicKey !== WARP_SERVER_KEY)
    return [];
  const num = (value, fallback) => {
    const parsed = Number.parseInt(String(value ?? "").trim(), 10);
    return Number.isFinite(parsed) ? parsed : fallback;
  };
  return [
    "    amnezia-wg-option:",
    `      jc: ${num(proxy.wnoisecount, 5)}`,
    `      jmin: ${AMNEZIA_JMIN}`,
    `      jmax: ${AMNEZIA_JMAX}`
  ];
}
const DNS_RESOLVERS = ["223.5.5.5", "223.6.6.6", "178.22.122.100"];
function dnsLines(enabled = true) {
  if (!enabled) return [];
  const resolverList = (key) => [`  ${key}:`, ...DNS_RESOLVERS.map((server) => `    - ${server}`)];
  return [
    "dns:",
    "  enable: true",
    "  ipv6: false",
    "  enhanced-mode: fake-ip",
    "  fake-ip-range: 198.18.0.1/16",
    "  fake-ip-filter:",
    '    - "+.lan"',
    '    - "+.local"',
    '    - "localhost.ptlogin2.qq.com"',
    "  default-nameserver:",
    "    - 223.5.5.5",
    "    - 223.6.6.6",
    ...resolverList("nameserver"),
    ...resolverList("proxy-server-nameserver")
  ];
}
function mihomo(entries, countries, healthById, speedByEndpoint = null, options = {}) {
  return [...mihomoStreamChunks(entries, countries, healthById, speedByEndpoint, options)].join("");
}
function mihomoVariantsForExit(country, index, entries = []) {
  if (Array.isArray(country.variants)) {
    const marker = `${country.code}-${String(index + 1).padStart(2, "0")}e`;
    return country.variants.filter((item) => (item.tag || "").startsWith(marker));
  }
  const exits = country.exits || (country.items || []).map((item) => item.proxy);
  const names = country.baseNames || exits.map((proxy, itemIndex) => proxy.name || `${country.code} ${itemIndex + 1}`);
  if (index >= exits.length) return [];
  if (!entries.length) return [{ proxy: exits[index], name: names[index] }];
  return entries.map((entry, slot) => {
    const prefix = (entry.tag || "").split(" ")[0] || `ET${slot + 1}`;
    return { proxy: exits[index], name: `${prefix} - ${names[index]}`, tag: `${country.code}-${String(index + 1).padStart(2, "0")}e${slot + 1}`, dialerProxy: entry.tag };
  });
}
function* eachCountryVariant(country, entries = []) {
  if (Array.isArray(country.variants)) {
    yield* country.variants;
    return;
  }
  const exits = country.exits || (country.items || []).map((item) => item.proxy);
  for (let index = 0; index < exits.length; index += 1)
    yield* mihomoVariantsForExit(country, index, entries);
}
function mihomoProxyBlock(proxy, name, dialerProxy = void 0) {
  const lines = [];
  if (proxy.type === "wireguard") {
    const localIp = proxy.address?.find((value) => value.includes(".")) || proxy.address?.[0] || "";
    lines.push(
      `  - name: ${yamlScalar(name)}`, "    type: wireguard",
      `    ip: ${yamlScalar(localIp.split("/")[0])}`,
      `    private-key: ${yamlScalar(proxy.secretKey)}`, "    peers:",
      `      - server: ${yamlScalar(proxy.server)}`, `        port: ${proxy.port}`,
      `        public-key: ${yamlScalar(proxy.publicKey)}`,
      '        allowed-ips: ["0.0.0.0/0", "::/0"]',
      ...proxy.reserved?.length ? [`        reserved: [${proxy.reserved.join(", ")}]`] : [],
      "    udp: true", ...proxy.mtu ? [`    mtu: ${proxy.mtu}`] : [],
      ...proxy.keepAlive ? [`    persistent-keepalive: ${proxy.keepAlive}`] : [],
      ...amneziaWgOption(proxy), ...dialerProxy ? [`    dialer-proxy: ${yamlScalar(dialerProxy)}`] : []
    );
  } else {
    const { ech, ...scalarProxy } = { ...proxy, type: mihomoType(proxy.type), name, ...dialerProxy ? { "dialer-proxy": dialerProxy } : {} };
    lines.push(`  -\n${scalarFields(scalarProxy)}`);
    if (proxy.reality)
      lines.push(`    reality-opts:\n      public-key: ${yamlScalar(proxy.reality["public-key"])}\n      short-id: ${yamlScalar(proxy.reality["short-id"])}`);
    if (proxy.alpn?.length)
      lines.push(`    alpn:\n${proxy.alpn.map((item) => `      - ${yamlScalar(item)}`).join("\n")}`);
    if (proxy["ws-opts"])
      lines.push(`    ws-opts:\n      path: ${yamlScalar(proxy["ws-opts"].path)}\n      headers:\n        Host: ${yamlScalar(proxy["ws-opts"].headers.Host)}`);
    const echOpts = proxy.tls ? parseEch(ech) : null;
    if (echOpts) {
      lines.push("    ech-opts:", "      enable: true");
      if (echOpts.config) lines.push(`      config: ${yamlScalar(echOpts.config)}`);
      if (echOpts.queryServerName) lines.push(`      query-server-name: ${yamlScalar(echOpts.queryServerName)}`);
    }
  }
  return lines.join("\n");
}
function* mihomoStreamChunks(entries, countries, healthById, speedByEndpoint = null, options = {}) {
  const autoBest = topQualityVariants(countries, healthById || {}, speedByEndpoint, entries);
  yield ["# Generated proxy subscription", ...dnsLines(options.dns !== false), "proxies:"].join("\n") + "\n";
  for (const entry of entries) yield mihomoProxyBlock(entry.proxy, entry.tag) + "\n";
  for (const country of countries)
    for (const item of eachCountryVariant(country, entries))
      yield mihomoProxyBlock(item.proxy, item.name, item.dialerProxy) + "\n";

  yield "proxy-groups:\n";
  if (entries.length)
    yield [`  - name: ${yamlScalar("EntryPoints")}`, "    type: select", "    proxies:", ...entries.map((entry) => `      - ${yamlScalar(entry.tag)}`)].join("\n") + "\n";
  if (countries.length === 1) {
    const only = countries[0];
    const title = `${countryName(only.code)} ${countryFlag(only.code)}`.trim();
    yield [`  - name: ${yamlScalar(title)}`, "    type: select", "    proxies:"].join("\n") + "\n";
    for (const item of eachCountryVariant(only, entries)) yield `      - ${yamlScalar(item.name)}\n`;
    if (autoBest.length > 1) {
      yield [`  - name: ${yamlScalar("Best")}`, "    type: url-test", "    url: http://www.gstatic.com/generate_204", "    interval: 300", "    tolerance: 50", "    lazy: true", "    proxies:", ...autoBest.map((item) => `      - ${yamlScalar(item.name)}`)].join("\n") + "\n";
      yield ["rules:", ...LOCAL_DIRECT_RULES.map((rule) => `  - ${rule}`), "  - MATCH,Best"].join("\n") + "\n";
    } else {
      yield ["rules:", ...LOCAL_DIRECT_RULES.map((rule) => `  - ${rule}`), `  - MATCH,${title}`].join("\n") + "\n";
    }
    return;
  }
  if (countries.length > 1) {
    const groupTitle = (code) => `${countryName(code)} ${countryFlag(code)}`.trim();
    const root = [`  - name: ${yamlScalar("Proxy")}`, "    type: select", "    proxies:"];
    if (autoBest.length > 1) root.push(`      - ${yamlScalar("Best")}`);
    if (entries.length) root.push(`      - ${yamlScalar("EntryPoints")}`);
    for (const country of countries) root.push(`      - ${yamlScalar(groupTitle(country.code))}`);
    yield root.join("\n") + "\n";
    for (const country of countries) {
      yield [`  - name: ${yamlScalar(groupTitle(country.code))}`, "    type: select", "    proxies:"].join("\n") + "\n";
      for (const item of eachCountryVariant(country, entries)) yield `      - ${yamlScalar(item.name)}\n`;
    }
    if (autoBest.length > 1)
      yield [`  - name: ${yamlScalar("Best")}`, "    type: url-test", "    url: http://www.gstatic.com/generate_204", "    interval: 300", "    tolerance: 50", "    lazy: true", "    proxies:", ...autoBest.map((item) => `      - ${yamlScalar(item.name)}`)].join("\n") + "\n";
    yield ["rules:", ...LOCAL_DIRECT_RULES.map((rule) => `  - ${rule}`), "  - MATCH,Proxy"].join("\n") + "\n";
    return;
  }
  yield [`  - name: ${yamlScalar("Proxy")}`, "    type: select", "    proxies:"].join("\n") + "\n";
  for (const country of countries)
    for (const item of eachCountryVariant(country, entries)) yield `      - ${yamlScalar(item.name)}\n`;
  for (const entry of entries) yield `      - ${yamlScalar(entry.tag)}\n`;
  yield ["rules:", ...LOCAL_DIRECT_RULES.map((rule) => `  - ${rule}`), "  - MATCH,Proxy"].join("\n") + "\n";
}
function streamMihomo(entries, countries, healthById, speedByEndpoint = null, options = {}) {
  const iterator = mihomoStreamChunks(entries, countries, healthById, speedByEndpoint, options);
  const encoder = new TextEncoder();
  return new ReadableStream({
    pull(controller) {
      let chunk = "";
      try {
        while (chunk.length < 16 * 1024) {
          const next = iterator.next();
          if (next.done) {
            if (chunk) controller.enqueue(encoder.encode(chunk));
            controller.close();
            return;
          }
          chunk += next.value;
        }
        controller.enqueue(encoder.encode(chunk));
      } catch (error) {
        controller.error(error);
      }
    },
    cancel() { iterator.return?.(); }
  });
}
function pushRules(lines, match) {
  lines.push("rules:");
  for (const rule of LOCAL_DIRECT_RULES)
    lines.push(`  - ${rule}`);
  lines.push(`  - ${match}`);
}
function b64(text) {
  return btoa(String.fromCharCode(...new TextEncoder().encode(text)));
}
var FORMAT_ALIASES = {
  // "clash" was already special-cased to mihomo before this table existed.
  clash: "mihomo",
  clashmeta: "mihomo",
  "clash-meta": "mihomo",
  singbox: "sing-box",
  neko: "sing-box",
  // v2rayN has no bundled-config renderer of its own, so it takes the flat
  // link list. "xray" is deliberately NOT aliased: guessFormat documents
  // ?format=xray as the escape hatch that returns the bundled xray config,
  // and an explicit override must not be silently remapped.
  v2rayn: "links",
  "v2ray-ng": "links",
  v2rayng: "links",
  links: "links"
};
var KNOWN_FORMATS = /* @__PURE__ */ new Set([
  "mihomo",
  "sing-box",
  "links",
  "xray",
  "clash",
  "unknown"
]);
function guessFormat(request, url) {
  const override = url.searchParams.get("format");
  if (override) {
    const key = override.toLowerCase().replace(/[_\s]/g, "-");
    const bare = key.replace(/-/g, "");
    const resolved = FORMAT_ALIASES[key] || FORMAT_ALIASES[bare];
    if (resolved)
      return resolved;
    return KNOWN_FORMATS.has(key) || KNOWN_FORMATS.has(bare) ? bare : null;
  }
  const ua = (request.headers.get("user-agent") || "").toLowerCase();
  if (/clash|mihomo|stash|clash.meta|clash-verge/.test(ua))
    return "mihomo";
  if (/sing-box|singbox|nekobox/.test(ua))
    return "sing-box";
  if (/mahsa|xray|v2rayng|v2ray-ng/.test(ua))
    return "links";
  return "unknown";
}
function xrayOutbound(proxy, tag, dialerProxy) {
  const protocol = proxy.type === "ss" ? "shadowsocks" : proxy.type === "socks5" ? "socks" : proxy.type;
  const outbound = { tag, protocol, settings: {} };
  if (protocol === "wireguard") {
    outbound.settings = {
      secretKey: proxy.secretKey,
      address: proxy.address,
      peers: [{
        endpoint: `${proxy.server}:${proxy.port}`,
        publicKey: proxy.publicKey,
        ...proxy.preSharedKey ? { preSharedKey: proxy.preSharedKey } : {},
        keepAlive: proxy.keepAlive || 0,
        allowedIPs: ["0.0.0.0/0", "::/0"]
      }],
      ...proxy.mtu ? { mtu: proxy.mtu } : {},
      ...proxy.reserved ? { reserved: proxy.reserved } : {},
      ...Object.fromEntries(["wnoise", "wnoisecount", "wnoisedelay", "wpayloadsize"].filter((key) => proxy[key] !== void 0).map((key) => [key, proxy[key]]))
    };
    if (dialerProxy)
      outbound.streamSettings = { sockopt: { dialerProxy } };
    return outbound;
  }
  if (protocol === "vless" || protocol === "vmess") {
    const user = protocol === "vless" ? { id: proxy.uuid, encryption: "none", ...proxy.flow ? { flow: proxy.flow } : {} } : { id: proxy.uuid, alterId: proxy.alterId || 0, security: proxy.cipher || "auto" };
    outbound.settings.vnext = [{ address: proxy.server, port: proxy.port, users: [user] }];
  } else if (protocol === "trojan") {
    outbound.settings.servers = [{ address: proxy.server, port: proxy.port, password: proxy.password }];
  } else if (protocol === "shadowsocks") {
    outbound.settings.servers = [{ address: proxy.server, port: proxy.port, method: proxy.cipher, password: proxy.password }];
  } else {
    outbound.settings.servers = [{ address: proxy.server, port: proxy.port, ...proxy.username ? { users: [{ user: proxy.username, pass: proxy.password || "" }] } : {} }];
  }
  const stream = { network: proxy.network === "ws" ? "ws" : proxy.network === "grpc" ? "grpc" : "tcp", security: proxy.reality ? "reality" : proxy.tls || proxy.sni ? "tls" : "none" };
  if (stream.security === "reality")
    stream.realitySettings = {
      serverName: proxy.servername || proxy.sni || "",
      publicKey: proxy.reality["public-key"],
      shortId: proxy.reality["short-id"],
      fingerprint: proxy["client-fingerprint"] || "chrome",
      show: false,
      ...proxy.alpn?.length ? { alpn: proxy.alpn } : {}
    };
  else if (stream.security === "tls") {
    // Xray takes a base64 ECHConfigList here, never the name+resolver form, and
    // it does not validate the field (garbage passes -test), so emit it only
    // when we really hold a config and leave it out otherwise.
    const echXray = parseEch(proxy.ech);
    stream.tlsSettings = {
      ...proxy.servername || proxy.sni ? { serverName: proxy.servername || proxy.sni } : {},
      ...proxy["client-fingerprint"] ? { fingerprint: proxy["client-fingerprint"] } : {},
      ...proxy.alpn?.length ? { alpn: proxy.alpn } : {},
      ...echXray?.config ? { echConfigList: echXray.config } : {}
    };
  }
  if (stream.network === "ws")
    stream.wsSettings = {
      path: proxy["ws-opts"]?.path || proxy.path || "/",
      headers: { Host: proxy["ws-opts"]?.headers?.Host || proxy.host || proxy.server }
    };
  if (stream.network === "grpc")
    stream.grpcSettings = { serviceName: proxy.grpcServiceName || "" };
  if (dialerProxy)
    stream.sockopt = { dialerProxy };
  outbound.streamSettings = stream;
  return outbound;
}
var GOOD_ENOUGH_MB_S = 50;
function qualityScore(health, stage3Speed = null) {
  if (!health || health.stale === true)
    return -1;
  const speed = Number(stage3Speed);
  if (!Number.isFinite(speed) || speed < 0.01)
    return -1;
  const fraud = Number(health.classification?.min_fraud_score);
  const risk = Number.isFinite(fraud) ? fraud : 50;
  const type = String(health?.classification?.connection_type ?? health?.connection_type ?? "").toLowerCase();
  const speedPart = Math.min(1, speed / GOOD_ENOUGH_MB_S);
  const residential = /resi/.test(type) ? 0.4 : 0;
  return 1.5 * speedPart + residential - 1 * (risk / 100);
}
function rankScore(health, stage3Speed = null) {
  return qualityScore(health, stage3Speed);
}
function scoreForProxy(proxy, healthById, endpointIndex, speedByEndpoint) {
  const health = resolveHealthFor({ proxy }, healthById, endpointIndex);
  if (!health)
    return -1;
  const key = endpointKeyOf(proxy.server, Number(proxy?.port ?? proxy?.server_port));
  const measured = speedByEndpoint ? Number(speedByEndpoint[key]) : NaN;
  return rankScore(health, Number.isFinite(measured) && measured > 0 ? measured : null);
}
var TOP_N = 10;
var COUNTRY_CAP = 60;
function topQualityVariants(countries, healthById, speedByEndpoint = null, entries = []) {
  const endpointIndex = buildEndpointIndex(healthById || {});
  const scored = [];
  const keepCandidate = (candidate) => {
    let index = 0;
    // Keep equal scores in their original feed order, matching stable sort.
    while (index < scored.length && scored[index].score >= candidate.score) index += 1;
    if (index >= TOP_N) return;
    scored.splice(index, 0, candidate);
    if (scored.length > TOP_N) scored.pop();
  };
  for (const country of countries) {
    if (!Array.isArray(country.variants) && Array.isArray(country.exits)) {
      for (let index = 0; index < country.exits.length; index += 1) {
        const proxy = country.exits[index];
        const measured = speedByEndpoint ? speedByEndpoint[endpointKeyOf(proxy?.server, Number(proxy?.port ?? proxy?.server_port))] : null;
        const score = qualityScore(resolveHealthFor({ proxy }, healthById, endpointIndex), measured);
        if (score >= 0)
          keepCandidate({ country, index, score });
      }
    } else {
      for (const item of country.variants || []) {
        const proxy = item.proxy || item;
        const measured = speedByEndpoint ? speedByEndpoint[endpointKeyOf(proxy?.server, Number(proxy?.port ?? proxy?.server_port))] : null;
        const score = qualityScore(resolveHealthFor(item, healthById, endpointIndex), measured);
        if (score >= 0)
          keepCandidate({ item, score });
      }
    }
  }
  const top = [];
  for (const candidate of scored) {
    if (candidate.item) {
      top.push(candidate.item);
      if (top.length === TOP_N) break;
      continue;
    }
    for (const item of mihomoVariantsForExit(candidate.country, candidate.index, entries)) {
      top.push(item);
      if (top.length === TOP_N) break;
    }
    if (top.length === TOP_N) break;
  }
  return top;
}
function xrayConfig(entries, countries, scope, healthById, speedByEndpoint = null) {
  const outbounds = [];
  entries.forEach((entry) => outbounds.push(xrayOutbound(entry.proxy, entry.tag)));
  const variants = countries.flatMap((country) => country.variants);
  variants.forEach((item) => outbounds.push(xrayOutbound(item.proxy, item.name, item.dialerProxy)));
  outbounds.push({ tag: "direct", protocol: "freedom" });
  const tags = [...variants.map((item) => item.name), ...entries.map((entry) => entry.tag)];
  const fallbackTag = variants[0]?.name || entries[0]?.tag || "direct";
  const poolTag = `pool-${scope}`;
  const autoBest = topQualityVariants(countries, healthById || {}, speedByEndpoint);
  const defaultSelector = autoBest.length > 1 ? autoBest.map((item) => item.name) : tags;
  const config = {
    log: { loglevel: "warning" },
    remarks: safeName(`${scope} proxy subscription`, `${scope} subscription`),
    inbounds: [{ tag: "local-socks", listen: "127.0.0.1", port: 10808, protocol: "socks", settings: { udp: true } }],
    outbounds,
    routing: {
      rules: [{ type: "field", inboundTag: ["local-socks"], balancerTag: poolTag }],
      balancers: [{ tag: poolTag, selector: defaultSelector, fallbackTag, strategy: { type: "leastPing" } }]
    },
    observatory: { subjectSelector: defaultSelector, probeUrl: "https://www.gstatic.com/generate_204", probeInterval: "5m", enableConcurrency: true }
  };
  return JSON.stringify(config, null, 2) + "\n";
}
function singboxOutbound(proxy, tag, detour = void 0) {
  const out = { type: proxy.type === "socks5" ? "socks" : proxy.type, tag, server: proxy.server, server_port: proxy.port };
  if (proxy.type === "hysteria2") {
    out.password = proxy.password;
    out.tls = { enabled: true, ...proxy.sni ? { server_name: proxy.sni } : {}, ...proxy["skip-cert-verify"] ? { insecure: true } : {} };
    if (proxy.obfs)
      out.obfs = { type: proxy.obfs, ...proxy["obfs-password"] ? { password: proxy["obfs-password"] } : {} };
  } else if (proxy.type === "tuic") {
    if (proxy.uuid) out.uuid = proxy.uuid;
    if (proxy.password) out.password = proxy.password;
    if (proxy.token) out.token = proxy.token;
    if (proxy["congestion-controller"]) out.congestion_control = proxy["congestion-controller"];
    if (proxy["udp-relay-mode"]) out.udp_relay_mode = proxy["udp-relay-mode"];
    out.tls = { enabled: true, ...proxy.sni ? { server_name: proxy.sni } : {}, ...proxy["skip-cert-verify"] ? { insecure: true } : {} };
  } else if (proxy.type === "anytls") {
    out.password = proxy.password;
    out.tls = { enabled: true, ...proxy.sni ? { server_name: proxy.sni } : {}, ...proxy["skip-cert-verify"] ? { insecure: true } : {} };
  } else if (proxy.type === "vless") {
    out.uuid = proxy.uuid;
    if (proxy.flow)
      out.flow = proxy.flow;
    if (proxy.tls) {
      out.tls = { enabled: true };
      if (proxy.servername)
        out.tls.server_name = proxy.servername;
      if (proxy.alpn?.length)
        out.tls.alpn = proxy.alpn;
      if (proxy["client-fingerprint"])
        out.tls.utls = { enabled: true, fingerprint: proxy["client-fingerprint"] };
      if (proxy.reality)
        out.tls.reality = { enabled: true, public_key: proxy.reality["public-key"], short_id: proxy.reality["short-id"] };
      const ech = parseEch(proxy.ech);
      if (ech) {
        out.tls.ech = { enabled: true };
        if (ech.queryServerName) out.tls.ech.query_server_name = ech.queryServerName;
        if (ech.config) {
          const body = ech.config.match(/.{1,64}/g) || [];
          out.tls.ech.config = ["-----BEGIN ECH CONFIGS-----", ...body, "-----END ECH CONFIGS-----"];
        }
      }
    }
    if (proxy.network === "ws")
      out.transport = { type: "ws", path: proxy["ws-opts"]?.path || "/", headers: { Host: proxy["ws-opts"]?.headers?.Host || proxy.server } };
    else if (proxy.network === "grpc")
      out.transport = { type: "grpc", service_name: proxy["grpc-opts"]?.["grpc-service-name"] || "" };
  } else if (proxy.type === "vmess") {
    out.uuid = proxy.uuid;
    out.security = proxy.cipher || "auto";
    out.alter_id = proxy.alterId || 0;
    if (proxy.tls)
      out.tls = { enabled: true, ...proxy.servername ? { server_name: proxy.servername } : {} };
    if (proxy.network === "ws")
      out.transport = { type: "ws", path: proxy.path || "/", headers: proxy.host ? { Host: proxy.host } : void 0 };
  } else if (proxy.type === "trojan") {
    out.password = proxy.password;
    if (proxy.sni)
      out.tls = { enabled: true, server_name: proxy.sni };
  } else if (proxy.type === "ss") {
    out.type = "shadowsocks";
    out.method = proxy.cipher;
    out.password = proxy.password;
  } else if (proxy.username) {
    out.username = proxy.username;
    if (proxy.password)
      out.password = proxy.password;
  }
  if (detour)
    out.detour = detour;
  return out;
}
function singbox(entries, countries, healthById, speedByEndpoint = null) {
  const outbounds = [];
  const autoBest = topQualityVariants(countries, healthById || {}, speedByEndpoint);
  entries.forEach((entry) => outbounds.push(singboxOutbound(entry.proxy, entry.tag)));
  const groupNames = [];
  if (entries.length) {
    outbounds.push({ type: "selector", tag: "EntryPoints", outbounds: entries.map((entry) => entry.tag), default: entries[0].tag });
    groupNames.push("EntryPoints");
  }
  for (const country of countries) {
    const tag = `country-${country.code}`;
    for (const item of country.variants)
      outbounds.push(singboxOutbound(item.proxy, item.tag || item.name, item.dialerProxy));
    const names = country.variants.map((item) => item.tag || item.name);
    outbounds.push({ type: "selector", tag, outbounds: names, default: names[0] });
    groupNames.push(tag);
  }
  if (countries.length === 1) {
    const only = countries[0];
    outbounds.push({
      type: "selector",
      tag: countryName(only.code),
      outbounds: only.variants.map((item) => item.tag || item.name),
      ...only.variants[0] ? { default: only.variants[0].tag || only.variants[0].name } : {}
    });
    outbounds.push({ type: "direct", tag: "direct" });
  } else {
    const firstExitNode = countries.length ? countries[0].variants[0]?.name : void 0;
    outbounds.push({
      type: "selector",
      tag: "Proxy",
      outbounds: countries.flatMap((country) => country.variants.map((item) => item.name)),
      ...firstExitNode ? { default: firstExitNode } : {}
    });
    outbounds.push({ type: "direct", tag: "direct" });
  }
  const autoTag = "Best";
  if (autoBest.length > 1) {
    outbounds.push({
      type: "urltest",
      tag: autoTag,
      outbounds: autoBest.map((item) => item.name),
      url: "http://www.gstatic.com/generate_204",
      interval: "5m",
      tolerance: 50,
      idle_timeout: "30m",
      interrupt_exist_connections: false
    });
  }
  const routeTarget = autoBest.length > 1 ? autoTag : countries.length === 1 ? countryName(countries[0].code) : "Proxy";
  for (const outbound of outbounds) {
    if (["selector", "direct", "block", "dns", "urltest"].includes(outbound.type))
      continue;
    if (!outbound.domain_resolver) {
      outbound.domain_resolver = { server: "dns-cloudflare", detour: routeTarget };
    }
  }
  const dns = {
    servers: [
      { tag: "dns-cloudflare", type: "https", server: "1.1.1.1", server_port: 443, detour: routeTarget },
      { tag: "dns-google", type: "https", server: "8.8.8.8", server_port: 443, detour: routeTarget }
    ],
    final: "dns-cloudflare",
    strategy: "prefer_ipv4"
  };
  const route = {
    // sing-box 1.12 removed the implicit resolver fallback and 1.14 removes
    // the escape hatch; "sing-box check" fails without this, because the DoH
    // servers and the detoured dials all need a way to resolve names.
    default_domain_resolver: { server: "dns-cloudflare", detour: routeTarget },
    rules: [
      // DNS queries arriving on the tunnel are answered internally, never
      // forwarded to the system resolver.
      { protocol: "dns", action: "hijack-dns" },
      // STUN is how WebRTC discovers the local address. Route it over the
      // proxy so the peer sees the exit IP, not the client.
      { protocol: "stun", action: "route", outbound: routeTarget },
      { ip_cidr: ["224.0.0.0/32", "ff00::/8"], action: "hijack-dns" }
    ],
    // final, not per-group: anything not matched above still goes through the
    // proxy, so there is no path that leaves via the real interface.
    final: routeTarget,
    auto_detect_interface: true
  };
  return JSON.stringify({
    log: { level: "warn" },
    outbounds,
    inbounds: [{ type: "tun", tag: "tun-in", address: ["172.19.0.1/30", "fdfe:dcba:9876::1/126"], mtu: 1500, auto_route: true, strict_route: true }],
    dns,
    route
  }, null, 2) + "\n";
}
var index_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method !== "GET")
      return fail("method_not_allowed", 405);
    if (url.pathname !== "/sub")
      return fail("not_found", 404);
    const requestedCountry = (url.searchParams.get("country") || "").toUpperCase();
    if (requestedCountry && requestedCountry !== "ALL" && !COUNTRY_RE.test(requestedCountry))
      return fail("country_must_be_two_letter_iso_code_or_ALL");
    const country = requestedCountry === "ALL" ? "" : requestedCountry;
    const rawProtocols = url.searchParams.get("protocol");
    let protocolFilter = null;
    if (rawProtocols !== null) {
      const requestedProtocols = rawProtocols.split(",").map((item) => item.trim().toLowerCase()).filter(Boolean);
      if (!requestedProtocols.length || requestedProtocols.some((item) => !FILTERABLE_PROTOCOLS.has(canonicalProtocol(item))))
        return fail("protocol_must_be_a_comma_separated_list_of_supported_protocols");
      protocolFilter = new Set(requestedProtocols.map(canonicalProtocol));
    }
    const rawExcludedCountries = url.searchParams.get("exclude");
    let excludedCountries = new Set();
    if (rawExcludedCountries !== null) {
      const excluded = rawExcludedCountries.split(",").map((item) => item.trim().toUpperCase()).filter(Boolean);
      if (excluded.some((item) => !COUNTRY_RE.test(item)))
        return fail("exclude_must_be_a_comma_separated_list_of_two_letter_country_codes");
      excludedCountries = new Set(excluded);
    }
    let entries;
    try {
      entries = decodeEntries(url);
    } catch (e) {
      return fail(e.message);
    }

    const format = guessFormat(request, url);
    if (format !== "mihomo" && format !== "sing-box" && format !== "xray" && format !== "links" && format !== "unknown")
      return fail("format_must_be_mihomo_sing_box_xray_or_links");
    if (entries.length && format === "unknown")
      return fail("client_format_not_detected_use_format_override", 406);
    if (entries.some((entry) => entry.proxy.type === "wireguard") && format !== "mihomo" && format !== "xray" && format !== "links")
      return fail("wireguard_entry_requires_mihomo_xray_or_links_format", 406);
    if (entries.some((entry) => entry.proxy.type === "masque") && format !== "mihomo")
      return fail("masque_entry_requires_mihomo_format", 406);
    if (entries.some((entry) => ["hysteria2", "tuic", "anytls"].includes(entry.proxy.type)) && format === "xray")
      return fail("quic_or_anytls_entry_requires_mihomo_or_sing_box_format", 406);
    const origin = (env.FEED_ORIGIN || "https://raw.githubusercontent.com/TheCalmBoy/proxy-collector/gh-pages").replace(/\/$/, "");
    const feedPath = country ? `countries/${country}.txt` : "all.txt";
    const feed = await fetch(`${origin}/${feedPath}`, {
      headers: { accept: "text/plain" },
      signal: AbortSignal.timeout(1e4),
      // The feed changes on the pipeline's schedule, not per request: without
      // this every visitor re-fetched it from the upstream on every hit.
      cf: { cacheTtl: 60, cacheEverything: true }
    });
    if (feed.status === 404)
      return fail("country_feed_not_found", 404);
    if (!feed.ok)
      return fail("country_feed_unavailable", 502);
    const feedText = await feed.text();
    const feedVersionToken = feed.headers.get("etag") || feed.headers.get("last-modified") || await digestToken(feedText);
    const rows = feedText.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
    let parsed = rows.map((uri, i) => {
      const scheme = uri.slice(0, uri.indexOf(":")).toLowerCase();
      if (protocolFilter && !protocolFilter.has(canonicalProtocol(scheme)))
        return null;
      const proxy = parseProxySafely(uri, i + 1);
      return proxy ? { uri, proxy } : null;
    }).filter(Boolean);
    if (format === "xray")
      parsed = parsed.filter((item) => !["hysteria2", "tuic", "anytls"].includes(item.proxy.type));
    if (!parsed.length)
      return fail(protocolFilter ? "no_proxies_match_protocol_filter" : "feed_has_no_supported_proxies", 404);
    // ?secure=1 keeps only exits whose hop is TLS: something is better than a
    // bare protocol when the ISP is the threat model.
    if (url.searchParams.get("secure") === "1") {
      parsed = parsed.filter((item) => isTlsHop(item.proxy));
      if (!parsed.length)
        return fail("no_tls_exits_in_feed", 503);
    }

    // ?ech=embed pins Cloudflare's published ECH key into the config, so the
    // client needs no ECH lookup of its own. It has to cover the exits as well
    // as the entrypoints: an exit can carry its own ech= and would otherwise
    // still need a lookup, which is the very thing this option exists to avoid.
    // Off by default, because mihomo 1.19.x has no ECH rejection fallback, so a
    // key that rotates takes the config with it.
    let echEmbedded = 0;
    let echVersionToken = "none";
    if ((url.searchParams.get("ech") || "").toLowerCase() === "embed") {
      const pending = new Map();
      for (const proxy of [...entries.map((entry) => entry.proxy), ...parsed.map((item) => item.proxy)]) {
        const parsedEch = parseEch(proxy.ech);
        if (!parsedEch?.queryServerName)
          continue;
        if (!pending.has(parsedEch.queryServerName))
          pending.set(parsedEch.queryServerName, []);
        pending.get(parsedEch.queryServerName).push(proxy);
      }
      const resolved = new Map(await Promise.all(
        [...pending.keys()].map(async (name) => [name, await fetchEchConfig(name)])
      ));
      echVersionToken = await digestToken([...resolved.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([name, config]) => `${name}:${config || ""}`).join("\n"));
      for (const [name, proxies] of pending) {
        const config = resolved.get(name);
        if (!config)
          continue;
        for (const proxy of proxies) {
          proxy.ech = config;
          echEmbedded += 1;
        }
      }
    }
    const echHeaders = url.searchParams.has("ech")
      ? { "x-ech-mode": echEmbedded ? "embedded:" + echEmbedded : "query" }
      : {};

    let healthById = {};
    let healthIndexState = "missing";
    let healthJoin = null;
    let healthAgeMs = null;
    const healthVersion = Math.floor(Date.now() / (5 * 6e4));
    let healthVersionToken = `missing:${healthVersion}`;
    try {
      const healthResponse = await fetch(`${origin}/egress-health.json?v=${healthVersion}`, {
        headers: { accept: "application/json" },
        signal: AbortSignal.timeout(5e3),
        cf: { cacheTtl: 300, cacheEverything: true }
      });
      if (healthResponse.status !== 404)
        healthIndexState = healthResponse.ok ? "stale" : "unavailable";
      if (healthResponse.ok) {
        const healthText = await healthResponse.text();
        healthVersionToken = healthResponse.headers.get("etag") || healthResponse.headers.get("last-modified") || await digestToken(healthText);
        const healthDocument = JSON.parse(healthText);
        const generatedAt = Date.parse(healthDocument?.generated_at || "");
        const ageMs = Date.now() - generatedAt;
        if (Number.isFinite(generatedAt) && ageMs >= -5 * 6e4 && ageMs <= HEALTH_HARD_MAX_AGE_MS && healthDocument.configs && typeof healthDocument.configs === "object") {
          healthById = healthDocument.configs;
          healthAgeMs = ageMs;
          healthIndexState = ageMs <= STALE_HEALTH_MAX_AGE_MS ? "fresh" : "aged";
        } else {
          healthIndexState = "unusable";
        }
      }
    } catch {
      healthIndexState = "unavailable";
      healthVersionToken = `unavailable:${healthVersion}`;
    }
    let speedByEndpoint = {};
    const enrichedVersion = Math.floor(Date.now() / (5 * 6e4));
    let enrichedVersionToken = `missing:${enrichedVersion}`;
    try {
      const enrichedResponse = await fetch(`${origin}/enriched-configs.json?v=${enrichedVersion}`, {
        headers: { accept: "application/json" },
        signal: AbortSignal.timeout(5e3),
        cf: { cacheTtl: 300, cacheEverything: true }
      });
      if (enrichedResponse.ok) {
        const enrichedText = await enrichedResponse.text();
        enrichedVersionToken = enrichedResponse.headers.get("etag") || enrichedResponse.headers.get("last-modified") || await digestToken(enrichedText);
        speedByEndpoint = buildSpeedIndex(JSON.parse(enrichedText));
      }
    } catch {
      enrichedVersionToken = `unavailable:${enrichedVersion}`;
    }
    const healthEndpointIndex = buildEndpointIndex(healthById);
    const healthHeaders = () => ({
      "x-health-index": healthIndexState,
      ...healthJoin ? { "x-health-join": `${healthJoin.verified}/${healthJoin.feed}` } : {},
      ...Number.isFinite(healthAgeMs) ? { "x-health-age": String(Math.max(0, Math.round(healthAgeMs / 1e3))) } : {}
    });
    if (healthIndexState === "fresh") {
      const before = parsed.length;
      parsed = parsed.filter((item) => {
        return Boolean(resolveHealthFor(item, healthById, healthEndpointIndex));
      });
      healthJoin = { feed: before, verified: parsed.length };
      if (!parsed.length)
        return fail("no_recently_verified_proxies", 503, healthHeaders());
    }
    const grouped = /* @__PURE__ */ new Map();
    const RAINBOW_KEY = "ZZ-RAINBOW";
    for (const item of parsed) {
      const health = resolveHealthFor(item.proxy, healthById, healthEndpointIndex);
      const classification = health?.classification && typeof health.classification === "object" ? health.classification : health || {};
      const remarkCountry = /^([A-Z]{2})-/.exec(item.proxy.name || "")?.[1];
      const observedCountries = [health?.primary_country, classification.country, remarkCountry, ...(Array.isArray(classification.countries) ? classification.countries : [])]
        .filter((value) => typeof value === "string")
        .map((value) => value.toUpperCase());
      if (observedCountries.some((code) => excludedCountries.has(code)))
        continue;
      const crossesBorders = !!health && String(health.classification?.same_country) === "false" && Array.isArray(health.classification?.countries) && health.classification.countries.length > 1;
      if (crossesBorders) {
        if (!grouped.has(RAINBOW_KEY))
          grouped.set(RAINBOW_KEY, []);
        grouped.get(RAINBOW_KEY).push(item);
        continue;
      }
      const fromHealth = health?.primary_country || health?.classification?.country;
      const code = country || (typeof fromHealth === "string" && COUNTRY_RE.test(fromHealth.toUpperCase()) ? fromHealth.toUpperCase() : null) || (/^([A-Z]{2})-/.exec(item.proxy.name || "")?.[1] || "ZZ");
      if (!grouped.has(code))
        grouped.set(code, []);
      grouped.get(code).push(item);
    }
    const endpointIndex = healthEndpointIndex;
    const countries = [...grouped.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([code, items]) => {
      const ranked = items.map((item) => ({
        item,
        score: scoreForProxy(item.proxy, healthById, endpointIndex, speedByEndpoint)
      })).sort((left, right) => right.score - left.score);
      const capped = code === RAINBOW_KEY ? ranked : ranked.slice(0, COUNTRY_CAP);
      const exits = capped.map((entry) => entry.item.proxy);
      const baseNames = exits.map((proxy, index) => friendlyExitName(code, index, proxy, healthById, null, speedByEndpoint, endpointIndex));
      const result = { code, items: capped.map((entry) => entry.item), exits, baseNames };
      if (format !== "mihomo") {
        const variants = [];
        for (let index = 0; index < exits.length; index += 1) {
          if (entries.length) {
            for (let slot = 0; slot < entries.length; slot += 1) {
              const entry = entries[slot];
              const prefix = (entry.tag || "").split(" ")[0] || `ET${slot + 1}`;
              variants.push({
                proxy: exits[index],
                name: `${prefix} - ${baseNames[index]}`,
                tag: `${code}-${String(index + 1).padStart(2, "0")}e${slot + 1}`,
                dialerProxy: entry.tag
              });
            }
          } else {
            variants.push({ proxy: exits[index], name: baseNames[index] });
          }
        }
        result.variants = variants;
      }
      return result;
    });
    if (!countries.length)
      return excludedCountries.size
        ? fail("no_proxies_match_filters", 404, healthHeaders())
        : fail("no_recently_verified_proxies", 503, healthHeaders());
    const joinHeaders = { ...healthHeaders(), ...echHeaders };
    if (format === "links" || !entries.length && (format === "xray" || format === "unknown")) {
      const links = countries.flatMap((group) => group.items.map((item, index) => withUriName(item.uri, group.baseNames[index])));
      if (entries.length)
        links.unshift(...entries.map((entry) => withUriName(entry.uri, entry.tag)));
      return replyWithEtag(request, b64(links.join("\n")), "text/plain; charset=utf-8", joinHeaders);
    }
    const dnsPref = url.searchParams.get("dns") !== "0";
    if (format === "mihomo") {
      const seed = JSON.stringify({
        renderer: "mihomo-stream-v1",
        url: request.url,
        format,
        feedVersionToken,
        healthVersionToken,
        healthIndexState,
        enrichedVersionToken,
        echVersionToken,
        healthMinute: Math.floor(Date.now() / 6e4)
      });
      return replyWithStreamEtag(request, streamMihomo(entries, countries, healthById, speedByEndpoint, { dns: dnsPref }), "text/yaml; charset=utf-8", joinHeaders, seed);
    }
    const render = format === "sing-box" ? singbox : (e, c, h, s) => xrayConfig(e, c, country || "ALL", h, s);
    return replyWithEtag(request, render(entries, countries, healthById, speedByEndpoint), format === "mihomo" ? "text/yaml; charset=utf-8" : "application/json; charset=utf-8", joinHeaders);
  }
};
export {
  GOOD_ENOUGH_MB_S,
  buildEndpointIndex,
  buildSpeedIndex,
  reply,
  index_default as default,
  endpointKeyOf,
  friendlyExitName,
  mihomo,
  parseEch,
  qualityScore,
  rankScore,
  resolveHealth,
  resolveHealthFor,
  scoreForProxy,
  topQualityVariants
};
