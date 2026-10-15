var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// index.js
var __defProp2 = Object.defineProperty;
var __name2 = /* @__PURE__ */ __name((target, value) => __defProp2(target, "name", { value, configurable: true }), "__name");
var __defProp22 = Object.defineProperty;
var __name22 = /* @__PURE__ */ __name2((target, value) => __defProp22(target, "name", { value, configurable: true }), "__name");
var MAX_ENTRY_BYTES = 9e3;
var MAX_ENTRIES = 90;
var MAX_BODY_BYTES = 9e5;
var STALE_HEALTH_MAX_AGE_MS = 24 * 60 * 6e4;
// Above the soft threshold we still serve the index (aged) instead of hard-failing
// the whole subscription; above this we ignore it entirely and serve unfiltered.
var HEALTH_HARD_MAX_AGE_MS = 7 * 24 * 60 * 6e4;
var COUNTRY_RE = /^[A-Z]{2}$/;
var ALLOWED_SCHEMES = /* @__PURE__ */ new Set(["vless", "vmess", "trojan", "ss", "socks", "socks5", "http", "wireguard"]);
function reply(body, status = 200, type = "application/json; charset=utf-8", extra = null) {
  const headers = { "content-type": type, "cache-control": "no-store", "x-content-type-options": "nosniff", ...extra || {} };
  if (typeof body === "string" && body.length > MAX_BODY_BYTES) {
    body = body.slice(0, MAX_BODY_BYTES);
    headers["x-body-truncated"] = "true";
  }
  return new Response(body, { status, headers });
}
__name(reply, "reply");
__name2(reply, "reply");
__name22(reply, "reply");
function fail(error, status = 400, extra = null) {
  return reply(JSON.stringify({ error }), status, "application/json; charset=utf-8", extra);
}
__name(fail, "fail");
__name2(fail, "fail");
__name22(fail, "fail");
function decodeEntries(url) {
  const values = url.searchParams.getAll("entry64");
  const unique = /* @__PURE__ */ new Set();
  const entries = [];
  for (const encoded of values) {
    if (!encoded || encoded.length > 12e3)
      throw new Error("invalid_or_too_large_entry64");
    let value;
    try {
      const normalized = encoded.replace(/-/g, "+").replace(/_/g, "/");
      value = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
    } catch {
      throw new Error("invalid_entry64");
    }
    const bytes = Uint8Array.from(value, (c) => c.charCodeAt(0));
    const uri = new TextDecoder("utf-8", { fatal: true }).decode(bytes).trim();
    if (new TextEncoder().encode(uri).length > MAX_ENTRY_BYTES)
      throw new Error("entry_too_large");
    const scheme = uri.slice(0, uri.indexOf(":")).toLowerCase();
    if (!ALLOWED_SCHEMES.has(scheme))
      throw new Error("unsupported_entry_scheme");
    if (unique.has(uri))
      continue;
    unique.add(uri);
    entries.push({ uri, proxy: parseEntry(uri) });
    if (entries.length >= MAX_ENTRIES)
      break;
  }
  return entries.map((item, index) => ({ ...item, tag: entryName(item.proxy, index + 1) }));
}
__name(decodeEntries, "decodeEntries");
__name2(decodeEntries, "decodeEntries");
__name22(decodeEntries, "decodeEntries");
function safeName(value, fallback) {
  const name = (value || fallback).replace(/[\u0000-\u001f\u007f-\u009f]/g, " ").replace(/["\\]/g, "").trim();
  return name.slice(0, 96) || fallback;
}
__name(safeName, "safeName");
__name2(safeName, "safeName");
__name22(safeName, "safeName");
function withUriName(uri, name) {
  const base = uri.split("#", 1)[0];
  return `${base}#${encodeURIComponent(name)}`;
}
__name(withUriName, "withUriName");
__name2(withUriName, "withUriName");
__name22(withUriName, "withUriName");
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
__name(buildSpeedIndex, "buildSpeedIndex");
__name2(buildSpeedIndex, "buildSpeedIndex");
__name22(buildSpeedIndex, "buildSpeedIndex");
function fnv1a(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = h * 16777619 >>> 0;
  }
  return h >>> 0;
}
__name(fnv1a, "fnv1a");
__name2(fnv1a, "fnv1a");
__name22(fnv1a, "fnv1a");
function configDisplayName(proxy) {
  const id = feedEntryId(proxy);
  if (id)
    return id.slice(-8).toUpperCase();
  return fnv1a(String(proxy.server || "") + ":" + (proxy.port ?? proxy.server_port ?? "")).toString(16).padStart(8, "0").toUpperCase();
}
__name(configDisplayName, "configDisplayName");
__name2(configDisplayName, "configDisplayName");
__name22(configDisplayName, "configDisplayName");
function friendlyExitName(country, index, proxy, healthById, entrypointNumber = null, speedByEndpoint = null) {
  const serial = String(index + 1).padStart(2, "0");
  const remark = /^([A-Z]{2})-(RES|DC|UNKNOWN)-(.+)-([A-F0-9]{6,12})$/.exec(proxy.name || "");
  const health = resolveHealthFor({ proxy }, healthById, buildEndpointIndex(healthById)) || (remark ? healthById[remark[4]] : null);
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
    const geminiTag = gemini?.flagged === true ? "Gem \u2717" : gemini?.clean === true ? "Gem \u2713" : "";
    const kindRaw = classification.connection_type ?? health.connection_type;
    const kindValue = typeof kindRaw === "string" ? kindRaw.replace(/[^a-z0-9 -]/gi, "").trim() : "";
    const kind = /resi/i.test(kindValue) ? "Resi" : /data.?center|hosting/i.test(kindValue) ? "DC" : "";
    const tags = [`${risk}${kind ? " " + kind : ""}`];
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
__name(friendlyExitName, "friendlyExitName");
__name2(friendlyExitName, "friendlyExitName");
__name22(friendlyExitName, "friendlyExitName");
function feedEntryId(proxy) {
  const name = proxy.name || "";
  const tail = name.split("|").pop().trim();
  if (/^[A-F0-9]{6,12}$/i.test(tail))
    return tail.toUpperCase();
  return /-([A-F0-9]{8,12})$/.exec(name)?.[1] || null;
}
__name(feedEntryId, "feedEntryId");
__name2(feedEntryId, "feedEntryId");
__name22(feedEntryId, "feedEntryId");
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
__name(resolveHealth, "resolveHealth");
__name2(resolveHealth, "resolveHealth");
__name22(resolveHealth, "resolveHealth");
function endpointKeyOf(server, port) {
  return `${String(server).trim().toLowerCase()}:${Number(port)}`;
}
__name(endpointKeyOf, "endpointKeyOf");
__name2(endpointKeyOf, "endpointKeyOf");
__name22(endpointKeyOf, "endpointKeyOf");
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
__name(buildEndpointIndex, "buildEndpointIndex");
__name2(buildEndpointIndex, "buildEndpointIndex");
__name22(buildEndpointIndex, "buildEndpointIndex");
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
__name(resolveHealthFor, "resolveHealthFor");
__name2(resolveHealthFor, "resolveHealthFor");
__name22(resolveHealthFor, "resolveHealthFor");
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
__name(healthByEndpoint, "healthByEndpoint");
__name2(healthByEndpoint, "healthByEndpoint");
__name22(healthByEndpoint, "healthByEndpoint");
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
    const port2 = Number(data.port);
    if (!data.add || !port2)
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
      alterId: Number(data.aid || 0),
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
  if (!["vless", "trojan", "ss", "socks", "socks5", "http", "wireguard"].includes(type))
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
    const first = /* @__PURE__ */ __name22((...keys) => keys.map((key) => u.searchParams.get(key)).find((value) => value !== null && value !== "") || "", "first");
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
  if (type === "vless") {
    const network = u.searchParams.get("type") || "tcp";
    const tlsMode = u.searchParams.get("security") || "none";
    const proxy = {
      type,
      name,
      server,
      port,
      uuid: decodeURIComponent(u.username),
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
  if (type === "trojan")
    return {
      type,
      name,
      server,
      port,
      password: decodeURIComponent(u.username),
      sni: u.searchParams.get("sni") || void 0,
      udp: true
    };
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
    return { type, name, server, port, cipher: credentials.slice(0, colon), password: credentials.slice(colon + 1), udp: true };
  }
  const user = decodeURIComponent(u.username || ""), password = decodeURIComponent(u.password || "");
  return { type: type === "socks5" ? "socks5" : type, name, server, port, ...user ? { username: user } : {}, ...password ? { password } : {}, udp: true };
}
__name(parseProxy, "parseProxy");
__name2(parseProxy, "parseProxy");
__name22(parseProxy, "parseProxy");
function parseEntry(uri) {
  const proxy = parseProxy(uri, 0);
  if (!proxy)
    throw new Error("entry_parse_failed");
  proxy.name = safeName(proxy.name, "entrypoint");
  return proxy;
}
__name(parseEntry, "parseEntry");
__name2(parseEntry, "parseEntry");
__name22(parseEntry, "parseEntry");
function entryName(entry, index) {
  const protocol = { wireguard: "WARP", vless: "VLESS", vmess: "VMess", trojan: "Trojan", ss: "Shadowsocks", socks: "SOCKS", socks5: "SOCKS", http: "HTTP" }[entry.type] || "Proxy";
  return safeName(`ET${index} - ${entry.name || protocol}`, `ET${index}`);
}
__name(entryName, "entryName");
__name2(entryName, "entryName");
__name22(entryName, "entryName");
function countryName(code) {
  if (code === "ZZ")
    return "Unknown";
  if (code === "ZZ-RAINBOW")
    return "Rainbow";
  return /^[A-Z]{2}$/i.test(code || "") ? code.toUpperCase() : code;
}
__name(countryName, "countryName");
__name2(countryName, "countryName");
__name22(countryName, "countryName");
var RAINBOW_FLAG = "\u{1F308}";
function countryFlag(code, dynamic = false) {
  if (dynamic)
    return RAINBOW_FLAG;
  if (!/^[A-Z]{2}$/i.test(code || "") || code.toUpperCase() === "ZZ")
    return "";
  return String.fromCodePoint(...[...code.toUpperCase()].map((c) => 127397 + c.charCodeAt(0)));
}
__name(countryFlag, "countryFlag");
__name2(countryFlag, "countryFlag");
__name22(countryFlag, "countryFlag");
function yamlScalar(value) {
  return JSON.stringify(value).replace(/[\u007f-\u009f]/g, (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`);
}
__name(yamlScalar, "yamlScalar");
__name2(yamlScalar, "yamlScalar");
__name22(yamlScalar, "yamlScalar");
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
__name(scalarFields, "scalarFields");
__name2(scalarFields, "scalarFields");
__name22(scalarFields, "scalarFields");
var AMNEZIA_JMIN = 50;
var AMNEZIA_JMAX = 100;
var WARP_SERVER_KEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";
function amneziaWgOption(proxy) {
  if (!proxy.wnoise && proxy.publicKey !== WARP_SERVER_KEY)
    return [];
  const num = /* @__PURE__ */ __name22((value, fallback) => {
    const parsed = Number.parseInt(String(value ?? "").trim(), 10);
    return Number.isFinite(parsed) ? parsed : fallback;
  }, "num");
  return [
    "    amnezia-wg-option:",
    `      jc: ${num(proxy.wnoisecount, 5)}`,
    `      jmin: ${AMNEZIA_JMIN}`,
    `      jmax: ${AMNEZIA_JMAX}`
  ];
}
__name(amneziaWgOption, "amneziaWgOption");
__name2(amneziaWgOption, "amneziaWgOption");
__name22(amneziaWgOption, "amneziaWgOption");
function mihomo(entries, countries, healthById, speedByEndpoint = null) {
  const autoBest = topQualityVariants(countries, healthById || {}, speedByEndpoint);
  const lines = ["# Generated proxy subscription", "proxies:"];
  const appendProxy = /* @__PURE__ */ __name22((proxy, name, dialerProxy = void 0) => {
    if (proxy.type === "wireguard") {
      const localIp = proxy.address?.find((value) => value.includes(".")) || proxy.address?.[0] || "";
      lines.push(
        `  - name: ${yamlScalar(name)}`,
        "    type: wireguard",
        `    ip: ${yamlScalar(localIp.split("/")[0])}`,
        `    private-key: ${yamlScalar(proxy.secretKey)}`,
        "    peers:",
        `      - server: ${yamlScalar(proxy.server)}`,
        `        port: ${proxy.port}`,
        `        public-key: ${yamlScalar(proxy.publicKey)}`,
        '        allowed-ips: ["0.0.0.0/0", "::/0"]',
        ...proxy.reserved?.length ? [`        reserved: [${proxy.reserved.join(", ")}]`] : [],
        "    udp: true",
        ...proxy.mtu ? [`    mtu: ${proxy.mtu}`] : [],
        ...proxy.keepAlive ? [`    persistent-keepalive: ${proxy.keepAlive}`] : [],
        ...amneziaWgOption(proxy),
        ...dialerProxy ? [`    dialer-proxy: ${yamlScalar(dialerProxy)}`] : []
      );
    } else {
      const { ech, ...scalarProxy } = { ...proxy, name, ...dialerProxy ? { "dialer-proxy": dialerProxy } : {} };
      lines.push(`  -\n${scalarFields(scalarProxy)}`);
      if (proxy.reality)
        lines.push(`    reality-opts:
      public-key: ${yamlScalar(proxy.reality["public-key"])}
      short-id: ${yamlScalar(proxy.reality["short-id"])}`);
      if (proxy.alpn?.length)
        lines.push(`    alpn:
${proxy.alpn.map((item) => `      - ${yamlScalar(item)}`).join("\n")}`);
      if (proxy["ws-opts"])
        lines.push(`    ws-opts:
      path: ${yamlScalar(proxy["ws-opts"].path)}
      headers:
        Host: ${yamlScalar(proxy["ws-opts"].headers.Host)}`);
      const echOpts = proxy.tls ? parseEch(ech) : null;
      if (echOpts) {
        lines.push("    ech-opts:", "      enable: true");
        if (echOpts.config)
          lines.push(`      config: ${yamlScalar(echOpts.config)}`);
        if (echOpts.queryServerName)
          lines.push(`      query-server-name: ${yamlScalar(echOpts.queryServerName)}`);
      }
    }
  }, "appendProxy");
  for (const entry of entries)
    appendProxy(entry.proxy, entry.tag);
  for (const country of countries) {
    for (const item of country.variants)
      appendProxy(item.proxy, item.name, item.dialerProxy);
  }
  lines.push("proxy-groups:");
  const rootGroups = [];
  if (entries.length) {
    lines.push(`  - name: ${yamlScalar("EntryPoints")}`, "    type: select", "    proxies:");
    entries.forEach((entry) => lines.push(`      - ${yamlScalar(entry.tag)}`));
    rootGroups.push("EntryPoints");
  }
  if (countries.length === 1) {
    const only = countries[0];
    lines.push(`  - name: ${yamlScalar(`${countryName(only.code)} ${countryFlag(only.code)}`.trim())}`, "    type: select", "    proxies:");
    only.variants.forEach((item) => lines.push(`      - ${yamlScalar(item.name)}`));
    if (autoBest.length > 1) {
      lines.push(
        `  - name: ${yamlScalar("Best")}`,
        "    type: url-test",
        "    url: http://www.gstatic.com/generate_204",
        "    interval: 300",
        "    tolerance: 50",
        "    lazy: true",
        "    proxies:"
      );
      autoBest.forEach((item) => lines.push(`      - ${yamlScalar(item.name)}`));
      lines.push("rules:", "  - MATCH,Best");
    } else {
      lines.push("rules:", `  - MATCH,${`${countryName(only.code)} ${countryFlag(only.code)}`.trim()}`);
    }
    return lines.join("\n") + "\n";
  }
  if (countries.length > 1) {
    const groupTitle = /* @__PURE__ */ __name2((code) => `${countryName(code)} ${countryFlag(code)}`.trim(), "groupTitle");
    const cardNames = countries.map((country) => groupTitle(country.code));
    lines.push(`  - name: ${yamlScalar("Proxy")}`, "    type: select", "    proxies:");
    if (autoBest.length > 1)
      lines.push(`      - ${yamlScalar("Best")}`);
    rootGroups.forEach((name) => lines.push(`      - ${yamlScalar(name)}`));
    cardNames.forEach((name) => lines.push(`      - ${yamlScalar(name)}`));
    for (const country of countries) {
      lines.push(`  - name: ${yamlScalar(groupTitle(country.code))}`, "    type: select", "    proxies:");
      country.variants.forEach((item) => lines.push(`      - ${yamlScalar(item.name)}`));
    }
    if (autoBest.length > 1) {
      lines.push(
        `  - name: ${yamlScalar("Best")}`,
        "    type: url-test",
        "    url: http://www.gstatic.com/generate_204",
        "    interval: 300",
        "    tolerance: 50",
        "    lazy: true",
        "    proxies:"
      );
      autoBest.forEach((item) => lines.push(`      - ${yamlScalar(item.name)}`));
    }
    lines.push("rules:", "  - MATCH,Proxy");
    return lines.join("\n") + "\n";
  }
  const ordered = [];
  for (const country of countries) {
    for (const item of country.variants)
      ordered.push(item.name);
  }
  for (const entry of entries)
    ordered.push(entry.tag);
  lines.push(`  - name: ${yamlScalar("Proxy")}`, "    type: select", "    proxies:");
  ordered.forEach((name) => lines.push(`      - ${yamlScalar(name)}`));
  lines.push("rules:", "  - MATCH,Proxy");
  return lines.join("\n") + "\n";
}
__name(mihomo, "mihomo");
__name2(mihomo, "mihomo");
__name22(mihomo, "mihomo");
function b64(text) {
  return btoa(String.fromCharCode(...new TextEncoder().encode(text)));
}
__name(b64, "b64");
__name2(b64, "b64");
__name22(b64, "b64");
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
__name(guessFormat, "guessFormat");
__name2(guessFormat, "guessFormat");
__name22(guessFormat, "guessFormat");
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
  else if (stream.security === "tls")
    stream.tlsSettings = {
      ...proxy.servername || proxy.sni ? { serverName: proxy.servername || proxy.sni } : {},
      ...proxy["client-fingerprint"] ? { fingerprint: proxy["client-fingerprint"] } : {},
      ...proxy.alpn?.length ? { alpn: proxy.alpn } : {},
      ...proxy.ech ? { echConfigList: proxy.ech } : {}
    };
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
__name(xrayOutbound, "xrayOutbound");
__name2(xrayOutbound, "xrayOutbound");
__name22(xrayOutbound, "xrayOutbound");
var GOOD_ENOUGH_MB_S = 50;
function qualityScore(health, stage3Speed = null) {
  if (!health)
    return -1;
  const speed = Number(stage3Speed);
  if (!Number.isFinite(speed) || speed < 0.01)
    return -1;
  const fraud = Number(health.classification?.min_fraud_score);
  const risk = Number.isFinite(fraud) ? fraud : 50;
  const type = String(health?.classification?.connection_type ?? health?.connection_type ?? "").toLowerCase();
  const speedPart = Math.min(1, speed / GOOD_ENOUGH_MB_S);
  const residential = /resi/.test(type) ? 0.4 : 0;
  const gemini = health.gemini && typeof health.gemini === "object" ? health.gemini : null;
  const geminiPenalty = gemini?.flagged === true ? -2.5 : 0;
  return 1.5 * speedPart + residential - 1 * (risk / 100) + geminiPenalty;
}
__name(qualityScore, "qualityScore");
__name2(qualityScore, "qualityScore");
__name22(qualityScore, "qualityScore");
function rankScore(health, stage3Speed = null) {
  return qualityScore(health, stage3Speed);
}
__name(rankScore, "rankScore");
__name2(rankScore, "rankScore");
__name22(rankScore, "rankScore");
function scoreForProxy(proxy, healthById, endpointIndex, speedByEndpoint) {
  const health = resolveHealthFor({ proxy }, healthById, endpointIndex);
  if (!health)
    return -1;
  const key = endpointKeyOf(proxy.server, Number(proxy?.port ?? proxy?.server_port));
  const measured = speedByEndpoint ? Number(speedByEndpoint[key]) : NaN;
  return rankScore(health, Number.isFinite(measured) && measured > 0 ? measured : null);
}
__name(scoreForProxy, "scoreForProxy");
__name2(scoreForProxy, "scoreForProxy");
__name22(scoreForProxy, "scoreForProxy");
var TOP_N = 10;
var COUNTRY_CAP = 60;
function topQualityVariants(countries, healthById, speedByEndpoint = null) {
  const endpointIndex = buildEndpointIndex(healthById || {});
  const scored = [];
  for (const country of countries) {
    for (const item of country.variants) {
      const proxy = item.proxy || item;
      const measured = speedByEndpoint ? speedByEndpoint[endpointKeyOf(proxy?.server, Number(proxy?.port ?? proxy?.server_port))] : null;
      const score = qualityScore(resolveHealthFor(item, healthById, endpointIndex), measured);
      if (score >= 0)
        scored.push({ item, score });
    }
  }
  scored.sort((left, right) => right.score - left.score);
  return scored.slice(0, TOP_N).map((entry) => entry.item);
}
__name(topQualityVariants, "topQualityVariants");
__name2(topQualityVariants, "topQualityVariants");
__name22(topQualityVariants, "topQualityVariants");
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
__name(xrayConfig, "xrayConfig");
__name2(xrayConfig, "xrayConfig");
__name22(xrayConfig, "xrayConfig");
function singboxOutbound(proxy, tag, detour = void 0) {
  const out = { type: proxy.type === "socks5" ? "socks" : proxy.type, tag, server: proxy.server, server_port: proxy.port };
  if (proxy.type === "vless") {
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
__name(singboxOutbound, "singboxOutbound");
__name2(singboxOutbound, "singboxOutbound");
__name22(singboxOutbound, "singboxOutbound");
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
__name(singbox, "singbox");
__name2(singbox, "singbox");
__name22(singbox, "singbox");
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
    const origin = (env.FEED_ORIGIN || "https://raw.githubusercontent.com/TheCalmBoy/proxy-collector/gh-pages").replace(/\/$/, "");
    const feedPath = country ? `countries/${country}.txt` : "all.txt";
    const feed = await fetch(`${origin}/${feedPath}`, { headers: { accept: "text/plain" }, signal: AbortSignal.timeout(1e4) });
    if (feed.status === 404)
      return fail("country_feed_not_found", 404);
    if (!feed.ok)
      return fail("country_feed_unavailable", 502);
    const rows = (await feed.text()).split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
    let parsed = rows.map((uri, i) => ({ uri, proxy: parseProxy(uri, i + 1) })).filter((item) => item.proxy);
    if (!parsed.length)
      return fail("feed_has_no_supported_proxies", 404);
    let healthById = {};
    let healthIndexState = "missing";
    let healthJoin = null;
    let healthAgeMs = null;
    try {
      const healthVersion = Math.floor(Date.now() / (5 * 6e4));
      const healthResponse = await fetch(`${origin}/egress-health.json?v=${healthVersion}`, {
        headers: { accept: "application/json" },
        signal: AbortSignal.timeout(5e3),
        cf: { cacheTtl: 300, cacheEverything: true }
      });
      if (healthResponse.status !== 404)
        healthIndexState = healthResponse.ok ? "stale" : "unavailable";
      if (healthResponse.ok) {
        const healthDocument = await healthResponse.json();
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
    }
    let speedByEndpoint = {};
    try {
      const enrichedVersion = Math.floor(Date.now() / (5 * 6e4));
      const enrichedResponse = await fetch(`${origin}/enriched-configs.json?v=${enrichedVersion}`, {
        headers: { accept: "application/json" },
        signal: AbortSignal.timeout(5e3),
        cf: { cacheTtl: 300, cacheEverything: true }
      });
      if (enrichedResponse.ok) {
        speedByEndpoint = buildSpeedIndex(await enrichedResponse.json());
      }
    } catch {
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
    let variantSerial = 0;
    const countries = [...grouped.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([code, items]) => {
      const ranked = items.map((item) => ({
        item,
        score: scoreForProxy(item.proxy, healthById, endpointIndex, speedByEndpoint)
      })).sort((left, right) => right.score - left.score);
      const capped = code === RAINBOW_KEY ? ranked : ranked.slice(0, COUNTRY_CAP);
      const exits = capped.map((entry) => entry.item.proxy);
      const baseNames = exits.map((proxy, index) => friendlyExitName(code, index, proxy, healthById, null, speedByEndpoint));
      const variants = [];
      for (let index = 0; index < exits.length; index += 1) {
        if (entries.length) {
          const slot = variantSerial;
          variantSerial += 1;
          const entry = entries[slot % entries.length];
          variants.push({
            proxy: exits[index],
            name: friendlyExitName(code, index, exits[index], healthById, null, speedByEndpoint),
            tag: `${code}-${String(index + 1).padStart(2, "0")}e${slot % entries.length + 1}`,
            dialerProxy: entry.tag
          });
        } else {
          variants.push({ proxy: exits[index], name: baseNames[index] });
        }
      }
      return { code, items: capped.map((entry) => entry.item), exits, baseNames, variants };
    });
    if (!countries.length)
      return fail("no_recently_verified_proxies", 503, healthHeaders());
    const joinHeaders = healthHeaders();
    if (format === "links" || !entries.length && (format === "xray" || format === "unknown")) {
      const links = countries.flatMap((group) => group.items.map((item, index) => withUriName(item.uri, group.baseNames[index])));
      if (entries.length)
        links.unshift(...entries.map((entry) => withUriName(entry.uri, entry.tag)));
      return reply(b64(links.join("\n")), 200, "text/plain; charset=utf-8", joinHeaders);
    }
    if (format === "mihomo")
      return reply(mihomo(entries, countries, healthById, speedByEndpoint), 200, "text/yaml; charset=utf-8", joinHeaders);
    if (format === "sing-box")
      return reply(singbox(entries, countries, healthById, speedByEndpoint), 200, "application/json; charset=utf-8", joinHeaders);
    return reply(xrayConfig(entries, countries, country || "ALL", healthById, speedByEndpoint), 200, "application/json; charset=utf-8", joinHeaders);
  }
};
export {
  GOOD_ENOUGH_MB_S,
  buildEndpointIndex,
  buildSpeedIndex,
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
//# sourceMappingURL=index.js.map
