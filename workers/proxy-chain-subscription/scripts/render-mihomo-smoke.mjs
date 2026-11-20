import { mihomo } from "../index.js";

// Produce a deterministic profile through the production renderer. CI feeds
// this to the Mihomo binary so renderer output is checked by the real client.
const proxies = [
  { type: "vless", name: "vless", server: "192.0.2.1", port: 443, uuid: "11111111-2222-3333-4444-555555555555", tls: { enabled: true, servername: "example.com" } },
  { type: "vmess", name: "vmess", server: "192.0.2.2", port: 443, uuid: "11111111-2222-3333-4444-555555555555", alterId: 0, cipher: "auto", tls: true },
  { type: "trojan", name: "trojan", server: "192.0.2.3", port: 443, password: "fixture-password", sni: "example.com" },
  { type: "ss", name: "shadowsocks", server: "192.0.2.4", port: 8388, cipher: "aes-128-gcm", password: "fixture-password" },
  { type: "socks", name: "socks", server: "192.0.2.5", port: 1080, username: "fixture", password: "fixture-password" },
  { type: "http", name: "http", server: "192.0.2.6", port: 8080 },
];
const countries = [{
  code: "US",
  variants: proxies.map((proxy, index) => ({
    proxy,
    name: `${proxy.name}-${index + 1}`,
    dialerProxy: "Entry-1",
  })),
}];
const entries = [{
  tag: "Entry-1",
  proxy: {
    type: "vless",
    name: "entry",
    server: "192.0.2.10",
    port: 443,
    uuid: "11111111-2222-3333-4444-555555555555",
    tls: true,
  },
}];
process.stdout.write(mihomo(entries, countries, {}, null));
