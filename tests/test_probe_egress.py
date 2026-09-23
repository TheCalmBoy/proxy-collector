import base64
import json
import unittest

from tools.probe_egress import UnsupportedConfig, build_sing_box_config, parse_proxy_uri


class ParseProxyUriTests(unittest.TestCase):
    def test_vless_reality(self):
        outbound = parse_proxy_uri(
            "vless://user-id@example.com:443?security=reality&type=tcp&"
            "sni=front.example&fp=chrome&pbk=public-key&sid=abcd&flow=xtls-rprx-vision#node"
        )
        self.assertEqual(outbound["type"], "vless")
        self.assertEqual(outbound["flow"], "xtls-rprx-vision")
        self.assertEqual(outbound["tls"]["server_name"], "front.example")
        self.assertEqual(outbound["tls"]["reality"]["short_id"], "abcd")
        self.assertEqual(outbound["tls"]["utls"], {"enabled": True, "fingerprint": "chrome"})

    def test_vless_reality_defaults_missing_fingerprint(self):
        outbound = parse_proxy_uri(
            "vless://user-id@example.com:443?security=reality&pbk=public-key"
        )
        self.assertEqual(outbound["tls"]["utls"]["fingerprint"], "chrome")

    def test_vmess_websocket_tls(self):
        payload = base64.b64encode(json.dumps({
            "add": "example.com", "port": "443", "id": "user-id", "aid": "0",
            "scy": "auto", "net": "ws", "host": "cdn.example", "path": "/path",
            "tls": "tls", "sni": "cdn.example", "fp": "chrome",
        }).encode()).decode()
        outbound = parse_proxy_uri("vmess://" + payload)
        self.assertEqual(outbound["type"], "vmess")
        self.assertEqual(outbound["transport"]["headers"]["Host"], "cdn.example")
        self.assertEqual(outbound["transport"]["path"], "/path")
        self.assertEqual(outbound["tls"]["server_name"], "cdn.example")

    def test_shadowsocks_sip002(self):
        outbound = parse_proxy_uri("ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@example.com:8388#node")
        self.assertEqual(outbound["type"], "shadowsocks")
        self.assertEqual(outbound["method"], "aes-128-gcm")
        self.assertEqual(outbound["password"], "password")

    def test_trojan_tls(self):
        outbound = parse_proxy_uri("trojan://secret@example.com:443?sni=front.example#node")
        self.assertEqual(outbound["type"], "trojan")
        self.assertEqual(outbound["password"], "secret")
        self.assertEqual(outbound["tls"]["server_name"], "front.example")

    def test_unknown_protocol_is_counted_not_guessed(self):
        with self.assertRaises(UnsupportedConfig):
            parse_proxy_uri("hysteria2://password@example.com:443")

    def test_builds_distinct_socks_inbounds_and_routes(self):
        links = [
            "vless://u1@example.com:443?security=none&type=tcp",
            "trojan://pass@example.net:443?sni=example.net",
        ]
        config, rows, stats = build_sing_box_config(links)
        self.assertEqual(len(rows), 2)
        self.assertEqual(len(config["inbounds"]), 2)
        self.assertEqual(len(config["route"]["rules"]), 2)
        self.assertEqual(stats["supported"], 2)
        self.assertEqual(config["route"]["rules"][0]["action"], "route")


if __name__ == "__main__":
    unittest.main()
