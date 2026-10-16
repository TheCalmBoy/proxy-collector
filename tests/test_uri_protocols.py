#!/usr/bin/env python3
"""QUIC protocols the core supports must not be dropped at the scheme check.

The allowlist held only vmess/vless/trojan/ss/socks/http, so hysteria2, tuic
and anytls links were discarded before any probe ran. 17 of the 271 links in a
live upstream feed were hysteria2, and they sat at a hard 0% survival for a
reason that had nothing to do with the servers.

sing-box 1.14 runs all three natively, and it also still ships the legacy
shadowsocks stream ciphers that the old cipher list rejected. Every value
allowed here was checked against `sing-box check` first.

Rejections are asserted against ValueError rather than UnsupportedConfig: that
class subclasses ValueError, and test_verify.py loads tools/verify.py a second
time under the module name "verify", so in a full-suite run there are two
distinct UnsupportedConfig class objects and assertRaises, which matches on
identity, would let the real one through.
"""

import base64
import unittest

from tools.verify import build_sing_box_config, parse_proxy_uri


class Hysteria2Tests(unittest.TestCase):
    def test_basic_link(self):
        out = parse_proxy_uri("hysteria2://secret@1.2.3.4:443?sni=a.example&insecure=1")
        self.assertEqual(out["type"], "hysteria2")
        self.assertEqual(out["password"], "secret")
        self.assertEqual(out["tls"]["server_name"], "a.example")
        self.assertIs(out["tls"]["insecure"], True)

    def test_hy2_alias(self):
        out = parse_proxy_uri("hy2://secret@1.2.3.4:8443?sni=a.example")
        self.assertEqual(out["type"], "hysteria2")
        self.assertEqual(out["server_port"], 8443)

    def test_obfs_is_carried_across(self):
        out = parse_proxy_uri(
            "hysteria2://secret@1.2.3.4:443?sni=a.example"
            "&obfs=salamander&obfs-password=opaque"
        )
        self.assertEqual(out["obfs"], {"type": "salamander", "password": "opaque"})

    def test_alpn_h3_is_kept(self):
        out = parse_proxy_uri("hysteria2://secret@1.2.3.4:443?sni=a.example&alpn=h3")
        self.assertEqual(out["tls"]["alpn"], ["h3"])

    def test_no_transport_block(self):
        # QUIC carries no TCP transport; emitting one would be wrong.
        out = parse_proxy_uri("hysteria2://secret@1.2.3.4:443?sni=a.example")
        self.assertNotIn("transport", out)

    def test_missing_password_is_rejected(self):
        with self.assertRaises(ValueError) as raised:
            parse_proxy_uri("hysteria2://1.2.3.4:443?sni=a.example")
        self.assertEqual(str(raised.exception), "missing_password")


class TuicTests(unittest.TestCase):
    def test_uuid_and_password_in_userinfo(self):
        out = parse_proxy_uri(
            "tuic://11111111-2222-3333-4444-555555555555:secret@1.2.3.4:443"
            "?sni=a.example&alpn=h3&congestion_control=bbr"
        )
        self.assertEqual(out["type"], "tuic")
        self.assertEqual(out["uuid"], "11111111-2222-3333-4444-555555555555")
        self.assertEqual(out["password"], "secret")
        self.assertEqual(out["congestion_control"], "bbr")
        self.assertEqual(out["tls"]["alpn"], ["h3"])

    def test_password_in_the_query(self):
        out = parse_proxy_uri("tuic://11111111-2222-3333-4444-555555555555@1.2.3.4:443?password=secret")
        self.assertEqual(out["uuid"], "11111111-2222-3333-4444-555555555555")
        self.assertEqual(out["password"], "secret")

    def test_missing_uuid_is_rejected(self):
        with self.assertRaises(ValueError) as raised:
            parse_proxy_uri("tuic://1.2.3.4:443?sni=a.example")
        self.assertEqual(str(raised.exception), "missing_uuid")


class AnytlsTests(unittest.TestCase):
    def test_password_and_tls(self):
        out = parse_proxy_uri("anytls://secret@1.2.3.4:443?sni=a.example&insecure=1")
        self.assertEqual(out["type"], "anytls")
        self.assertEqual(out["password"], "secret")
        self.assertIs(out["tls"]["insecure"], True)

    def test_missing_password_is_rejected(self):
        with self.assertRaises(ValueError) as raised:
            parse_proxy_uri("anytls://1.2.3.4:443?sni=a.example")
        self.assertEqual(str(raised.exception), "missing_password")


class ShadowsocksCipherTests(unittest.TestCase):
    @staticmethod
    def link(method, password="pw"):
        auth = base64.b64encode(f"{method}:{password}".encode()).decode()
        return f"ss://{auth}@1.2.3.4:8388#tag"

    def test_legacy_stream_ciphers_are_accepted(self):
        # These are built into sing-box 1.14; rejecting them discarded working
        # configs that appear throughout the upstream feeds.
        for method in ("aes-256-cfb", "aes-128-cfb", "aes-256-ctr", "rc4-md5", "chacha20-ietf", "xchacha20"):
            with self.subTest(method=method):
                self.assertEqual(parse_proxy_uri(self.link(method))["method"], method)

    def test_bare_chacha20_is_still_rejected(self):
        # The one name the core genuinely does not have.
        with self.assertRaises(ValueError) as raised:
            parse_proxy_uri(self.link("chacha20"))
        self.assertEqual(str(raised.exception), "unsupported_ss_method:chacha20")

    def test_2022_key_length_is_still_enforced(self):
        with self.assertRaises(ValueError) as raised:
            parse_proxy_uri(self.link("2022-blake3-aes-256-gcm", password="tooshort"))
        self.assertEqual(str(raised.exception), "invalid_ss_key_length")


class MixedBatchTests(unittest.TestCase):
    def test_quic_protocols_reach_the_verifier(self):
        uris = [
            "hysteria2://secret@1.2.3.4:443?sni=a.example",
            "tuic://11111111-2222-3333-4444-555555555555:secret@1.2.3.5:443?sni=a.example",
            "anytls://secret@1.2.3.6:443?sni=a.example",
            "ss://" + base64.b64encode(b"aes-256-cfb:pw").decode() + "@1.2.3.7:8388",
            "vless://11111111-2222-3333-4444-555555555555@1.2.3.8:443?security=tls&type=xhttp",
        ]
        config, records, stats = build_sing_box_config(uris)
        self.assertEqual(stats["supported"], 4)
        self.assertEqual(stats["unsupported"], 1)
        kinds = {o["type"] for o in config["outbounds"]}
        self.assertLessEqual({"hysteria2", "tuic", "anytls", "shadowsocks"}, kinds)


if __name__ == "__main__":
    unittest.main()
