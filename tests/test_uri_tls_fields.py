#!/usr/bin/env python3
"""TLS fields must reach sing-box, or the probe reports a working config dead.

Every field here was previously dropped, and each drop produced a false
negative rather than an error. The worst was silent: sing-box treats a reality
block without `enabled` as "no reality at all", so the outbound fell back to
plain TLS and was dialled unencrypted against a reality server. Nothing logged
a problem -- the config just came back dead.

The accepted fingerprint list mirrors `sing-box check` on the shipped 1.14
build, tested one value at a time. An unknown name does not merely fail that
config: it aborts the shared process and zeroes the whole run.
"""

import unittest

from tools.verify import parse_proxy_uri

UUID = "11111111-2222-3333-4444-555555555555"
PBK = "A" * 43


def vless(query, host="1.2.3.4"):
    return parse_proxy_uri(f"vless://{UUID}@{host}:443?{query}")


class RealityTests(unittest.TestCase):
    def test_reality_block_is_enabled_and_complete(self):
        out = vless(
            f"encryption=none&security=reality&pbk={PBK}&sid=0123"
            "&sni=a.example&fp=chrome"
        )
        reality = out["tls"]["reality"]
        self.assertIs(reality["enabled"], True)
        self.assertEqual(reality["public_key"], PBK)
        self.assertEqual(reality["short_id"], "0123")
        self.assertEqual(out["tls"]["server_name"], "a.example")

    def test_reality_always_carries_utls(self):
        # sing-box refuses to start a reality client without uTLS, so a link
        # that asks for no fingerprint still has to get one.
        for query in (
            f"security=reality&pbk={PBK}&sni=a.example",
            f"security=reality&pbk={PBK}&sni=a.example&fp=unsafe",
            f"security=reality&pbk={PBK}&sni=a.example&fp=not-a-real-fingerprint",
        ):
            with self.subTest(query=query):
                tls = vless(query)["tls"]
                self.assertEqual(tls["utls"], {"enabled": True, "fingerprint": "chrome"})

    def test_reality_keeps_a_supported_fingerprint(self):
        out = vless(f"security=reality&pbk={PBK}&sni=a.example&fp=firefox")
        self.assertEqual(out["tls"]["utls"]["fingerprint"], "firefox")

    def test_reality_without_public_key_is_rejected(self):
        # Probing it as plain TLS can only ever be a false negative.
        with self.assertRaises(ValueError) as raised:
            vless("security=reality&sni=a.example&fp=chrome")
        self.assertEqual(str(raised.exception), "reality_without_public_key")


class TransportLayerSecurityTests(unittest.TestCase):
    def test_alpn_is_passed_through_as_a_list(self):
        self.assertEqual(
            vless("security=tls&sni=a.example&alpn=h2,http/1.1")["tls"]["alpn"],
            ["h2", "http/1.1"],
        )

    def test_single_alpn_value(self):
        self.assertEqual(
            vless("security=tls&sni=a.example&alpn=http%2F1.1")["tls"]["alpn"],
            ["http/1.1"],
        )

    def test_alpn_absent_means_no_key(self):
        self.assertNotIn("alpn", vless("security=tls&sni=a.example")["tls"])

    def test_insecure_spellings_all_map_to_tls_insecure(self):
        for key in ("insecure", "allowInsecure", "skip-cert-verify"):
            with self.subTest(key=key):
                tls = vless(f"security=tls&sni=a.example&{key}=1")["tls"]
                self.assertIs(tls["insecure"], True)

    def test_insecure_zero_is_not_insecure(self):
        self.assertNotIn("insecure", vless("security=tls&sni=a.example&insecure=0")["tls"])

    def test_fingerprint_unsafe_means_no_utls(self):
        # Xray spells "do not use uTLS" as "unsafe"; sing-box rejects that
        # literal name, so it has to become an absent utls block.
        self.assertNotIn("utls", vless("security=tls&sni=a.example&fp=unsafe")["tls"])

    def test_supported_fingerprints_are_kept(self):
        for fp in ("chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random"):
            with self.subTest(fp=fp):
                tls = vless(f"security=tls&sni=a.example&fp={fp}")["tls"]
                self.assertEqual(tls["utls"], {"enabled": True, "fingerprint": fp})

    def test_unknown_fingerprint_is_dropped_not_forwarded(self):
        tls = vless("security=tls&sni=a.example&fp=chrome9")["tls"]
        self.assertNotIn("utls", tls)

    def test_security_none_stays_plain(self):
        self.assertNotIn("tls", vless("encryption=none&type=tcp"))

    def test_sni_falls_back_to_the_server(self):
        self.assertEqual(vless("security=tls")["tls"]["server_name"], "1.2.3.4")

    def test_trojan_gets_the_same_fields(self):
        out = parse_proxy_uri(
            "trojan://secret@1.2.3.4:443?security=tls&sni=b.example"
            "&alpn=http/1.1&allowInsecure=1&fp=firefox"
        )
        self.assertEqual(out["password"], "secret")
        self.assertEqual(out["tls"]["alpn"], ["http/1.1"])
        self.assertIs(out["tls"]["insecure"], True)
        self.assertEqual(out["tls"]["utls"]["fingerprint"], "firefox")


if __name__ == "__main__":
    unittest.main()
