#!/usr/bin/env python3
"""Batch-build robustness, found by the 2026-10-17 source hunt.

Two failures, each of which cost an entire 22k-candidate measurement run:

1. an `https://` proxy emitted `"tls": true`. sing-box wants a TLS object there
   and refuses the whole config at startup ("cannot unmarshal bool into
   HTTPOutboundOptions.OutboundTLSOptionsContainer.tls"). Our three original
   feeds carry no http(s) URIs, so the bug stayed hidden until aggregator feeds
   brought hundreds of them.
2. any `check` failure raised, so one unbuildable outbound cost every candidate
   in the batch instead of itself.
"""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from tools import verify


def _uris():
    return [
        "http://1.2.3.4:8080",
        "https://user:pass@example.com:8443",
        "socks5://5.6.7.8:1080",
        "vless://00000000-0000-4000-8000-000000000000@9.9.9.9:443?security=tls&sni=a.example&type=tcp",
    ]


class TestHttpsOutboundTls(unittest.TestCase):
    def test_https_outbound_emits_a_tls_object(self):
        config, _records, _stats = verify.build_sing_box_config(["https://user:pass@example.com:8443"])
        http_ob = [ob for ob in config["outbounds"] if ob["type"] == "http"]
        self.assertEqual(len(http_ob), 1)
        self.assertIsInstance(http_ob[0]["tls"], dict)
        self.assertTrue(http_ob[0]["tls"]["enabled"])
        self.assertEqual(http_ob[0]["tls"]["server_name"], "example.com")

    def test_plain_http_outbound_carries_no_tls(self):
        config, _records, _stats = verify.build_sing_box_config(["http://1.2.3.4:8080"])
        http_ob = [ob for ob in config["outbounds"] if ob["type"] == "http"][0]
        self.assertNotIn("tls", http_ob)

    def test_no_outbound_tls_field_is_a_bool(self):
        config, _records, _stats = verify.build_sing_box_config(_uris())
        for ob in config["outbounds"]:
            if "tls" in ob:
                self.assertIsInstance(ob["tls"], dict, f"bool tls on {ob.get('tag')}")


class TestOffenderDrop(unittest.TestCase):
    def test_named_outbound_loses_outbound_inbound_and_rule(self):
        config, _records, _stats = verify.build_sing_box_config(_uris())
        index = next(
            i for i, ob in enumerate(config["outbounds"])
            if str(ob.get("tag", "")).startswith("proxy-")
        )
        cid = config["outbounds"][index]["tag"].removeprefix("proxy-")
        stderr = f"FATAL decode config at /tmp/verify-sing-box.json: outbounds[{index}].tls: bad"
        dropped = verify._drop_offending_outbounds(config, stderr)
        self.assertEqual(dropped, [cid])
        self.assertNotIn(f"proxy-{cid}", [ob.get("tag") for ob in config["outbounds"]])
        self.assertNotIn(f"in-{cid}", [ib.get("tag") for ib in config["inbounds"]])
        for rule in config["route"]["rules"]:
            self.assertNotIn(f"in-{cid}", rule.get("inbound") or [])

    def test_final_outbound_is_never_dropped(self):
        config, _records, _stats = verify.build_sing_box_config(_uris())
        final = config["route"]["final"]
        index = next(i for i, ob in enumerate(config["outbounds"]) if ob.get("tag") == final)
        self.assertEqual(verify._drop_offending_outbounds(config, f"outbounds[{index}].tls"), [])
        self.assertIn(final, [ob.get("tag") for ob in config["outbounds"]])

    def test_unattributable_failure_drops_nothing(self):
        config, _records, _stats = verify.build_sing_box_config(_uris())
        before = len(config["outbounds"])
        self.assertEqual(verify._drop_offending_outbounds(config, "FATAL: something else"), [])
        self.assertEqual(len(config["outbounds"]), before)

    def test_multiple_named_outbounds_drop_together(self):
        config, _records, _stats = verify.build_sing_box_config(_uris())
        indices = [
            i for i, ob in enumerate(config["outbounds"])
            if str(ob.get("tag", "")).startswith("proxy-")
        ]
        if len(indices) < 2:
            self.skipTest("need two proxy outbounds")
        stderr = f"outbounds[{indices[0]}].tls: a\noutbounds[{indices[-1]}].x: b"
        self.assertEqual(len(verify._drop_offending_outbounds(config, stderr)), 2)

    def test_out_of_range_index_is_ignored(self):
        config, _records, _stats = verify.build_sing_box_config(_uris())
        before = len(config["outbounds"])
        self.assertEqual(verify._drop_offending_outbounds(config, "outbounds[9999].tls"), [])
        self.assertEqual(len(config["outbounds"]), before)


class TestRealityPublicKey(unittest.TestCase):
    """A malformed `pbk` costs the whole batch at sing-box startup, so it has to
    be rejected at build time, where it costs one candidate and gets a counter."""

    @staticmethod
    def _reality_uri(pbk: str) -> str:
        base = (
            "vless://00000000-0000-4000-8000-000000000000@9.9.9.9:443"
            "?security=reality&type=tcp&sni=a.example&sid=abcd&pbk="
        )
        return base + pbk

    def test_unpadded_base64url_key_is_accepted(self):
        key = "A" * 43  # 43 base64url chars == 32 bytes
        outbound = verify.parse_proxy_uri(self._reality_uri(key))
        self.assertEqual(outbound["tls"]["reality"]["public_key"], key)

    def test_padded_base64_key_is_accepted(self):
        key = "A" * 43 + "="
        outbound = verify.parse_proxy_uri(self._reality_uri(key))
        self.assertEqual(outbound["tls"]["reality"]["public_key"], key)

    def test_hex_key_is_accepted(self):
        key = "ab" * 32
        outbound = verify.parse_proxy_uri(self._reality_uri(key))
        self.assertEqual(outbound["tls"]["reality"]["public_key"], key)

    def test_bad_key_is_rejected_with_a_reason(self):
        # "A" * 64 is deliberately absent: that is a valid 32-byte hex key.
        for bad in ("notakey", "A" * 40, "A" * 60, "aa!!bb"):
            with self.subTest(bad=bad):
                with self.assertRaises(verify.UnsupportedConfig) as ctx:
                    verify.parse_proxy_uri(self._reality_uri(bad))
                self.assertEqual(str(ctx.exception), "invalid_reality_public_key")

    def test_missing_key_keeps_its_original_reason(self):
        uri = (
            "vless://00000000-0000-4000-8000-000000000000@9.9.9.9:443"
            "?security=reality&type=tcp&sni=a.example"
        )
        with self.assertRaises(verify.UnsupportedConfig) as ctx:
            verify.parse_proxy_uri(uri)
        self.assertEqual(str(ctx.exception), "reality_without_public_key")

    def test_bad_key_is_counted_not_fatal_in_a_batch(self):
        config, records, stats = verify.build_sing_box_config(
            [_uris()[0], self._reality_uri("notakey")]
        )
        self.assertEqual(stats["unsupported"], 1)
        self.assertEqual(stats["supported"], 1)
        self.assertEqual(len(records), 1)


class TestStartupStyleErrors(unittest.TestCase):
    def test_initialize_outbound_index_is_dropped(self):
        config, _records, _stats = verify.build_sing_box_config(_uris())
        index = next(
            i for i, ob in enumerate(config["outbounds"])
            if str(ob.get("tag", "")).startswith("proxy-")
        )
        cid = config["outbounds"][index]["tag"].removeprefix("proxy-")
        stderr = f"FATAL[0000] initialize outbound[{index}]: invalid public_key"
        self.assertEqual(verify._drop_offending_outbounds(config, stderr), [cid])


if __name__ == "__main__":
    unittest.main()
