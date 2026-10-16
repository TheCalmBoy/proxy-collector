#!/usr/bin/env python3
"""Translation defects found by the A/B against mihomo's own parser.

The A/B (run 38976227854) took 30 configs our pipeline drops from upstream's
"verified" pool and dialled each one twice on the same runner: once through our
parser + sing-box, once through mihomo's own subscription decoder. Controls
guaranteed validity -- 8/8 published configs opened in both arms, and an
unroutable 192.0.2.1 canary failed in both. Result: mihomo opened 4 that we
could not. Two were xhttp (a transport sing-box does not implement, refused on
purpose, so not a defect). The other two were ours:

* a trojan link carrying `sni` but no explicit `security=tls` was emitted with
  NO tls block at all -- a plaintext dial at a TLS server, guaranteed dead;
* a trojan+ws link naming only `sni` got no Host header at all.

The early-data case is measured over the whole feed rather than the sample:
13 of 13 ws configs whose path carried `?ed=` died, against 13.4% survival for
the rest, because the query was passed through as part of the request path.
"""

import base64
import json
import unittest

from tools.verify import parse_proxy_uri


class TrojanTlsIsImplied(unittest.TestCase):
    """Trojan has no plaintext mode: sni or any TLS material means TLS."""

    def test_sni_without_security_still_builds_tls(self):
        out = parse_proxy_uri("trojan://secret@1.2.3.4:443?sni=x.example.com&type=tcp&fp=chrome")
        self.assertIn("tls", out)
        self.assertIs(out["tls"]["enabled"], True)
        self.assertEqual(out["tls"]["server_name"], "x.example.com")

    def test_security_none_does_not_strip_trojan_tls(self):
        out = parse_proxy_uri("trojan://secret@1.2.3.4:443?security=none&sni=x.example.com")
        self.assertIn("tls", out)

    def test_vless_is_not_treated_as_implied(self):
        # The fix must not leak: vless really can be plaintext.
        out = parse_proxy_uri(
            "vless://user-id@1.2.3.4:443?encryption=none&security=none&type=tcp"
        )
        self.assertNotIn("tls", out)


class WebSocketEarlyData(unittest.TestCase):
    """`path=/x?ed=2560` is early data, not part of the request path."""

    def test_ed_query_is_split_out_of_the_path(self):
        out = parse_proxy_uri(
            "vless://user-id@1.2.3.4:443?encryption=none&security=tls&type=ws"
            "&path=%2Fx%3Fed%3D2560&host=h.example.com"
        )
        transport = out["transport"]
        self.assertEqual(transport["path"], "/x")
        self.assertEqual(transport["max_early_data"], 2560)
        self.assertEqual(transport["early_data_header_name"], "Sec-WebSocket-Protocol")

    def test_plain_path_is_untouched(self):
        out = parse_proxy_uri(
            "vless://user-id@1.2.3.4:443?encryption=none&security=tls&type=ws&path=%2Fplain"
        )
        self.assertEqual(out["transport"]["path"], "/plain")
        self.assertNotIn("max_early_data", out["transport"])

    def test_vmess_ws_early_data_is_split_too(self):
        payload = base64.b64encode(json.dumps({
            "add": "example.com", "port": "443", "id": "user-id", "aid": "0",
            "net": "ws", "path": "/vm?ed=2048", "host": "h.example.com", "tls": "tls",
        }).encode()).decode()
        out = parse_proxy_uri("vmess://" + payload)
        self.assertEqual(out["transport"]["path"], "/vm")
        self.assertEqual(out["transport"]["max_early_data"], 2048)


class WebSocketHostFallback(unittest.TestCase):
    """A ws link naming only sni still needs the Host header the front routes on."""

    def test_host_falls_back_to_sni(self):
        out = parse_proxy_uri(
            "vless://user-id@1.2.3.4:443?encryption=none&security=tls&type=ws"
            "&path=%2Fonly&sni=s.example.com"
        )
        self.assertEqual(out["transport"]["headers"]["Host"], "s.example.com")

    def test_explicit_host_still_wins(self):
        out = parse_proxy_uri(
            "vless://user-id@1.2.3.4:443?encryption=none&security=tls&type=ws"
            "&path=%2Fonly&sni=s.example.com&host=explicit.example.com"
        )
        self.assertEqual(out["transport"]["headers"]["Host"], "explicit.example.com")


class VmessRawTransport(unittest.TestCase):
    """`net=raw` is "no transport", exactly as the vless path already treats it."""

    def _vmess(self, **overrides):
        payload = {"add": "example.com", "port": "443", "id": "user-id", "aid": "0",
                   "net": "raw", "type": "none", "host": "", "path": "",
                   "tls": "tls", "sni": "x.example.com"}
        payload.update(overrides)
        return "vmess://" + base64.b64encode(json.dumps(payload).encode()).decode()

    def test_net_raw_parses_as_plain_tcp(self):
        out = parse_proxy_uri(self._vmess())
        self.assertEqual(out["type"], "vmess")
        self.assertNotIn("transport", out)

    def test_net_none_parses_as_plain_tcp(self):
        out = parse_proxy_uri(self._vmess(net="none"))
        self.assertNotIn("transport", out)


if __name__ == "__main__":
    unittest.main()
