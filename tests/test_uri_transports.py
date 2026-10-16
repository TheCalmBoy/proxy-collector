#!/usr/bin/env python3
"""A transport sing-box cannot build must be rejected, never dialled as TCP.

The old code produced a transport block only for ws and grpc and returned None
for everything else, which meant an h2, httpupgrade or xhttp config was probed
as a plain TCP connection to the server. That cannot succeed, and because the
drop was silent the config landed in the survival numbers looking exactly like
a dead server.

Two rules follow from that, and both are tested here:
  * transports sing-box implements are built, with the exact key shapes it
    wants (it takes the h2 host as a list, and fails validation otherwise);
  * transports it does not implement are raised as unsupported, so the loss is
    visible in the per-source reasons instead of hiding among the dead.
"""

import unittest

from tools.verify import build_sing_box_config, parse_proxy_uri

UUID = "11111111-2222-3333-4444-555555555555"


def vless(query, host="1.2.3.4"):
    return parse_proxy_uri(f"vless://{UUID}@{host}:443?{query}")


def vmess(**payload):
    import base64
    import json

    body = {
        "v": "2", "ps": "t", "add": "1.2.3.4", "port": "443",
        "id": UUID, "aid": "0", "scy": "auto",
    }
    body.update(payload)
    encoded = base64.b64encode(json.dumps(body).encode()).decode()
    return parse_proxy_uri(f"vmess://{encoded}")


class QueryTransportTests(unittest.TestCase):
    def test_ws_carries_path_and_host_header(self):
        out = vless("security=tls&type=ws&path=%2Fabc&host=a.example")
        self.assertEqual(out["transport"], {"type": "ws", "path": "/abc", "headers": {"Host": "a.example"}})

    def test_grpc_carries_service_name(self):
        out = vless("security=tls&type=grpc&serviceName=svc")
        self.assertEqual(out["transport"], {"type": "grpc", "service_name": "svc"})

    def test_httpupgrade_is_built(self):
        out = vless("security=tls&type=httpupgrade&path=%2Fup&host=a.example")
        self.assertEqual(
            out["transport"],
            {"type": "httpupgrade", "path": "/up", "headers": {"Host": "a.example"}},
        )

    def test_h2_host_is_a_list(self):
        # sing-box rejects a bare string here, which would abort the run.
        out = vless("security=tls&type=h2&path=%2Fh2&host=a.example")
        self.assertEqual(out["transport"], {"type": "http", "path": "/h2", "host": ["a.example"]})

    def test_http_and_h2mux_are_the_same_transport(self):
        for net in ("http", "h2", "h2mux"):
            with self.subTest(net=net):
                self.assertEqual(vless(f"security=tls&type={net}")["transport"]["type"], "http")

    def test_plain_transports_produce_no_block(self):
        for net in ("", "tcp", "raw", "none"):
            with self.subTest(net=net):
                query = "security=tls" + (f"&type={net}" if net else "")
                self.assertNotIn("transport", vless(query))

    def test_xray_only_transports_are_rejected(self):
        for net in ("xhttp", "splithttp", "quic", "kcp"):
            with self.subTest(net=net):
                with self.assertRaises(ValueError) as raised:
                    vless(f"security=tls&type={net}")
                self.assertEqual(str(raised.exception), f"unsupported_transport:{net}")


class VmessTransportTests(unittest.TestCase):
    def test_vmess_tls_is_honoured(self):
        # The `tls` key was never read, so vmess-over-TLS was dialled in
        # plaintext at a TLS port and could only fail.
        out = vmess(net="ws", path="/w", host="a.example", tls="tls", sni="a.example")
        self.assertEqual(out["tls"]["enabled"], True)
        self.assertEqual(out["tls"]["server_name"], "a.example")
        self.assertEqual(out["transport"]["type"], "ws")

    def test_vmess_without_tls_has_no_tls_block(self):
        self.assertNotIn("tls", vmess(net="ws", path="/w"))

    def test_vmess_tls_carries_alpn_and_insecure(self):
        out = vmess(net="ws", tls="tls", sni="a.example", alpn="h2,http/1.1", allowInsecure=True)
        self.assertEqual(out["tls"]["alpn"], ["h2", "http/1.1"])
        self.assertIs(out["tls"]["insecure"], True)

    def test_vmess_h2_builds_an_http_transport(self):
        out = vmess(net="h2", path="/h", host="a.example")
        self.assertEqual(out["transport"], {"type": "http", "path": "/h", "host": ["a.example"]})

    def test_vmess_httpupgrade_is_built(self):
        out = vmess(net="httpupgrade", path="/u", host="a.example")
        self.assertEqual(out["transport"]["type"], "httpupgrade")

    def test_vmess_tcp_with_http_header_is_h2_style(self):
        out = vmess(net="tcp", type="http", path="/x", host="a.example")
        self.assertEqual(out["transport"]["type"], "http")

    def test_vmess_tcp_without_header_is_plain(self):
        self.assertNotIn("transport", vmess(net="tcp", type="none"))

    def test_vmess_unsupported_nets_are_rejected(self):
        for net in ("kcp", "quic"):
            with self.subTest(net=net):
                with self.assertRaises(ValueError) as raised:
                    vmess(net=net)
                self.assertEqual(str(raised.exception), f"unsupported_vmess_net:{net}")


class BuildConfigTests(unittest.TestCase):
    def test_no_outbound_ships_a_null_valued_key(self):
        # `"transport": null` was previously emitted whenever _vmess_transport
        # gave up. A null key must never reach the config: sing-box decodes it
        # as an explicitly empty transport block.
        uris = [
            f"vless://{UUID}@1.2.3.4:443?security=tls&type=tcp",
            f"vless://{UUID}@1.2.3.6:443?security=tls&type=ws&path=%2F&host=a.example",
            f"vless://{UUID}@1.2.3.5:443?security=tls&type=xhttp",
        ]
        config, records, stats = build_sing_box_config(uris)
        self.assertEqual(stats["supported"], 2)
        self.assertEqual(stats["unsupported"], 1)
        for outbound in config["outbounds"]:
            nulls = [key for key, value in outbound.items() if value is None]
            self.assertEqual(nulls, [], f"{outbound.get('tag')} carries null keys: {nulls}")

    def test_each_record_gets_its_own_inbound_and_outbound(self):
        uris = [
            f"vless://{UUID}@1.2.3.4:443?security=tls",
            "hysteria2://pw@1.2.3.5:443?sni=a.example",
        ]
        config, records, _ = build_sing_box_config(uris)
        out_tags = {o["tag"] for o in config["outbounds"]}
        in_tags = {i["tag"] for i in config["inbounds"]}
        self.assertEqual(len(records), 2)
        for record in records:
            self.assertTrue(any(t.endswith(record["id"]) for t in in_tags))
            self.assertTrue(any(t.endswith(record["id"]) for t in out_tags))
        # One listener per config, and no two share a port.
        self.assertEqual(len(config["inbounds"]), len(records))
        self.assertEqual(len({r["port"] for r in records}), len(records))


if __name__ == "__main__":
    unittest.main()
