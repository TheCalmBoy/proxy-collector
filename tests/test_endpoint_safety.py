import socket
import unittest
from unittest import mock

from tools.endpoint_safety import resolve_public_endpoint


class PublicEndpointTests(unittest.TestCase):
    def setUp(self):
        resolve_public_endpoint.cache_clear()
        self.addCleanup(resolve_public_endpoint.cache_clear)

    def test_rejects_non_global_ip_literals_without_dns(self):
        for host in ("127.0.0.1", "169.254.169.254", "100.64.0.1", "::1", "fc00::1"):
            with self.subTest(host=host):
                with mock.patch("tools.endpoint_safety.socket.getaddrinfo") as lookup:
                    self.assertIsNone(resolve_public_endpoint(host))
                    lookup.assert_not_called()

    def test_public_literal_is_returned_without_dns(self):
        with mock.patch("tools.endpoint_safety.socket.getaddrinfo") as lookup:
            self.assertEqual(resolve_public_endpoint("1.1.1.1"), "1.1.1.1")
            lookup.assert_not_called()

    def test_hostname_with_any_non_global_answer_is_rejected(self):
        answers = [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.168.1.1", 0)),
        ]
        with mock.patch("tools.endpoint_safety.socket.getaddrinfo", return_value=answers):
            self.assertIsNone(resolve_public_endpoint("mixed.example"))

    def test_public_hostname_is_pinned_to_ipv4_answer(self):
        answers = [
            (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("2606:4700:4700::1111", 0, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("1.1.1.1", 0)),
        ]
        with mock.patch("tools.endpoint_safety.socket.getaddrinfo", return_value=answers):
            self.assertEqual(resolve_public_endpoint("public.example"), "1.1.1.1")


if __name__ == "__main__":
    unittest.main()
