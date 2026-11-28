import os
import socket
import threading
import time
import unittest
from unittest import mock

from tools.endpoint_safety import (
    PREWARM_TIMEOUT_ENV,
    prewarm_public_endpoints,
    resolve_public_endpoint,
)


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


class PrewarmDeadlineTests(unittest.TestCase):
    def setUp(self):
        resolve_public_endpoint.cache_clear()
        self.addCleanup(resolve_public_endpoint.cache_clear)

    def test_hung_resolver_returns_at_deadline_and_host_stays_unresolved(self):
        entered = threading.Event()
        release = threading.Event()
        finished = threading.Event()

        def hanging_resolver(*args, **kwargs):
            entered.set()
            release.wait()
            finished.set()
            return [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("1.1.1.1", 0)),
            ]

        started = time.monotonic()
        try:
            with mock.patch.dict(os.environ, {PREWARM_TIMEOUT_ENV: "0.05"}), mock.patch(
                "tools.endpoint_safety.socket.getaddrinfo", side_effect=hanging_resolver
            ):
                prewarm_public_endpoints(["stuck.example"], workers=1)
                elapsed = time.monotonic() - started

                self.assertTrue(entered.wait(1))
                self.assertLess(elapsed, 0.5)
                self.assertIsNone(resolve_public_endpoint("stuck.example"))
        finally:
            release.set()
        self.assertTrue(finished.wait(1))
        # A resolver that returns after the deadline cannot make the host
        # usable again during this run.
        self.assertIsNone(resolve_public_endpoint("stuck.example"))


if __name__ == "__main__":
    unittest.main()
