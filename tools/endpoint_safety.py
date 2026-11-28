"""Resolve proxy endpoints safely before the probe process opens sockets."""

from __future__ import annotations

import ipaddress
import math
import os
import queue
import socket
import threading
import time
from functools import lru_cache

PREWARM_TIMEOUT_ENV = "ENDPOINT_PREWARM_TIMEOUT_SECONDS"
DEFAULT_PREWARM_TIMEOUT_SECONDS = 60.0
_PREWARM_UNRESOLVED: set[str] = set()
_PREWARM_UNRESOLVED_LOCK = threading.Lock()


def resolve_public_endpoint(host: str) -> str | None:
    """Return a pinned public address, or None when this host is unresolved."""
    normalized = str(host or "").strip().strip("[]")
    with _PREWARM_UNRESOLVED_LOCK:
        if normalized in _PREWARM_UNRESOLVED:
            return None
    return _resolve_public_endpoint(normalized)


@lru_cache(maxsize=16_384)
def _resolve_public_endpoint(host: str) -> str | None:
    """Return a globally routable address, or None for unsafe/unresolved hosts.

    Reject the entire hostname if any DNS answer is not globally routable. The
    caller pins the returned address into the probe config, preventing a second
    DNS lookup from changing the destination between validation and connect.
    """
    if not host or len(host) > 253 or not host.isascii():
        return None
    if any(len(label) > 63 for label in host.split(".")):
        return None

    try:
        address = ipaddress.ip_address(host)
        return str(address) if address.is_global else None
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError, ValueError):
        return None

    addresses: set[str] = set()
    for info in infos:
        sockaddr = info[4]
        if sockaddr:
            addresses.add(sockaddr[0])
    if not addresses:
        return None

    parsed: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    try:
        parsed = [ipaddress.ip_address(value) for value in addresses]
    except ValueError:
        return None
    if any(not address.is_global for address in parsed):
        return None

    parsed.sort(key=lambda address: (address.version != 4, int(address)))
    return str(parsed[0])


def _clear_resolution_cache() -> None:
    _resolve_public_endpoint.cache_clear()
    with _PREWARM_UNRESOLVED_LOCK:
        _PREWARM_UNRESOLVED.clear()


# Preserve the cache-clear hook used by tests and local diagnostics.
resolve_public_endpoint.cache_clear = _clear_resolution_cache


def prewarm_public_endpoints(hosts: list[str], workers: int = 32) -> None:
    """Resolve hosts concurrently, with a bounded wait and nonblocking shutdown.

    DNS resolver calls cannot be cancelled safely once started. Workers are
    daemon threads, and hosts still in flight at the overall deadline are
    latched as unresolved so the later config-building pass will skip them.
    """
    unique = sorted({str(host).strip() for host in hosts if host})
    if not unique:
        return

    try:
        timeout = float(os.environ.get(PREWARM_TIMEOUT_ENV, DEFAULT_PREWARM_TIMEOUT_SECONDS))
    except (TypeError, ValueError):
        timeout = DEFAULT_PREWARM_TIMEOUT_SECONDS
    if not math.isfinite(timeout) or timeout < 0:
        timeout = DEFAULT_PREWARM_TIMEOUT_SECONDS
    if timeout == 0:
        with _PREWARM_UNRESOLVED_LOCK:
            _PREWARM_UNRESOLVED.update(unique)
        return

    deadline = time.monotonic() + timeout
    pending: queue.Queue[str] = queue.Queue()
    for host in unique:
        pending.put(host)
    completed: set[str] = set()
    completed_lock = threading.Lock()

    def resolve_hosts() -> None:
        while time.monotonic() < deadline:
            try:
                host = pending.get_nowait()
            except queue.Empty:
                return
            try:
                resolve_public_endpoint(host)
            except Exception:
                # One resolver failure must not prevent the other hosts from
                # using the remaining prewarm budget.
                pass
            finally:
                with completed_lock:
                    completed.add(host)
                pending.task_done()

    thread_count = max(1, min(workers, len(unique)))
    threads = [
        threading.Thread(target=resolve_hosts, name="endpoint-dns-prewarm", daemon=True)
        for _ in range(thread_count)
    ]
    for thread in threads:
        thread.start()

    for thread in threads:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        thread.join(remaining)

    with completed_lock:
        unfinished = set(unique) - completed
    if unfinished:
        with _PREWARM_UNRESOLVED_LOCK:
            _PREWARM_UNRESOLVED.update(unfinished)
