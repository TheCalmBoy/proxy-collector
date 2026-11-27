"""Resolve proxy endpoints safely before the probe process opens sockets."""

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache


@lru_cache(maxsize=16_384)
def resolve_public_endpoint(host: str) -> str | None:
    """Return a globally routable address, or None for unsafe/unresolved hosts.

    Reject the entire hostname if any DNS answer is not globally routable. The
    caller pins the returned address into the probe config, preventing a second
    DNS lookup from changing the destination between validation and connect.
    """
    host = str(host or "").strip().strip("[]")
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


def prewarm_public_endpoints(hosts: list[str], workers: int = 32) -> None:
    """Resolve distinct feed hosts concurrently before building probe configs."""
    unique = sorted({str(host).strip() for host in hosts if host})
    if not unique:
        return
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(unique)))) as pool:
        list(pool.map(resolve_public_endpoint, unique))
