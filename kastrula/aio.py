"""
kastrula.aio — asyncio версии всех модулей kastrula.

>>> import asyncio
>>> from kastrula.aio import resolve, grab_cert, port_scan, check_proxy
>>>
>>> async def main():
...     ips = await resolve("google.com")
...     cert = await grab_cert("github.com")
...     scan = await port_scan("example.com", ports=[80, 443])
...     print(ips, cert.subject, scan.open_ports)
>>>
>>> asyncio.run(main())
"""

from __future__ import annotations

import asyncio
import socket
import ssl
import time
from typing import Optional
from concurrent.futures import ThreadPoolExecutor


# Default thread pool for wrapping sync operations
_pool = ThreadPoolExecutor(max_workers=50)


async def _run_sync(func, *args, **kwargs):
    """Run synchronous function in thread pool."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_pool, lambda: func(*args, **kwargs))


# ---------------------------------------------------------------------------
# Async DNS
# ---------------------------------------------------------------------------

async def resolve(
    domain: str,
    qtype: str = "A",
    server: str = "8.8.8.8",
    timeout: float = 5.0,
) -> list[str]:
    """
    Async DNS resolve.

    >>> ips = await resolve("google.com")
    """
    from kastrula.dns import resolve as _resolve
    return await _run_sync(_resolve, domain, qtype, server, timeout)


async def dns_records(
    domain: str,
    types: Optional[list[str]] = None,
    server: str = "8.8.8.8",
    timeout: float = 5.0,
) -> list:
    """Async DNS records lookup."""
    from kastrula.dns import dns_records as _dns_records
    return await _run_sync(_dns_records, domain, types, server, timeout)


async def doh_resolve(
    domain: str,
    qtype: str = "A",
    server: str = "https://cloudflare-dns.com/dns-query",
    timeout: float = 5.0,
) -> list[str]:
    """Async DNS over HTTPS."""
    from kastrula.dns import doh_resolve as _doh
    return await _run_sync(_doh, domain, qtype, server, timeout)


async def dot_resolve(
    domain: str,
    qtype: str = "A",
    server: str = "1.1.1.1",
    timeout: float = 5.0,
) -> list[str]:
    """Async DNS over TLS."""
    from kastrula.dns import dot_resolve as _dot
    return await _run_sync(_dot, domain, qtype, server, timeout)


# ---------------------------------------------------------------------------
# Async TLS
# ---------------------------------------------------------------------------

async def grab_cert(host: str, port: int = 443, timeout: float = 10.0):
    """
    Async TLS cert grab.

    >>> cert = await grab_cert("google.com")
    >>> print(cert.subject, cert.days_left())
    """
    from kastrula.tls import grab_cert as _grab
    return await _run_sync(_grab, host, port, timeout)


async def tls_handshake(host: str, port: int = 443, timeout: float = 10.0):
    """Async TLS handshake probe."""
    from kastrula.tls import TLSProbe
    probe = TLSProbe(host, port, timeout)
    return await _run_sync(probe.handshake)


async def ja3_fingerprint(host: str, port: int = 443, timeout: float = 10.0):
    """Async JA3 fingerprint."""
    from kastrula.tls import ja3_fingerprint as _ja3
    return await _run_sync(_ja3, host, port, timeout)


async def jarm_fingerprint(host: str, port: int = 443, timeout: float = 5.0):
    """Async JARM fingerprint."""
    from kastrula.tls import jarm_fingerprint as _jarm
    return await _run_sync(_jarm, host, port, timeout)


async def cipher_enum(host: str, port: int = 443, timeout: float = 5.0):
    """Async cipher enumeration."""
    from kastrula.tls import cipher_enum as _enum
    return await _run_sync(_enum, host, port, timeout)


# ---------------------------------------------------------------------------
# Async Scan
# ---------------------------------------------------------------------------

async def port_scan(
    host: str,
    ports: Optional[list[int]] = None,
    timeout: float = 2.0,
    threads: int = 50,
):
    """
    Async port scan.

    >>> result = await port_scan("example.com", ports=[22, 80, 443])
    >>> print(result.summary())
    """
    from kastrula.scan import port_scan as _scan
    return await _run_sync(_scan, host, ports, 100, timeout, threads)


async def udp_scan(
    host: str,
    ports: Optional[list[int]] = None,
    timeout: float = 3.0,
):
    """Async UDP scan."""
    from kastrula.scan import udp_scan as _udp
    return await _run_sync(_udp, host, ports, timeout)


async def os_fingerprint(host: str, port: int = 80, timeout: float = 5.0):
    """Async OS fingerprint."""
    from kastrula.scan import os_fingerprint as _os
    return await _run_sync(_os, host, port, timeout)


async def run_scripts(host: str, ports: Optional[list[int]] = None):
    """Async NSE scripts."""
    from kastrula.scan import run_scripts as _scripts
    return await _run_sync(_scripts, host, ports)


# ---------------------------------------------------------------------------
# Async HTTP
# ---------------------------------------------------------------------------

async def http_get(url: str, profile: str = "chrome_120", **kwargs):
    """
    Async HTTP GET with browser profile.

    >>> resp = await http_get("https://httpbin.org/ip")
    >>> print(resp.json())
    """
    from kastrula.http import KastClient
    client = KastClient(profile=profile, **kwargs)
    resp = await _run_sync(client.get, url)
    client.close()
    return resp


async def http_post(url: str, profile: str = "chrome_120", **kwargs):
    """Async HTTP POST."""
    from kastrula.http import KastClient
    client = KastClient(profile=profile)
    resp = await _run_sync(client.post, url, **kwargs)
    client.close()
    return resp


# ---------------------------------------------------------------------------
# Async WHOIS
# ---------------------------------------------------------------------------

async def whois(domain: str, timeout: float = 10.0):
    """
    Async WHOIS lookup.

    >>> info = await whois("google.com")
    >>> print(info.registrar, info.nameservers)
    """
    from kastrula.whois import whois as _whois
    return await _run_sync(_whois, domain, timeout)


async def ip_whois(ip: str, timeout: float = 10.0):
    """Async IP WHOIS."""
    from kastrula.whois import ip_whois as _ip_whois
    return await _run_sync(_ip_whois, ip, timeout)


# ---------------------------------------------------------------------------
# Async Traceroute
# ---------------------------------------------------------------------------

async def traceroute(
    target: str,
    max_hops: int = 30,
    timeout: float = 2.0,
    method: str = "tcp",
    port: int = 443,
):
    """
    Async traceroute.

    >>> result = await traceroute("google.com")
    >>> print(result.summary())
    """
    from kastrula.trace import traceroute as _trace
    return await _run_sync(_trace, target, max_hops, timeout, method, port)


# ---------------------------------------------------------------------------
# Async Proxy
# ---------------------------------------------------------------------------

async def check_proxy(proxy: str, timeout: float = 10.0):
    """
    Async proxy check.

    >>> info = await check_proxy("http://1.2.3.4:8080")
    """
    from kastrula.proxy import check_proxy as _check
    return await _run_sync(_check, proxy, timeout)


async def check_proxies(proxies: list[str], timeout: float = 10.0, threads: int = 20):
    """Async mass proxy check."""
    from kastrula.proxy import check_proxies as _check_all
    return await _run_sync(_check_all, proxies, timeout, threads)


async def grab_proxies(**kwargs):
    """Async proxy grabber."""
    from kastrula.proxy import grab_proxies as _grab
    return await _run_sync(_grab, **kwargs)


# ---------------------------------------------------------------------------
# Async WebSocket
# ---------------------------------------------------------------------------

async def ws_sniff(url: str, duration: float = 10.0, **kwargs):
    """
    Async WebSocket sniff.

    >>> session = await ws_sniff("wss://stream.binance.com:9443/ws/btcusdt@trade", duration=5)
    """
    from kastrula.ws import ws_sniff as _sniff
    return await _run_sync(_sniff, url, duration, **kwargs)


# ---------------------------------------------------------------------------
# Batch operations
# ---------------------------------------------------------------------------

async def multi_resolve(domains: list[str], qtype: str = "A") -> dict[str, list[str]]:
    """
    Резолвить несколько доменов параллельно.

    >>> results = await multi_resolve(["google.com", "github.com", "example.com"])
    >>> for domain, ips in results.items():
    ...     print(f"{domain}: {ips}")
    """
    tasks = {domain: resolve(domain, qtype) for domain in domains}
    results = {}
    for domain, task in tasks.items():
        try:
            results[domain] = await task
        except Exception:
            results[domain] = []
    return results


async def multi_scan(hosts: list[str], ports: Optional[list[int]] = None) -> list:
    """
    Сканировать несколько хостов параллельно.

    >>> results = await multi_scan(["host1.com", "host2.com"], ports=[80, 443])
    """
    tasks = [port_scan(host, ports) for host in hosts]
    return await asyncio.gather(*tasks, return_exceptions=True)


async def full_recon(target: str) -> dict:
    """
    Полная разведка цели — всё параллельно.

    >>> data = await full_recon("example.com")
    >>> print(data.keys())  # dns, tls, ports, whois, http
    """
    results = {}

    tasks = {
        "dns": dns_records(target),
        "tls": grab_cert(target),
        "ports": port_scan(target),
        "whois": whois(target),
        "http": http_get(f"https://{target}"),
    }

    for name, task in tasks.items():
        try:
            results[name] = await task
        except Exception as e:
            results[name] = {"error": str(e)}

    return results
