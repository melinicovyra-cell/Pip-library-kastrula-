"""
kastrula.proxy — прокси: чекер, граббер, валидатор.
"""

from __future__ import annotations

import re
import socket
import struct
import time
import concurrent.futures
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

import httpx


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

class ProxyType(str, Enum):
    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"


class ProxyAnonymity(str, Enum):
    TRANSPARENT = "transparent"
    ANONYMOUS = "anonymous"
    ELITE = "elite"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ProxyInfo:
    """Информация о прокси."""
    host: str
    port: int
    proxy_type: ProxyType
    alive: bool = False
    latency_ms: float = 0.0
    anonymity: ProxyAnonymity = ProxyAnonymity.UNKNOWN
    country: str = ""
    external_ip: str = ""
    error: str = ""

    @property
    def url(self) -> str:
        return f"{self.proxy_type.value}://{self.host}:{self.port}"

    def __repr__(self) -> str:
        status = "✓" if self.alive else "✗"
        return f"<Proxy {status} {self.url} {self.latency_ms:.0f}ms {self.anonymity.value}>"


@dataclass
class CheckResult:
    """Результат массовой проверки прокси."""
    total: int
    alive: int
    dead: int
    proxies: list[ProxyInfo]
    check_time_ms: float

    @property
    def alive_proxies(self) -> list[ProxyInfo]:
        return [p for p in self.proxies if p.alive]

    @property
    def by_type(self) -> dict[str, list[ProxyInfo]]:
        result = {}
        for p in self.alive_proxies:
            result.setdefault(p.proxy_type.value, []).append(p)
        return result

    @property
    def fastest(self) -> Optional[ProxyInfo]:
        alive = self.alive_proxies
        return min(alive, key=lambda p: p.latency_ms) if alive else None

    def summary(self) -> str:
        lines = [f"Checked: {self.total} | Alive: {self.alive} | Dead: {self.dead}"]
        lines.append(f"Time: {self.check_time_ms:.0f}ms")
        if self.alive_proxies:
            lines.append(f"Fastest: {self.fastest.url} ({self.fastest.latency_ms:.0f}ms)")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Proxy sources for grabbing
# ---------------------------------------------------------------------------

PROXY_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
]


# ---------------------------------------------------------------------------
# Checkers
# ---------------------------------------------------------------------------

def _check_http_proxy(
    host: str,
    port: int,
    timeout: float,
    test_url: str,
) -> ProxyInfo:
    """Check HTTP/HTTPS proxy."""
    info = ProxyInfo(host=host, port=port, proxy_type=ProxyType.HTTP)

    try:
        start = time.monotonic()
        with httpx.Client(
            proxy=f"http://{host}:{port}",
            timeout=timeout,
            follow_redirects=True,
        ) as client:
            resp = client.get(test_url)

        info.latency_ms = round((time.monotonic() - start) * 1000, 2)

        if resp.status_code == 200:
            info.alive = True
            try:
                data = resp.json()
                info.external_ip = data.get("origin", data.get("ip", ""))
            except Exception:
                info.external_ip = ""

    except Exception as e:
        info.error = str(e)[:100]

    return info


def _check_socks5_proxy(
    host: str,
    port: int,
    timeout: float,
    test_url: str,
) -> ProxyInfo:
    """Check SOCKS5 proxy."""
    info = ProxyInfo(host=host, port=port, proxy_type=ProxyType.SOCKS5)

    try:
        # Basic SOCKS5 handshake check
        start = time.monotonic()
        sock = socket.create_connection((host, port), timeout=timeout)

        # Send greeting: version 5, 1 auth method (no auth)
        sock.sendall(b"\x05\x01\x00")
        resp = sock.recv(2)

        if len(resp) >= 2 and resp[0] == 0x05 and resp[1] == 0x00:
            info.alive = True
            info.latency_ms = round((time.monotonic() - start) * 1000, 2)

        sock.close()

        # If alive, try actual HTTP through SOCKS5
        if info.alive:
            try:
                with httpx.Client(
                    proxy=f"socks5://{host}:{port}",
                    timeout=timeout,
                ) as client:
                    r = client.get(test_url)
                    if r.status_code == 200:
                        data = r.json()
                        info.external_ip = data.get("origin", data.get("ip", ""))
            except Exception:
                pass

    except Exception as e:
        info.error = str(e)[:100]

    return info


def _check_socks4_proxy(
    host: str,
    port: int,
    timeout: float,
) -> ProxyInfo:
    """Check SOCKS4 proxy."""
    info = ProxyInfo(host=host, port=port, proxy_type=ProxyType.SOCKS4)

    try:
        start = time.monotonic()
        sock = socket.create_connection((host, port), timeout=timeout)

        # SOCKS4 connect request to google DNS
        target_ip = socket.inet_aton("8.8.8.8")
        request = b"\x04\x01" + struct.pack("!H", 53) + target_ip + b"\x00"
        sock.sendall(request)

        resp = sock.recv(8)
        if len(resp) >= 2 and resp[1] == 0x5A:  # Request granted
            info.alive = True
            info.latency_ms = round((time.monotonic() - start) * 1000, 2)

        sock.close()

    except Exception as e:
        info.error = str(e)[:100]

    return info


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_proxy(
    proxy: str,
    timeout: float = 10.0,
    test_url: str = "https://httpbin.org/ip",
) -> ProxyInfo:
    """
    Проверить один прокси.

    >>> info = check_proxy("http://1.2.3.4:8080")
    >>> print(info.alive, info.latency_ms)

    >>> info = check_proxy("socks5://1.2.3.4:1080")
    """
    # Parse proxy string
    proxy = proxy.strip()
    proxy_type = ProxyType.HTTP
    host_port = proxy

    if "://" in proxy:
        scheme, host_port = proxy.split("://", 1)
        scheme = scheme.lower()
        if scheme == "socks5":
            proxy_type = ProxyType.SOCKS5
        elif scheme == "socks4":
            proxy_type = ProxyType.SOCKS4
        elif scheme == "https":
            proxy_type = ProxyType.HTTPS

    parts = host_port.split(":")
    if len(parts) != 2:
        return ProxyInfo(host=host_port, port=0, proxy_type=proxy_type, error="Invalid format")

    host = parts[0]
    try:
        port = int(parts[1])
    except ValueError:
        return ProxyInfo(host=host, port=0, proxy_type=proxy_type, error="Invalid port")

    if proxy_type == ProxyType.SOCKS5:
        return _check_socks5_proxy(host, port, timeout, test_url)
    elif proxy_type == ProxyType.SOCKS4:
        return _check_socks4_proxy(host, port, timeout)
    else:
        return _check_http_proxy(host, port, timeout, test_url)


def check_proxies(
    proxies: list[str],
    timeout: float = 10.0,
    threads: int = 20,
    test_url: str = "https://httpbin.org/ip",
    on_result: Optional[callable] = None,
) -> CheckResult:
    """
    Массовая проверка прокси.

    >>> proxies = ["http://1.2.3.4:8080", "socks5://5.6.7.8:1080"]
    >>> result = check_proxies(proxies)
    >>> print(result.summary())
    >>> for p in result.alive_proxies:
    ...     print(p.url, p.latency_ms)
    """
    start = time.monotonic()
    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(check_proxy, p, timeout, test_url): p
            for p in proxies
        }

        for future in concurrent.futures.as_completed(futures):
            try:
                info = future.result()
                results.append(info)
                if on_result:
                    on_result(info)
            except Exception:
                pass

    elapsed = (time.monotonic() - start) * 1000
    alive_count = sum(1 for p in results if p.alive)

    return CheckResult(
        total=len(proxies),
        alive=alive_count,
        dead=len(results) - alive_count,
        proxies=results,
        check_time_ms=round(elapsed, 2),
    )


def grab_proxies(
    sources: Optional[list[str]] = None,
    timeout: float = 15.0,
    proxy_type: Optional[ProxyType] = None,
) -> list[str]:
    """
    Собрать прокси из открытых источников.

    >>> proxies = grab_proxies()
    >>> print(f"Найдено: {len(proxies)}")

    >>> # Только SOCKS5
    >>> socks = grab_proxies(proxy_type=ProxyType.SOCKS5)
    """
    if sources is None:
        sources = PROXY_SOURCES.copy()
        if proxy_type:
            # Filter sources by type
            type_str = proxy_type.value
            sources = [s for s in sources if type_str in s.lower()]
            if not sources:
                sources = PROXY_SOURCES

    all_proxies = set()

    for url in sources:
        try:
            resp = httpx.get(url, timeout=timeout, follow_redirects=True)
            if resp.status_code == 200:
                lines = resp.text.strip().split("\n")
                for line in lines:
                    line = line.strip()
                    # Validate format: ip:port
                    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}$", line):
                        all_proxies.add(line)
        except Exception:
            pass

    result = sorted(all_proxies)

    # Add scheme prefix based on source
    if proxy_type:
        result = [f"{proxy_type.value}://{p}" for p in result]

    return result


def grab_and_check(
    max_grab: int = 200,
    timeout: float = 10.0,
    threads: int = 30,
    proxy_type: Optional[ProxyType] = None,
) -> CheckResult:
    """
    Граббить и сразу проверить прокси.

    >>> result = grab_and_check(max_grab=100, threads=50)
    >>> print(result.summary())
    >>> for p in result.alive_proxies[:10]:
    ...     print(p)
    """
    proxies = grab_proxies(proxy_type=proxy_type, timeout=15.0)

    if len(proxies) > max_grab:
        import random
        proxies = random.sample(proxies, max_grab)

    # Add http:// prefix if missing
    prefixed = []
    for p in proxies:
        if "://" not in p:
            prefixed.append(f"http://{p}")
        else:
            prefixed.append(p)

    return check_proxies(prefixed, timeout=timeout, threads=threads)
