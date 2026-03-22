"""
kastrula.trace — трассировка маршрута: ICMP, UDP, TCP.
"""

from __future__ import annotations

import socket
import struct
import time
import select
from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class Hop:
    """Один хоп трассировки."""
    ttl: int
    ip: Optional[str]
    hostname: Optional[str]
    rtt_ms: float
    reached: bool

    @property
    def display(self) -> str:
        if not self.ip:
            return f"{self.ttl:>2}  *  timeout"
        host = self.hostname or self.ip
        return f"{self.ttl:>2}  {host} ({self.ip})  {self.rtt_ms:.1f}ms"


@dataclass
class TraceResult:
    """Результат трассировки."""
    target: str
    target_ip: str
    hops: list[Hop]
    reached: bool
    total_ms: float

    def summary(self) -> str:
        lines = [f"traceroute to {self.target} ({self.target_ip})"]
        for hop in self.hops:
            lines.append(hop.display)
        if self.reached:
            lines.append(f"\n✓ Target reached in {len(self.hops)} hops ({self.total_ms:.0f}ms)")
        else:
            lines.append(f"\n✗ Target not reached after {len(self.hops)} hops")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Resolve helper
# ---------------------------------------------------------------------------

def _resolve_hostname(ip: str) -> Optional[str]:
    """Try to resolve IP to hostname."""
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror, OSError):
        return None


# ---------------------------------------------------------------------------
# UDP traceroute (works without root on most systems)
# ---------------------------------------------------------------------------

def _trace_udp_hop(
    target_ip: str,
    ttl: int,
    port: int,
    timeout: float,
) -> Hop:
    """Send one UDP probe with given TTL."""
    dest_port = port + ttl  # vary port to avoid firewall caching

    try:
        # Create UDP socket for sending
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        send_sock.settimeout(timeout)

        # Create ICMP socket for receiving TTL exceeded
        try:
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            recv_sock.settimeout(timeout)
            use_icmp = True
        except PermissionError:
            # No raw socket permission — fallback to error from UDP
            recv_sock = None
            use_icmp = False

        start = time.monotonic()
        send_sock.sendto(b"\x00" * 32, (target_ip, dest_port))

        ip_addr = None

        if use_icmp and recv_sock:
            try:
                ready = select.select([recv_sock], [], [], timeout)
                if ready[0]:
                    data, addr = recv_sock.recvfrom(1024)
                    ip_addr = addr[0]
            except Exception:
                pass
            recv_sock.close()
        else:
            # Fallback: try to detect via UDP error
            try:
                send_sock.recvfrom(1024)
            except socket.timeout:
                pass
            except OSError:
                pass

        rtt = (time.monotonic() - start) * 1000
        send_sock.close()

        reached = ip_addr == target_ip if ip_addr else False
        hostname = _resolve_hostname(ip_addr) if ip_addr else None

        return Hop(ttl=ttl, ip=ip_addr, hostname=hostname, rtt_ms=round(rtt, 2), reached=reached)

    except Exception:
        return Hop(ttl=ttl, ip=None, hostname=None, rtt_ms=0, reached=False)


# ---------------------------------------------------------------------------
# TCP traceroute (SYN, works on more platforms)
# ---------------------------------------------------------------------------

def _trace_tcp_hop(
    target_ip: str,
    ttl: int,
    port: int,
    timeout: float,
) -> Hop:
    """Send one TCP SYN probe with given TTL."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        sock.settimeout(timeout)

        start = time.monotonic()
        result = sock.connect_ex((target_ip, port))
        rtt = (time.monotonic() - start) * 1000

        # Get peer address if connected
        try:
            peer = sock.getpeername()
            ip_addr = peer[0]
        except Exception:
            ip_addr = None

        sock.close()

        if result == 0:
            # Connected — we reached the target
            hostname = _resolve_hostname(target_ip)
            return Hop(ttl=ttl, ip=target_ip, hostname=hostname, rtt_ms=round(rtt, 2), reached=True)
        else:
            return Hop(ttl=ttl, ip=None, hostname=None, rtt_ms=round(rtt, 2), reached=False)

    except socket.timeout:
        return Hop(ttl=ttl, ip=None, hostname=None, rtt_ms=0, reached=False)
    except OSError as e:
        # Connection refused or network unreachable — might still give us IP
        rtt = 0
        return Hop(ttl=ttl, ip=None, hostname=None, rtt_ms=rtt, reached=False)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def traceroute(
    target: str,
    max_hops: int = 30,
    timeout: float = 2.0,
    method: str = "udp",
    port: int = 33434,
    resolve_hosts: bool = True,
) -> TraceResult:
    """
    Трассировка маршрута к хосту.

    >>> result = traceroute("google.com")
    >>> print(result.summary())

    >>> # TCP трассировка на порт 443
    >>> result = traceroute("github.com", method="tcp", port=443)

    Методы: "udp" (по умолчанию), "tcp"
    UDP требует ICMP raw socket (root на Linux, работает на Android).
    TCP работает без root.
    """
    # Resolve target
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        return TraceResult(
            target=target, target_ip="unresolved",
            hops=[], reached=False, total_ms=0,
        )

    hops = []
    total_start = time.monotonic()
    reached = False

    for ttl in range(1, max_hops + 1):
        if method == "tcp":
            hop = _trace_tcp_hop(target_ip, ttl, port, timeout)
        else:
            hop = _trace_udp_hop(target_ip, ttl, port, timeout)

        # Resolve hostname if needed
        if hop.ip and not hop.hostname and resolve_hosts:
            hop.hostname = _resolve_hostname(hop.ip)

        hops.append(hop)

        if hop.reached or hop.ip == target_ip:
            reached = True
            break

    total_ms = (time.monotonic() - total_start) * 1000

    return TraceResult(
        target=target,
        target_ip=target_ip,
        hops=hops,
        reached=reached,
        total_ms=round(total_ms, 2),
    )


def tcp_traceroute(
    target: str,
    port: int = 443,
    max_hops: int = 30,
    timeout: float = 2.0,
) -> TraceResult:
    """
    TCP трассировка (работает без root).

    >>> result = tcp_traceroute("github.com", port=443)
    >>> print(result.summary())
    """
    return traceroute(target, max_hops=max_hops, timeout=timeout, method="tcp", port=port)
