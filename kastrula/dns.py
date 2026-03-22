"""
kastrula.dns — DNS-утилиты: резолвинг, записи, reverse lookup.
"""

from __future__ import annotations

import socket
import struct
import random
from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class DNSRecord:
    """Одна DNS-запись."""
    name: str
    rtype: str
    ttl: int
    value: str


@dataclass
class LookupResult:
    """Результат полного DNS lookup."""
    domain: str
    records: list[DNSRecord]
    nameservers: list[str]
    response_time_ms: float


# ---------------------------------------------------------------------------
# Low-level DNS packet builder/parser (no external deps)
# ---------------------------------------------------------------------------

# Record type codes
QTYPES = {
    "A": 1, "AAAA": 28, "CNAME": 5, "MX": 15, "NS": 2,
    "TXT": 16, "SOA": 6, "PTR": 12, "SRV": 33, "CAA": 257,
}
QTYPES_REV = {v: k for k, v in QTYPES.items()}


def _build_query(domain: str, qtype: int) -> bytes:
    """Build a raw DNS query packet."""
    txn_id = random.randint(0, 0xFFFF)
    flags = 0x0100  # standard query, recursion desired
    header = struct.pack("!HHHHHH", txn_id, flags, 1, 0, 0, 0)

    question = b""
    for label in domain.rstrip(".").split("."):
        question += struct.pack("!B", len(label)) + label.encode()
    question += b"\x00"
    question += struct.pack("!HH", qtype, 1)  # QTYPE, QCLASS=IN

    return header + question


def _parse_name(data: bytes, offset: int) -> tuple[str, int]:
    """Parse a DNS compressed name. Returns (name, new_offset)."""
    labels = []
    jumped = False
    original_offset = offset
    max_jumps = 20
    jumps = 0

    while True:
        if offset >= len(data):
            break
        length = data[offset]

        if (length & 0xC0) == 0xC0:
            if not jumped:
                original_offset = offset + 2
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            offset = pointer
            jumped = True
            jumps += 1
            if jumps > max_jumps:
                break
            continue

        if length == 0:
            offset += 1
            break

        offset += 1
        labels.append(data[offset:offset + length].decode(errors="replace"))
        offset += length

    name = ".".join(labels)
    return name, original_offset if jumped else offset


def _parse_response(data: bytes, domain: str) -> list[DNSRecord]:
    """Parse DNS response packet into records."""
    if len(data) < 12:
        return []

    _, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    offset = 12

    # Skip questions
    for _ in range(qdcount):
        _, offset = _parse_name(data, offset)
        offset += 4  # QTYPE + QCLASS

    records = []
    total = ancount + nscount + arcount

    for _ in range(total):
        if offset >= len(data):
            break

        name, offset = _parse_name(data, offset)
        if offset + 10 > len(data):
            break

        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10

        if offset + rdlength > len(data):
            break

        rdata = data[offset:offset + rdlength]
        offset += rdlength

        type_str = QTYPES_REV.get(rtype, f"TYPE{rtype}")
        value = _decode_rdata(rtype, rdata, data, offset - rdlength)

        records.append(DNSRecord(name=name, rtype=type_str, ttl=ttl, value=value))

    return records


def _decode_rdata(rtype: int, rdata: bytes, full_data: bytes, rdata_offset: int) -> str:
    """Decode RDATA based on record type."""
    if rtype == 1 and len(rdata) == 4:  # A
        return socket.inet_ntoa(rdata)
    elif rtype == 28 and len(rdata) == 16:  # AAAA
        return socket.inet_ntop(socket.AF_INET6, rdata)
    elif rtype in (2, 5, 12):  # NS, CNAME, PTR
        name, _ = _parse_name(full_data, rdata_offset)
        return name
    elif rtype == 15:  # MX
        priority = struct.unpack("!H", rdata[:2])[0]
        name, _ = _parse_name(full_data, rdata_offset + 2)
        return f"{priority} {name}"
    elif rtype == 16:  # TXT
        texts = []
        pos = 0
        while pos < len(rdata):
            txt_len = rdata[pos]
            pos += 1
            texts.append(rdata[pos:pos + txt_len].decode(errors="replace"))
            pos += txt_len
        return " ".join(texts)
    elif rtype == 6:  # SOA
        mname, pos = _parse_name(full_data, rdata_offset)
        rname, pos = _parse_name(full_data, pos)
        if pos + 20 <= len(full_data):
            serial, refresh, retry, expire, minimum = struct.unpack(
                "!IIIII", full_data[pos:pos + 20]
            )
            return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
        return f"{mname} {rname}"
    elif rtype == 33:  # SRV
        if len(rdata) >= 6:
            priority, weight, port = struct.unpack("!HHH", rdata[:6])
            target, _ = _parse_name(full_data, rdata_offset + 6)
            return f"{priority} {weight} {port} {target}"
    return rdata.hex()


def _query_dns(
    domain: str,
    qtype: str = "A",
    server: str = "8.8.8.8",
    port: int = 53,
    timeout: float = 5.0,
) -> list[DNSRecord]:
    """Send DNS query and parse response."""
    qtype_code = QTYPES.get(qtype.upper(), 1)
    packet = _build_query(domain, qtype_code)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, port))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()

    return _parse_response(data, domain)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def resolve(
    domain: str,
    qtype: str = "A",
    server: str = "8.8.8.8",
    timeout: float = 5.0,
) -> list[str]:
    """
    Резолвить домен, вернуть список значений.

    >>> resolve("google.com")
    ['142.250.x.x', ...]
    >>> resolve("google.com", "AAAA")
    ['2a00:1450:...']
    >>> resolve("google.com", "MX")
    ['10 smtp.google.com', ...]
    """
    records = _query_dns(domain, qtype, server, timeout=timeout)
    return [r.value for r in records if r.rtype == qtype.upper()]


def dns_records(
    domain: str,
    types: Optional[list[str]] = None,
    server: str = "8.8.8.8",
    timeout: float = 5.0,
) -> list[DNSRecord]:
    """
    Получить DNS-записи нескольких типов.

    >>> records = dns_records("github.com", ["A", "AAAA", "MX", "NS", "TXT"])
    >>> for r in records:
    ...     print(f"{r.rtype:6} {r.ttl:>6}s  {r.value}")
    """
    if types is None:
        types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

    all_records = []
    for qtype in types:
        try:
            recs = _query_dns(domain, qtype, server, timeout=timeout)
            all_records.extend(recs)
        except Exception:
            pass
    return all_records


def lookup(
    domain: str,
    server: str = "8.8.8.8",
    timeout: float = 5.0,
) -> LookupResult:
    """
    Полный DNS lookup: все основные записи + время ответа.

    >>> result = lookup("example.com")
    >>> print(f"{result.domain}: {len(result.records)} records, {result.response_time_ms:.1f}ms")
    """
    import time

    types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]
    all_records = []
    nameservers = []

    start = time.monotonic()
    for qtype in types:
        try:
            recs = _query_dns(domain, qtype, server, timeout=timeout)
            for r in recs:
                all_records.append(r)
                if r.rtype == "NS":
                    nameservers.append(r.value)
        except Exception:
            pass
    elapsed = (time.monotonic() - start) * 1000

    return LookupResult(
        domain=domain,
        records=all_records,
        nameservers=list(set(nameservers)),
        response_time_ms=round(elapsed, 2),
    )


def reverse_lookup(
    ip: str,
    server: str = "8.8.8.8",
    timeout: float = 5.0,
) -> list[str]:
    """
    Обратный DNS lookup (PTR).

    >>> reverse_lookup("8.8.8.8")
    ['dns.google']
    """
    parts = ip.split(".")
    if len(parts) == 4:
        # IPv4
        ptr_domain = ".".join(reversed(parts)) + ".in-addr.arpa"
    else:
        # Попробуем как IPv6
        import ipaddress
        addr = ipaddress.ip_address(ip)
        nibbles = addr.exploded.replace(":", "")
        ptr_domain = ".".join(reversed(nibbles)) + ".ip6.arpa"

    records = _query_dns(ptr_domain, "PTR", server, timeout=timeout)
    return [r.value for r in records if r.rtype == "PTR"]


# ---------------------------------------------------------------------------
# DNS Cache
# ---------------------------------------------------------------------------

import time as _time
import threading


class DNSCache:
    """
    Простой in-memory DNS кэш с TTL.

    >>> cache = DNSCache()
    >>> cache.put("google.com", "A", ["1.2.3.4"], ttl=300)
    >>> cache.get("google.com", "A")
    ['1.2.3.4']
    """

    def __init__(self):
        self._store: dict[str, tuple[list, float]] = {}
        self._lock = threading.Lock()

    def _key(self, domain: str, qtype: str) -> str:
        return f"{domain.lower()}:{qtype.upper()}"

    def get(self, domain: str, qtype: str) -> Optional[list[str]]:
        key = self._key(domain, qtype)
        with self._lock:
            if key in self._store:
                values, expires = self._store[key]
                if _time.time() < expires:
                    return values
                else:
                    del self._store[key]
        return None

    def put(self, domain: str, qtype: str, values: list[str], ttl: int = 300) -> None:
        key = self._key(domain, qtype)
        with self._lock:
            self._store[key] = (values, _time.time() + ttl)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def stats(self) -> dict:
        with self._lock:
            now = _time.time()
            total = len(self._store)
            alive = sum(1 for _, (_, exp) in self._store.items() if now < exp)
            return {"total": total, "alive": alive, "expired": total - alive}

    def __len__(self) -> int:
        return len(self._store)


# Global cache instance
_global_cache = DNSCache()


def cached_resolve(
    domain: str,
    qtype: str = "A",
    server: str = "8.8.8.8",
    timeout: float = 5.0,
    cache: Optional[DNSCache] = None,
) -> list[str]:
    """
    Резолвить с кэшированием.

    >>> ips = cached_resolve("google.com")  # первый раз — запрос
    >>> ips = cached_resolve("google.com")  # из кэша
    """
    c = cache or _global_cache
    cached = c.get(domain, qtype)
    if cached is not None:
        return cached

    values = resolve(domain, qtype, server, timeout)
    if values:
        c.put(domain, qtype, values)
    return values


# ---------------------------------------------------------------------------
# DNS over HTTPS (DoH)
# ---------------------------------------------------------------------------

def doh_resolve(
    domain: str,
    qtype: str = "A",
    server: str = "https://cloudflare-dns.com/dns-query",
    timeout: float = 5.0,
) -> list[str]:
    """
    DNS-запрос через HTTPS (DoH).

    Серверы:
    - https://cloudflare-dns.com/dns-query (Cloudflare)
    - https://dns.google/dns-query (Google)
    - https://dns.quad9.net/dns-query (Quad9)

    >>> ips = doh_resolve("google.com")
    >>> mx = doh_resolve("gmail.com", "MX")
    """
    import httpx

    qtype_code = QTYPES.get(qtype.upper(), 1)
    packet = _build_query(domain, qtype_code)

    # Wireformat POST
    resp = httpx.post(
        server,
        content=packet,
        headers={
            "Content-Type": "application/dns-message",
            "Accept": "application/dns-message",
        },
        timeout=timeout,
    )

    if resp.status_code != 200:
        raise RuntimeError(f"DoH error: HTTP {resp.status_code}")

    records = _parse_response(resp.content, domain)
    return [r.value for r in records if r.rtype == qtype.upper()]


def doh_json_resolve(
    domain: str,
    qtype: str = "A",
    server: str = "https://cloudflare-dns.com/dns-query",
    timeout: float = 5.0,
) -> list[dict]:
    """
    DoH запрос с JSON ответом (Cloudflare/Google формат).

    >>> records = doh_json_resolve("google.com")
    >>> for r in records:
    ...     print(r["type"], r["data"])
    """
    import httpx

    params = {"name": domain, "type": qtype}
    resp = httpx.get(
        server,
        params=params,
        headers={"Accept": "application/dns-json"},
        timeout=timeout,
    )

    if resp.status_code != 200:
        raise RuntimeError(f"DoH JSON error: HTTP {resp.status_code}")

    data = resp.json()
    answers = data.get("Answer", [])
    return answers


# ---------------------------------------------------------------------------
# DNS over TLS (DoT)
# ---------------------------------------------------------------------------

def dot_resolve(
    domain: str,
    qtype: str = "A",
    server: str = "1.1.1.1",
    port: int = 853,
    timeout: float = 5.0,
) -> list[str]:
    """
    DNS-запрос через TLS (DoT, порт 853).

    >>> ips = dot_resolve("google.com")
    >>> ips = dot_resolve("google.com", server="8.8.8.8")
    """
    import ssl

    qtype_code = QTYPES.get(qtype.upper(), 1)
    packet = _build_query(domain, qtype_code)

    # DoT uses TCP with TLS, DNS message prefixed with 2-byte length
    length_prefix = struct.pack("!H", len(packet))

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    sock = socket.create_connection((server, port), timeout=timeout)
    ssock = ctx.wrap_socket(sock, server_hostname=server)

    ssock.sendall(length_prefix + packet)

    # Read response length
    resp_len_data = b""
    while len(resp_len_data) < 2:
        chunk = ssock.recv(2 - len(resp_len_data))
        if not chunk:
            break
        resp_len_data += chunk

    resp_len = struct.unpack("!H", resp_len_data)[0]

    # Read response
    resp_data = b""
    while len(resp_data) < resp_len:
        chunk = ssock.recv(resp_len - len(resp_data))
        if not chunk:
            break
        resp_data += chunk

    ssock.close()

    records = _parse_response(resp_data, domain)
    return [r.value for r in records if r.rtype == qtype.upper()]


# ---------------------------------------------------------------------------
# Zone transfer attempt (AXFR)
# ---------------------------------------------------------------------------

def zone_transfer(
    domain: str,
    nameserver: Optional[str] = None,
    timeout: float = 10.0,
) -> list[DNSRecord]:
    """
    Попытка AXFR zone transfer.

    Обычно закрыт, но иногда бывает открыт на неправильно настроенных NS.

    >>> records = zone_transfer("example.com")
    >>> for r in records:
    ...     print(r.rtype, r.name, r.value)
    """
    # Find nameserver if not specified
    if not nameserver:
        ns_records = resolve(domain, "NS")
        if not ns_records:
            raise RuntimeError(f"No NS records found for {domain}")
        nameserver = ns_records[0].rstrip(".")
        # Resolve NS hostname to IP
        ns_ips = resolve(nameserver, "A")
        if not ns_ips:
            raise RuntimeError(f"Cannot resolve NS {nameserver}")
        nameserver = ns_ips[0]

    # Build AXFR query (type=252)
    packet = _build_query(domain, 252)

    # AXFR uses TCP
    sock = socket.create_connection((nameserver, 53), timeout=timeout)

    # TCP DNS: prefix with 2-byte length
    length_prefix = struct.pack("!H", len(packet))
    sock.sendall(length_prefix + packet)

    # Read response
    all_data = b""
    try:
        while True:
            sock.settimeout(timeout)
            # Read length prefix
            len_data = b""
            while len(len_data) < 2:
                chunk = sock.recv(2 - len(len_data))
                if not chunk:
                    break
                len_data += chunk

            if len(len_data) < 2:
                break

            msg_len = struct.unpack("!H", len_data)[0]

            msg_data = b""
            while len(msg_data) < msg_len:
                chunk = sock.recv(msg_len - len(msg_data))
                if not chunk:
                    break
                msg_data += chunk

            records = _parse_response(msg_data, domain)
            if not records:
                break

            # Check for SOA at end (signals end of AXFR)
            has_soa = any(r.rtype == "SOA" for r in records)
            for r in records:
                all_data = all_data  # just to keep variable
            if has_soa and len(records) <= 2:
                break

            return records

    except socket.timeout:
        pass
    finally:
        sock.close()

    return []
