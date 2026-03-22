"""
kastrula.scan — сканирование: порты, баннеры, определение сервисов.
"""

from __future__ import annotations

import socket
import ssl
import concurrent.futures
from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------------------------
# Common ports & service signatures
# ---------------------------------------------------------------------------

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios", 143: "imap", 443: "https", 445: "smb",
    465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s",
    1080: "socks", 1433: "mssql", 1521: "oracle", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    8080: "http-proxy", 8443: "https-alt", 8888: "http-alt",
    9090: "prometheus", 27017: "mongodb",
}

SERVICE_SIGNATURES = {
    b"SSH-": "ssh",
    b"220 ": "smtp/ftp",
    b"HTTP/": "http",
    b"+OK": "pop3",
    b"* OK": "imap",
    b"\x00\x00\x00": "smb",
    b"-ERR": "redis",
    b"MySQL": "mysql",
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class PortResult:
    """Результат проверки одного порта."""
    port: int
    state: str  # "open", "closed", "filtered"
    service: str
    banner: str
    tls: bool


@dataclass
class ScanResult:
    """Результат сканирования хоста."""
    host: str
    ip: str
    open_ports: list[PortResult]
    closed_count: int
    filtered_count: int
    scan_time_ms: float

    def summary(self) -> str:
        lines = [f"Scan: {self.host} ({self.ip})"]
        lines.append(f"Open: {len(self.open_ports)} | Closed: {self.closed_count} | Filtered: {self.filtered_count}")
        lines.append(f"Time: {self.scan_time_ms:.0f}ms\n")
        for p in self.open_ports:
            tls_mark = " [TLS]" if p.tls else ""
            banner_short = p.banner[:60].replace("\n", " ") if p.banner else ""
            lines.append(f"  {p.port:>5}/tcp  {p.service:<15}{tls_mark}  {banner_short}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _check_port(
    host: str,
    port: int,
    timeout: float = 2.0,
    grab_banner: bool = True,
) -> PortResult:
    """Check a single port."""
    service = COMMON_PORTS.get(port, "unknown")
    banner = ""
    is_tls = False

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))

        if result != 0:
            sock.close()
            return PortResult(port=port, state="closed", service=service, banner="", tls=False)

        # Порт открыт
        if grab_banner:
            banner, is_tls = _grab_banner_from_sock(sock, host, port, timeout)

        # Определяем сервис по баннеру
        if banner:
            detected = _detect_service(banner.encode(errors="replace"))
            if detected and service == "unknown":
                service = detected

        sock.close()
        return PortResult(port=port, state="open", service=service, banner=banner, tls=is_tls)

    except socket.timeout:
        return PortResult(port=port, state="filtered", service=service, banner="", tls=False)
    except Exception:
        return PortResult(port=port, state="closed", service=service, banner="", tls=False)


def _grab_banner_from_sock(
    sock: socket.socket,
    host: str,
    port: int,
    timeout: float,
) -> tuple[str, bool]:
    """Try to grab banner, with TLS upgrade if needed."""
    banner = ""
    is_tls = False

    # Попробуем TLS для типичных TLS-портов
    tls_ports = {443, 465, 636, 853, 993, 995, 8443}

    if port in tls_ports:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ssock = ctx.wrap_socket(sock, server_hostname=host)
            is_tls = True
            ssock.sendall(b"HEAD / HTTP/1.1\r\nHost: %b\r\n\r\n" % host.encode())
            banner = ssock.recv(1024).decode(errors="replace").strip()
            return banner, is_tls
        except Exception:
            pass
        return banner, is_tls

    # Для остальных портов — сначала ждём баннер, потом пробуем отправить запрос
    try:
        sock.settimeout(min(timeout, 2.0))

        # Многие сервисы шлют баннер сразу (SSH, SMTP, FTP, etc.)
        try:
            banner = sock.recv(1024).decode(errors="replace").strip()
        except socket.timeout:
            pass

        # Если баннер пустой и это HTTP-порт, шлём запрос
        if not banner and port in (80, 8080, 8888, 8000, 3000, 9090):
            sock.sendall(b"HEAD / HTTP/1.1\r\nHost: %b\r\n\r\n" % host.encode())
            try:
                banner = sock.recv(1024).decode(errors="replace").strip()
            except socket.timeout:
                pass

    except Exception:
        pass

    return banner, is_tls


def _detect_service(data: bytes) -> Optional[str]:
    """Detect service from banner bytes."""
    for sig, svc in SERVICE_SIGNATURES.items():
        if data.startswith(sig):
            return svc
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def port_scan(
    host: str,
    ports: Optional[list[int]] = None,
    top: int = 100,
    timeout: float = 2.0,
    threads: int = 50,
    grab_banners: bool = True,
) -> ScanResult:
    """
    Сканировать порты хоста.

    >>> result = port_scan("example.com")
    >>> print(result.summary())

    >>> # Конкретные порты
    >>> result = port_scan("192.168.1.1", ports=[22, 80, 443, 8080])

    >>> # Топ-1000 портов, быстро
    >>> result = port_scan("target.com", top=1000, threads=100, timeout=1.0)
    """
    import time

    # Резолвим хост
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return ScanResult(host=host, ip="unresolved", open_ports=[], closed_count=0, filtered_count=0, scan_time_ms=0)

    # Определяем порты
    if ports is None:
        sorted_ports = sorted(COMMON_PORTS.keys())
        if top and top < len(sorted_ports):
            ports = sorted_ports[:top]
        else:
            ports = sorted_ports

    start = time.monotonic()

    open_ports = []
    closed = 0
    filtered = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(_check_port, ip, p, timeout, grab_banners): p
            for p in ports
        }

        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result.state == "open":
                    open_ports.append(result)
                elif result.state == "filtered":
                    filtered += 1
                else:
                    closed += 1
            except Exception:
                closed += 1

    elapsed = (time.monotonic() - start) * 1000
    open_ports.sort(key=lambda p: p.port)

    return ScanResult(
        host=host,
        ip=ip,
        open_ports=open_ports,
        closed_count=closed,
        filtered_count=filtered,
        scan_time_ms=round(elapsed, 2),
    )


def banner_grab(
    host: str,
    port: int,
    timeout: float = 5.0,
    send: Optional[bytes] = None,
) -> str:
    """
    Получить баннер конкретного порта.

    >>> print(banner_grab("github.com", 22))
    'SSH-2.0-babeld-...'

    >>> # Отправить кастомный запрос
    >>> print(banner_grab("example.com", 80, send=b"GET / HTTP/1.0\\r\\n\\r\\n"))
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)

        if send:
            sock.sendall(send)
        else:
            # Ждём баннер от сервера
            pass

        sock.settimeout(min(timeout, 3.0))
        data = sock.recv(4096)
        sock.close()
        return data.decode(errors="replace").strip()
    except Exception as e:
        return f"error: {e}"


def service_detect(
    host: str,
    port: int,
    timeout: float = 5.0,
) -> dict:
    """
    Определить сервис на порту: баннер + TLS + версия.

    >>> info = service_detect("github.com", 443)
    >>> print(info)
    {'port': 443, 'service': 'https', 'banner': '...', 'tls': True, 'tls_version': 'TLSv1.3', 'cert_cn': '*.github.com'}
    """
    result = {
        "port": port,
        "service": COMMON_PORTS.get(port, "unknown"),
        "banner": "",
        "tls": False,
        "tls_version": None,
        "cert_cn": None,
        "cipher": None,
    }

    try:
        sock = socket.create_connection((host, port), timeout=timeout)

        # Пробуем TLS
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ssock = ctx.wrap_socket(sock, server_hostname=host)

            result["tls"] = True
            result["tls_version"] = ssock.version()
            cipher = ssock.cipher()
            if cipher:
                result["cipher"] = cipher[0]

            cert = ssock.getpeercert()
            if cert:
                subject = dict(x[0] for x in cert.get("subject", []))
                result["cert_cn"] = subject.get("commonName", "")

            # Grab HTTP banner over TLS
            ssock.sendall(f"HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
            ssock.settimeout(2.0)
            try:
                result["banner"] = ssock.recv(1024).decode(errors="replace").strip()[:200]
            except socket.timeout:
                pass

            ssock.close()
        except Exception:
            # Не TLS — обычный баннер
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.settimeout(2.0)
            try:
                result["banner"] = sock.recv(1024).decode(errors="replace").strip()[:200]
            except socket.timeout:
                pass
            sock.close()

    except Exception as e:
        result["banner"] = f"error: {e}"

    # Detect from banner
    if result["banner"]:
        detected = _detect_service(result["banner"].encode(errors="replace"))
        if detected:
            result["service"] = detected

    return result


# ---------------------------------------------------------------------------
# UDP Scan
# ---------------------------------------------------------------------------

UDP_PROBES = {
    53: b"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # DNS
    123: b"\xe3\x00\x04\xfa" + b"\x00" * 44,  # NTP
    161: (  # SNMP get-request public community
        b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19"
        b"\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00"
        b"\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"
    ),
    1900: b"M-SEARCH * HTTP/1.1\r\nHost:239.255.255.250:1900\r\nST:ssdp:all\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\n\r\n",
    5353: b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00",  # mDNS
}

COMMON_UDP_PORTS = {
    53: "dns", 67: "dhcp-server", 68: "dhcp-client", 69: "tftp",
    123: "ntp", 137: "netbios-ns", 138: "netbios-dgm", 161: "snmp",
    162: "snmp-trap", 500: "isakmp", 514: "syslog", 520: "rip",
    1194: "openvpn", 1900: "ssdp/upnp", 4500: "ipsec-nat",
    5353: "mdns", 5060: "sip", 51820: "wireguard",
}


@dataclass
class UDPPortResult:
    """Результат UDP-сканирования порта."""
    port: int
    state: str  # "open", "closed", "open|filtered"
    service: str
    response: str


@dataclass
class UDPScanResult:
    """Результат UDP-сканирования."""
    host: str
    ip: str
    open_ports: list[UDPPortResult]
    scan_time_ms: float

    def summary(self) -> str:
        lines = [f"UDP Scan: {self.host} ({self.ip})"]
        lines.append(f"Open: {len(self.open_ports)} | Time: {self.scan_time_ms:.0f}ms\n")
        for p in self.open_ports:
            resp_short = p.response[:40].replace("\n", " ") if p.response else ""
            lines.append(f"  {p.port:>5}/udp  {p.service:<15} {p.state:<15} {resp_short}")
        return "\n".join(lines)


def _check_udp_port(
    host: str,
    port: int,
    timeout: float = 3.0,
) -> UDPPortResult:
    """Check a single UDP port."""
    service = COMMON_UDP_PORTS.get(port, "unknown")
    probe = UDP_PROBES.get(port, b"\x00" * 8)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(probe, (host, port))

        try:
            data, _ = sock.recvfrom(4096)
            sock.close()
            response = data[:100].decode(errors="replace")
            return UDPPortResult(port=port, state="open", service=service, response=response)
        except socket.timeout:
            sock.close()
            return UDPPortResult(port=port, state="open|filtered", service=service, response="")

    except OSError:
        return UDPPortResult(port=port, state="closed", service=service, response="")


def udp_scan(
    host: str,
    ports: Optional[list[int]] = None,
    timeout: float = 3.0,
    threads: int = 20,
) -> UDPScanResult:
    """
    UDP-сканирование портов.

    >>> result = udp_scan("192.168.1.1", ports=[53, 123, 161, 1900])
    >>> print(result.summary())
    """
    import time

    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return UDPScanResult(host=host, ip="unresolved", open_ports=[], scan_time_ms=0)

    if ports is None:
        ports = sorted(COMMON_UDP_PORTS.keys())

    start = time.monotonic()
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(_check_udp_port, ip, p, timeout): p
            for p in ports
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result.state in ("open", "open|filtered"):
                    open_ports.append(result)
            except Exception:
                pass

    elapsed = (time.monotonic() - start) * 1000
    open_ports.sort(key=lambda p: p.port)

    return UDPScanResult(
        host=host, ip=ip,
        open_ports=open_ports,
        scan_time_ms=round(elapsed, 2),
    )


# ---------------------------------------------------------------------------
# OS Fingerprint (TCP/IP stack analysis)
# ---------------------------------------------------------------------------

@dataclass
class OSGuess:
    """Предположение об ОС."""
    os_name: str
    confidence: float  # 0-100
    ttl: int
    window_size: int
    details: str


# TTL-based OS detection (simple but effective)
_OS_TTL_MAP = [
    (64, "Linux/Android/macOS/iOS"),
    (128, "Windows"),
    (255, "Cisco IOS / Solaris / FreeBSD"),
    (60, "HP-UX"),
    (30, "Network device"),
]


def os_fingerprint(
    host: str,
    port: int = 80,
    timeout: float = 5.0,
) -> list[OSGuess]:
    """
    Определить ОС по TCP/IP стеку.

    Использует TTL, TCP window size и поведение стека.

    >>> guesses = os_fingerprint("example.com")
    >>> for g in guesses:
    ...     print(f"{g.os_name}: {g.confidence:.0f}% (TTL={g.ttl})")
    """
    results = []

    try:
        # Connect and get TCP parameters
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Get TTL from IP options
        ttl = None
        try:
            ttl = sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        except Exception:
            pass

        # Try to get initial TTL from traceroute-like technique
        # Use the received TTL to estimate original
        if ttl is None:
            # Fallback: ping-like
            import subprocess
            try:
                out = subprocess.run(
                    ["ping", "-c", "1", "-W", str(int(timeout)), host],
                    capture_output=True, text=True, timeout=timeout,
                )
                import re
                m = re.search(r"ttl[=:](\d+)", out.stdout, re.IGNORECASE)
                if m:
                    ttl = int(m.group(1))
            except Exception:
                pass

        sock.close()

        if ttl is not None:
            # Find closest initial TTL
            for initial_ttl, os_name in _OS_TTL_MAP:
                if ttl <= initial_ttl:
                    # Estimate hops
                    hops = initial_ttl - ttl
                    confidence = max(10, 90 - abs(hops) * 2)

                    results.append(OSGuess(
                        os_name=os_name,
                        confidence=confidence,
                        ttl=ttl,
                        window_size=0,
                        details=f"Recv TTL={ttl}, est. initial={initial_ttl}, hops≈{hops}",
                    ))
                    break

            # Secondary guesses
            if not results:
                results.append(OSGuess(
                    os_name="Unknown",
                    confidence=10,
                    ttl=ttl,
                    window_size=0,
                    details=f"TTL={ttl} doesn't match known patterns",
                ))

    except Exception as e:
        results.append(OSGuess(
            os_name="Unknown",
            confidence=0,
            ttl=0,
            window_size=0,
            details=f"Scan failed: {e}",
        ))

    return results


# ---------------------------------------------------------------------------
# NSE-like Scripts
# ---------------------------------------------------------------------------

@dataclass
class ScriptResult:
    """Результат NSE-подобного скрипта."""
    name: str
    port: int
    output: str
    success: bool


def _script_http_title(host: str, port: int, timeout: float) -> ScriptResult:
    """Получить title HTML-страницы."""
    import re
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        scheme = "https" if port in (443, 8443) else "http"

        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        sock.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        data = b""
        try:
            while len(data) < 8192:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        sock.close()

        text = data.decode(errors="replace")
        match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
        title = match.group(1).strip()[:100] if match else "No title"

        return ScriptResult(name="http-title", port=port, output=title, success=True)
    except Exception as e:
        return ScriptResult(name="http-title", port=port, output=str(e), success=False)


def _script_ssh_info(host: str, port: int, timeout: float) -> ScriptResult:
    """Получить SSH версию и ключи."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(3.0)
        banner = sock.recv(256).decode(errors="replace").strip()
        sock.close()
        return ScriptResult(name="ssh-info", port=port, output=banner, success=True)
    except Exception as e:
        return ScriptResult(name="ssh-info", port=port, output=str(e), success=False)


def _script_ssl_cert(host: str, port: int, timeout: float) -> ScriptResult:
    """Быстро получить SSL сертификат."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((host, port), timeout=timeout)
        ssock = ctx.wrap_socket(sock, server_hostname=host)
        cert = ssock.getpeercert()
        version = ssock.version()
        ssock.close()

        if cert:
            subject = dict(x[0] for x in cert.get("subject", []))
            cn = subject.get("commonName", "?")
            output = f"CN={cn} | {version}"
        else:
            output = f"No cert info | {version}"

        return ScriptResult(name="ssl-cert", port=port, output=output, success=True)
    except Exception as e:
        return ScriptResult(name="ssl-cert", port=port, output=str(e), success=False)


# Script registry
SCRIPTS = {
    "http-title": {"ports": [80, 8080, 8000, 3000, 443, 8443], "func": _script_http_title},
    "ssh-info": {"ports": [22, 2222], "func": _script_ssh_info},
    "ssl-cert": {"ports": [443, 8443, 465, 993, 995], "func": _script_ssl_cert},
}


def run_scripts(
    host: str,
    ports: Optional[list[int]] = None,
    scripts: Optional[list[str]] = None,
    timeout: float = 5.0,
) -> list[ScriptResult]:
    """
    Запустить NSE-подобные скрипты на хосте.

    >>> results = run_scripts("example.com", ports=[80, 443])
    >>> for r in results:
    ...     print(f"{r.name}({r.port}): {r.output}")

    >>> # Конкретные скрипты
    >>> results = run_scripts("github.com", scripts=["ssh-info", "ssl-cert"])
    """
    results = []
    scripts_to_run = scripts or list(SCRIPTS.keys())

    for script_name in scripts_to_run:
        if script_name not in SCRIPTS:
            continue

        script = SCRIPTS[script_name]
        target_ports = ports or script["ports"]

        for port in target_ports:
            if port in script["ports"] or ports:
                result = script["func"](host, port, timeout)
                results.append(result)

    return results
