"""
🍲 kastrula — сетевая кастрюля
TLS, HTTP, DNS, WebSocket, WHOIS, Traceroute, Proxy, Scan — всё в одном пакете.
"""

__version__ = "0.2.0"
__author__ = "KrScript"

# ── TLS ────────────────────────────────────────────────────────────────────
from kastrula.tls import (
    TLSProbe, grab_cert, ja3_fingerprint, check_chain,
    jarm_fingerprint, cipher_enum,
    CertInfo, HandshakeInfo, JA3Result, JARMResult, CipherInfo,
)

# ── DNS ────────────────────────────────────────────────────────────────────
from kastrula.dns import (
    resolve, lookup, dns_records, reverse_lookup,
    cached_resolve, doh_resolve, doh_json_resolve, dot_resolve,
    zone_transfer, DNSCache, DNSRecord, LookupResult,
)

# ── HTTP ───────────────────────────────────────────────────────────────────
from kastrula.http import (
    KastClient, KastResponse, RetryClient, KastSession, KastCookieJar,
)

# ── Scan ───────────────────────────────────────────────────────────────────
from kastrula.scan import (
    port_scan, banner_grab, service_detect,
    udp_scan, os_fingerprint, run_scripts,
    PortResult, ScanResult, UDPPortResult, UDPScanResult,
    OSGuess, ScriptResult,
)

# ── WebSocket ──────────────────────────────────────────────────────────────
from kastrula.ws import (
    WSClient, ws_sniff, ws_probe,
    WSFrame, WSInfo, WSSession, Opcode,
)

# ── WHOIS ──────────────────────────────────────────────────────────────────
from kastrula.whois import (
    whois, ip_whois, is_registered,
    WhoisResult, IPWhoisResult,
)

# ── Traceroute ─────────────────────────────────────────────────────────────
from kastrula.trace import (
    traceroute, tcp_traceroute,
    TraceResult, Hop,
)

# ── Proxy ──────────────────────────────────────────────────────────────────
from kastrula.proxy import (
    check_proxy, check_proxies, grab_proxies, grab_and_check,
    ProxyInfo, ProxyType, CheckResult,
)

# ── Export ─────────────────────────────────────────────────────────────────
from kastrula.export import Report

__all__ = [
    # TLS
    "TLSProbe", "grab_cert", "ja3_fingerprint", "check_chain",
    "jarm_fingerprint", "cipher_enum",
    # DNS
    "resolve", "lookup", "dns_records", "reverse_lookup",
    "cached_resolve", "doh_resolve", "doh_json_resolve", "dot_resolve",
    "zone_transfer", "DNSCache",
    # HTTP
    "KastClient", "RetryClient", "KastSession", "KastCookieJar",
    # Scan
    "port_scan", "banner_grab", "service_detect",
    "udp_scan", "os_fingerprint", "run_scripts",
    # WebSocket
    "WSClient", "ws_sniff", "ws_probe",
    # WHOIS
    "whois", "ip_whois", "is_registered",
    # Traceroute
    "traceroute", "tcp_traceroute",
    # Proxy
    "check_proxy", "check_proxies", "grab_proxies", "grab_and_check",
    # Export
    "Report",
]
