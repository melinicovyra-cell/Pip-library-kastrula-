"""
kastrula.whois — WHOIS запросы: домены, IP, регистраторы.
"""

from __future__ import annotations

import socket
import re
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


# ---------------------------------------------------------------------------
# WHOIS servers
# ---------------------------------------------------------------------------

TLD_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "io": "whois.nic.io",
    "dev": "whois.nic.google",
    "app": "whois.nic.google",
    "me": "whois.nic.me",
    "co": "whois.nic.co",
    "xyz": "whois.nic.xyz",
    "ru": "whois.tcinet.ru",
    "su": "whois.tcinet.ru",
    "рф": "whois.tcinet.ru",
    "de": "whois.denic.de",
    "uk": "whois.nic.uk",
    "fr": "whois.nic.fr",
    "eu": "whois.eu",
    "nl": "whois.sidn.nl",
    "au": "whois.auda.org.au",
    "ca": "whois.cira.ca",
    "br": "whois.registro.br",
    "jp": "whois.jprs.jp",
    "cn": "whois.cnnic.cn",
    "in": "whois.registry.in",
    "tv": "whois.nic.tv",
    "cc": "ccwhois.verisign-grs.com",
    "us": "whois.nic.us",
}

IP_WHOIS_SERVER = "whois.arin.net"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class WhoisResult:
    """Результат WHOIS запроса."""
    domain: str
    registrar: str = ""
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    status: list[str] = field(default_factory=list)
    nameservers: list[str] = field(default_factory=list)
    registrant: str = ""
    registrant_country: str = ""
    dnssec: str = ""
    whois_server: str = ""
    raw: str = ""

    @property
    def is_registered(self) -> bool:
        return bool(self.registrar or self.creation_date)

    def days_until_expiry(self) -> Optional[int]:
        if not self.expiration_date:
            return None
        try:
            for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d", "%d-%b-%Y", "%Y-%m-%d %H:%M:%S"):
                try:
                    exp = datetime.strptime(self.expiration_date, fmt)
                    return (exp - datetime.now()).days
                except ValueError:
                    continue
        except Exception:
            pass
        return None


@dataclass
class IPWhoisResult:
    """Результат WHOIS для IP."""
    ip: str
    network: str = ""
    netname: str = ""
    description: str = ""
    country: str = ""
    org: str = ""
    abuse_email: str = ""
    cidr: str = ""
    raw: str = ""


# ---------------------------------------------------------------------------
# Raw WHOIS query
# ---------------------------------------------------------------------------

def _raw_whois(
    query: str,
    server: str,
    port: int = 43,
    timeout: float = 10.0,
) -> str:
    """Send raw WHOIS query and return response text."""
    sock = socket.create_connection((server, port), timeout=timeout)
    sock.sendall((query + "\r\n").encode())

    response = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        except socket.timeout:
            break
    sock.close()

    return response.decode(errors="replace")


def _extract_field(raw: str, patterns: list[str]) -> str:
    """Extract field value from WHOIS raw text."""
    for pattern in patterns:
        match = re.search(rf"(?i){pattern}\s*:\s*(.+)", raw)
        if match:
            return match.group(1).strip()
    return ""


def _extract_list(raw: str, patterns: list[str]) -> list[str]:
    """Extract list of values from WHOIS raw text."""
    results = []
    for pattern in patterns:
        matches = re.findall(rf"(?i){pattern}\s*:\s*(.+)", raw)
        for m in matches:
            val = m.strip()
            if val and val not in results:
                results.append(val)
    return results


def _get_whois_server(domain: str) -> str:
    """Determine WHOIS server for domain."""
    tld = domain.rsplit(".", 1)[-1].lower()
    return TLD_SERVERS.get(tld, f"whois.nic.{tld}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def whois(domain: str, timeout: float = 10.0, follow: bool = True) -> WhoisResult:
    """
    WHOIS-запрос для домена.

    >>> result = whois("google.com")
    >>> print(result.registrar)
    >>> print(result.nameservers)
    >>> print(result.days_until_expiry())
    """
    domain = domain.lower().strip()
    server = _get_whois_server(domain)

    raw = _raw_whois(domain, server, timeout=timeout)

    # Follow referral to registrar WHOIS
    if follow:
        referral = _extract_field(raw, ["Registrar WHOIS Server", "Whois Server", "refer"])
        if referral and referral != server:
            try:
                raw2 = _raw_whois(domain, referral, timeout=timeout)
                if len(raw2) > len(raw) // 2:
                    raw = raw2
                    server = referral
            except Exception:
                pass

    return WhoisResult(
        domain=domain,
        registrar=_extract_field(raw, ["Registrar", "registrar"]),
        creation_date=_extract_field(raw, [
            "Creation Date", "Created", "created", "Registration Date",
            "Registration Time", "Registered on", "domain_dateregistered",
        ]),
        expiration_date=_extract_field(raw, [
            "Registry Expiry Date", "Expiration Date", "Expiry Date",
            "paid-till", "Expiry date", "domain_datedelete",
        ]),
        updated_date=_extract_field(raw, ["Updated Date", "Last Modified", "last-modified"]),
        status=_extract_list(raw, ["Domain Status", "Status", "state"]),
        nameservers=_extract_list(raw, ["Name Server", "nserver", "Nameservers"]),
        registrant=_extract_field(raw, [
            "Registrant Organization", "Registrant Name", "org",
            "Registrant", "registrant",
        ]),
        registrant_country=_extract_field(raw, [
            "Registrant Country", "Registrant State/Province", "country",
        ]),
        dnssec=_extract_field(raw, ["DNSSEC", "dnssec"]),
        whois_server=server,
        raw=raw,
    )


def ip_whois(ip: str, timeout: float = 10.0) -> IPWhoisResult:
    """
    WHOIS-запрос для IP-адреса.

    >>> result = ip_whois("8.8.8.8")
    >>> print(result.org, result.country, result.cidr)
    """
    # Определяем RIR
    server = IP_WHOIS_SERVER
    raw = _raw_whois(f"n {ip}", server, timeout=timeout)

    # Follow referral
    referral = _extract_field(raw, ["ReferralServer", "refer"])
    if referral:
        ref_host = referral.replace("whois://", "").replace("rwhois://", "").split(":")[0]
        try:
            raw2 = _raw_whois(ip, ref_host, timeout=timeout)
            if raw2:
                raw = raw2
        except Exception:
            pass

    return IPWhoisResult(
        ip=ip,
        network=_extract_field(raw, ["NetRange", "inetnum", "CIDR"]),
        netname=_extract_field(raw, ["NetName", "netname"]),
        description=_extract_field(raw, ["OrgName", "descr", "Organization"]),
        country=_extract_field(raw, ["Country", "country"]),
        org=_extract_field(raw, ["OrgName", "org-name", "Organization", "org"]),
        abuse_email=_extract_field(raw, ["OrgAbuseEmail", "abuse-mailbox", "e-mail"]),
        cidr=_extract_field(raw, ["CIDR", "inetnum", "NetRange"]),
        raw=raw,
    )


def is_registered(domain: str, timeout: float = 10.0) -> bool:
    """
    Быстрая проверка — зарегистрирован ли домен.

    >>> is_registered("google.com")
    True
    >>> is_registered("thisdomain-definitely-not-exist-12345.com")
    False
    """
    try:
        result = whois(domain, timeout=timeout, follow=False)
        return result.is_registered
    except Exception:
        return False
