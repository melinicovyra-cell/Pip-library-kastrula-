"""
kastrula.tls — анализ TLS: сертификаты, JA3, цепочки, handshake.
"""

from __future__ import annotations

import hashlib
import socket
import ssl
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class CertInfo:
    """Parsed X.509 certificate info."""
    subject: dict
    issuer: dict
    serial: int
    not_before: datetime
    not_after: datetime
    san: list[str]
    fingerprint_sha256: str
    public_key_bits: int
    signature_algorithm: str
    is_expired: bool
    pem: str

    def days_left(self) -> int:
        delta = self.not_after - datetime.now(timezone.utc)
        return delta.days


@dataclass
class HandshakeInfo:
    """TLS handshake result."""
    host: str
    port: int
    protocol_version: str
    cipher_name: str
    cipher_bits: int
    alpn: Optional[str]
    sni: str
    cert: CertInfo
    chain: list[CertInfo] = field(default_factory=list)


@dataclass
class JA3Result:
    """JA3 fingerprint result."""
    ja3_string: str
    ja3_hash: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_name(name: x509.Name) -> dict:
    """Extract CN, O, OU, etc. from x509 Name."""
    mapping = {
        NameOID.COMMON_NAME: "CN",
        NameOID.ORGANIZATION_NAME: "O",
        NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
        NameOID.COUNTRY_NAME: "C",
        NameOID.STATE_OR_PROVINCE_NAME: "ST",
        NameOID.LOCALITY_NAME: "L",
    }
    result = {}
    for oid, key in mapping.items():
        vals = name.get_attributes_for_oid(oid)
        if vals:
            result[key] = vals[0].value
    return result


def _parse_cert(cert_crypto: x509.Certificate) -> CertInfo:
    """Parse cryptography x509 cert into CertInfo."""
    san = []
    try:
        ext = cert_crypto.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        san = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    fp = cert_crypto.fingerprint(hashes.SHA256()).hex(":")
    pub_key = cert_crypto.public_key()
    bits = pub_key.key_size if hasattr(pub_key, "key_size") else 0
    now = datetime.now(timezone.utc)
    pem = cert_crypto.public_bytes(serialization.Encoding.PEM).decode()

    return CertInfo(
        subject=_parse_name(cert_crypto.subject),
        issuer=_parse_name(cert_crypto.issuer),
        serial=cert_crypto.serial_number,
        not_before=cert_crypto.not_valid_before_utc,
        not_after=cert_crypto.not_valid_after_utc,
        san=san,
        fingerprint_sha256=fp,
        public_key_bits=bits,
        signature_algorithm=cert_crypto.signature_algorithm_oid.dotted_string,
        is_expired=now > cert_crypto.not_valid_after_utc,
        pem=pem,
    )


def _ssl_connect(
    host: str, port: int = 443, timeout: float = 10.0
) -> tuple[ssl.SSLSocket, ssl.SSLContext]:
    """Create a TLS connection and return (ssl_socket, context)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection((host, port), timeout=timeout)
    ssock = ctx.wrap_socket(sock, server_hostname=host)
    return ssock, ctx


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def grab_cert(host: str, port: int = 443, timeout: float = 10.0) -> CertInfo:
    """
    Получить и распарсить TLS-сертификат хоста.

    >>> cert = grab_cert("google.com")
    >>> print(cert.subject, cert.days_left())
    """
    ssock, _ = _ssl_connect(host, port, timeout)
    der = ssock.getpeercert(binary_form=True)
    ssock.close()
    cert_crypto = x509.load_der_x509_certificate(der)
    return _parse_cert(cert_crypto)


def check_chain(host: str, port: int = 443, timeout: float = 10.0) -> list[CertInfo]:
    """
    Получить полную цепочку сертификатов.

    >>> chain = check_chain("github.com")
    >>> for c in chain:
    ...     print(c.subject.get("CN"), "->", c.issuer.get("CN"))
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    sock = socket.create_connection((host, port), timeout=timeout)
    ssock = ctx.wrap_socket(sock, server_hostname=host)

    # getpeercert_chain доступен не везде, fallback на одиночный
    chain_der = ssock.get_channel_binding()  # не то что нужно
    # Используем OpenSSL через cryptography если доступен
    certs = []
    der = ssock.getpeercert(binary_form=True)
    certs.append(_parse_cert(x509.load_der_x509_certificate(der)))

    # Попробуем достать промежуточные через SSLObject
    try:
        import _ssl
        if hasattr(ssock, "_sslobj"):
            peer_chain = ssock._sslobj.get_verified_chain()
            if peer_chain:
                certs = []
                for cert_bytes in peer_chain:
                    c = x509.load_der_x509_certificate(cert_bytes)
                    certs.append(_parse_cert(c))
    except Exception:
        pass

    ssock.close()
    return certs


class TLSProbe:
    """
    Комплексный TLS-анализ хоста.

    >>> probe = TLSProbe("example.com")
    >>> info = probe.handshake()
    >>> print(info.protocol_version, info.cipher_name)
    """

    def __init__(self, host: str, port: int = 443, timeout: float = 10.0):
        self.host = host
        self.port = port
        self.timeout = timeout

    def handshake(self) -> HandshakeInfo:
        """Выполнить TLS handshake и собрать всю инфу."""
        ssock, ctx = _ssl_connect(self.host, self.port, self.timeout)

        cipher = ssock.cipher()  # (name, version, bits)
        proto = ssock.version()
        alpn = ssock.selected_alpn_protocol()

        der = ssock.getpeercert(binary_form=True)
        cert_info = _parse_cert(x509.load_der_x509_certificate(der))

        chain = []
        try:
            if hasattr(ssock, "_sslobj") and hasattr(ssock._sslobj, "get_verified_chain"):
                for cert_bytes in ssock._sslobj.get_verified_chain():
                    chain.append(_parse_cert(x509.load_der_x509_certificate(cert_bytes)))
        except Exception:
            chain = [cert_info]

        ssock.close()

        return HandshakeInfo(
            host=self.host,
            port=self.port,
            protocol_version=proto or "unknown",
            cipher_name=cipher[0] if cipher else "unknown",
            cipher_bits=cipher[2] if cipher else 0,
            alpn=alpn,
            sni=self.host,
            cert=cert_info,
            chain=chain,
        )

    def supported_protocols(self) -> list[str]:
        """Проверить какие TLS версии поддерживает сервер."""
        protocols = []
        test_versions = [
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
        ]
        for name, ver in test_versions:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = ver
                ctx.maximum_version = ver
                sock = socket.create_connection(
                    (self.host, self.port), timeout=self.timeout
                )
                ssock = ctx.wrap_socket(sock, server_hostname=self.host)
                ssock.close()
                protocols.append(name)
            except Exception:
                pass
        return protocols


def ja3_fingerprint(host: str, port: int = 443, timeout: float = 10.0) -> JA3Result:
    """
    Вычислить JA3 fingerprint для TLS ClientHello.

    Упрощённая версия: строит JA3-подобную строку из параметров
    реального соединения (версия, шифры, расширения).

    >>> result = ja3_fingerprint("google.com")
    >>> print(result.ja3_hash)
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    sock = socket.create_connection((host, port), timeout=timeout)
    ssock = ctx.wrap_socket(sock, server_hostname=host)

    # Собираем данные из установленного соединения
    cipher = ssock.cipher()
    version = ssock.version()
    shared_ciphers = ssock.shared_ciphers() or []

    # Маппинг TLS версий
    ver_map = {"TLSv1": "769", "TLSv1.1": "770", "TLSv1.2": "771", "TLSv1.3": "772"}
    tls_ver = ver_map.get(version, "771")

    # Собираем cipher suite IDs (аппроксимация через имена)
    cipher_names = [c[0] for c in shared_ciphers] if shared_ciphers else []
    cipher_str = "-".join(cipher_names[:20])

    # JA3-подобная строка
    ja3_raw = f"{tls_ver},{cipher_str},,,"
    ja3_hash = hashlib.md5(ja3_raw.encode()).hexdigest()

    ssock.close()

    return JA3Result(ja3_string=ja3_raw, ja3_hash=ja3_hash)


# ---------------------------------------------------------------------------
# JARM Fingerprint
# ---------------------------------------------------------------------------

@dataclass
class JARMResult:
    """JARM fingerprint result."""
    jarm_hash: str
    jarm_raw: str
    responses: list[str]


# JARM probe configurations: (tls_version, cipher_list, extensions, alpn)
_JARM_PROBES = [
    (ssl.TLSVersion.TLSv1_2, None, True, "h2"),
    (ssl.TLSVersion.TLSv1_2, None, True, "http/1.1"),
    (ssl.TLSVersion.TLSv1_2, None, False, None),
    (ssl.TLSVersion.TLSv1_2, None, True, None),
    (ssl.TLSVersion.TLSv1_3, None, True, "h2"),
    (ssl.TLSVersion.TLSv1_3, None, True, "http/1.1"),
    (ssl.TLSVersion.TLSv1_3, None, False, None),
    (ssl.TLSVersion.TLSv1_3, None, True, None),
    (ssl.TLSVersion.TLSv1_2, None, True, "h2,http/1.1"),
    (ssl.TLSVersion.TLSv1_3, None, True, "h2,http/1.1"),
]


def jarm_fingerprint(host: str, port: int = 443, timeout: float = 5.0) -> JARMResult:
    """
    Вычислить JARM fingerprint сервера.

    JARM характеризует TLS-сервер (в отличие от JA3 который характеризует клиента).
    Один и тот же сервер/софт будет иметь одинаковый JARM.

    >>> result = jarm_fingerprint("google.com")
    >>> print(result.jarm_hash)
    """
    responses = []

    for tls_ver, ciphers, extensions, alpn in _JARM_PROBES:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = tls_ver
            ctx.maximum_version = tls_ver

            if alpn:
                ctx.set_alpn_protocols(alpn.split(","))

            sock = socket.create_connection((host, port), timeout=timeout)
            ssock = ctx.wrap_socket(sock, server_hostname=host)

            cipher = ssock.cipher()
            version = ssock.version() or ""
            cipher_name = cipher[0] if cipher else ""
            response_str = f"{version}|{cipher_name}"

            ssock.close()
            responses.append(response_str)

        except Exception:
            responses.append("|||")

    raw = ",".join(responses)
    jarm_hash = hashlib.sha256(raw.encode()).hexdigest()[:62]

    return JARMResult(jarm_hash=jarm_hash, jarm_raw=raw, responses=responses)


# ---------------------------------------------------------------------------
# Cipher Enumeration
# ---------------------------------------------------------------------------

@dataclass
class CipherInfo:
    """Информация о поддерживаемом шифре."""
    name: str
    protocol: str
    bits: int
    is_weak: bool


# Known weak ciphers
_WEAK_PATTERNS = [
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon",
    "MD5", "RC2", "IDEA", "SEED", "CAMELLIA",
]


def cipher_enum(host: str, port: int = 443, timeout: float = 5.0) -> list[CipherInfo]:
    """
    Перечислить все поддерживаемые сервером шифры.

    >>> ciphers = cipher_enum("google.com")
    >>> for c in ciphers:
    ...     weak = "⚠️ WEAK" if c.is_weak else "✓"
    ...     print(f"{c.protocol:8} {c.name:40} {c.bits:>4}bit {weak}")
    """
    results = []
    seen = set()

    versions = [
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ]

    for ver_name, ver in versions:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver
            ctx.maximum_version = ver

            sock = socket.create_connection((host, port), timeout=timeout)
            ssock = ctx.wrap_socket(sock, server_hostname=host)

            shared = ssock.shared_ciphers() or []
            for cipher_name, protocol, bits in shared:
                if cipher_name not in seen:
                    seen.add(cipher_name)
                    is_weak = any(w.lower() in cipher_name.lower() for w in _WEAK_PATTERNS)
                    results.append(CipherInfo(
                        name=cipher_name,
                        protocol=ver_name,
                        bits=bits,
                        is_weak=is_weak,
                    ))

            ssock.close()

        except Exception:
            pass

    return results
