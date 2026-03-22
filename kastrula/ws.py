"""
kastrula.ws — WebSocket: подключение, сниффинг фреймов, отправка.
"""

from __future__ import annotations

import json
import ssl
import socket
import struct
import hashlib
import base64
import os
import time
import threading
from dataclasses import dataclass, field
from typing import Optional, Callable
from enum import IntEnum


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class Opcode(IntEnum):
    CONTINUATION = 0x0
    TEXT = 0x1
    BINARY = 0x2
    CLOSE = 0x8
    PING = 0x9
    PONG = 0xA

OPCODE_NAMES = {
    0x0: "CONT", 0x1: "TEXT", 0x2: "BIN",
    0x8: "CLOSE", 0x9: "PING", 0xA: "PONG",
}

WS_MAGIC = b"258EAFA5-E914-47DA-95CA-5AB9964C7BE0"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class WSFrame:
    """Один WebSocket фрейм."""
    opcode: int
    payload: bytes
    fin: bool = True
    timestamp: float = 0.0

    @property
    def opcode_name(self) -> str:
        return OPCODE_NAMES.get(self.opcode, f"0x{self.opcode:02x}")

    @property
    def text(self) -> str:
        try:
            return self.payload.decode("utf-8")
        except UnicodeDecodeError:
            return self.payload.hex()

    @property
    def json(self) -> dict:
        return json.loads(self.payload)

    def __repr__(self) -> str:
        preview = self.text[:60] if len(self.payload) < 200 else self.text[:57] + "..."
        return f"<WSFrame {self.opcode_name} len={len(self.payload)} '{preview}'>"


@dataclass
class WSInfo:
    """Информация о WS-подключении."""
    url: str
    status_code: int
    headers: dict
    protocol: Optional[str]
    extensions: list[str]
    tls: bool


@dataclass
class WSSession:
    """Результат WS-сессии сниффинга."""
    url: str
    frames: list[WSFrame] = field(default_factory=list)
    duration_ms: float = 0.0
    sent_count: int = 0
    recv_count: int = 0

    def texts(self) -> list[str]:
        return [f.text for f in self.frames if f.opcode == Opcode.TEXT]

    def jsons(self) -> list[dict]:
        results = []
        for f in self.frames:
            if f.opcode == Opcode.TEXT:
                try:
                    results.append(f.json)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
        return results


# ---------------------------------------------------------------------------
# Low-level WebSocket protocol
# ---------------------------------------------------------------------------

def _parse_ws_url(url: str) -> tuple[str, str, int, str, bool]:
    """Parse ws:// or wss:// URL -> (scheme, host, port, path, tls)."""
    if url.startswith("wss://"):
        scheme, tls, default_port = "wss", True, 443
    elif url.startswith("ws://"):
        scheme, tls, default_port = "ws", False, 80
    else:
        raise ValueError(f"Invalid WS URL: {url}")

    rest = url[len(scheme) + 3:]
    if "/" in rest:
        hostport, path = rest.split("/", 1)
        path = "/" + path
    else:
        hostport = rest
        path = "/"

    if ":" in hostport:
        host, port_str = hostport.rsplit(":", 1)
        port = int(port_str)
    else:
        host = hostport
        port = default_port

    return scheme, host, port, path, tls


def _build_handshake(host: str, port: int, path: str, extra_headers: dict = None) -> tuple[bytes, str]:
    """Build HTTP upgrade request, return (request_bytes, ws_key)."""
    key = base64.b64encode(os.urandom(16)).decode()
    headers = {
        "Host": f"{host}:{port}" if port not in (80, 443) else host,
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Sec-WebSocket-Key": key,
        "Sec-WebSocket-Version": "13",
        "Origin": f"https://{host}" if port == 443 else f"http://{host}",
    }
    if extra_headers:
        headers.update(extra_headers)

    lines = [f"GET {path} HTTP/1.1"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    lines.append("\r\n")

    return "\r\n".join(lines).encode(), key


def _parse_handshake_response(data: bytes) -> tuple[int, dict]:
    """Parse HTTP upgrade response."""
    header_end = data.find(b"\r\n\r\n")
    if header_end == -1:
        return 0, {}

    header_text = data[:header_end].decode(errors="replace")
    lines = header_text.split("\r\n")

    status_line = lines[0]
    status_code = int(status_line.split(" ")[1]) if " " in status_line else 0

    headers = {}
    for line in lines[1:]:
        if ": " in line:
            k, v = line.split(": ", 1)
            headers[k.lower()] = v

    return status_code, headers


def _mask_payload(payload: bytes, mask_key: bytes) -> bytes:
    """Apply XOR mask to payload."""
    return bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))


def _build_frame(opcode: int, payload: bytes, mask: bool = True) -> bytes:
    """Build a WebSocket frame."""
    frame = bytearray()
    frame.append(0x80 | opcode)  # FIN + opcode

    length = len(payload)
    mask_bit = 0x80 if mask else 0

    if length < 126:
        frame.append(mask_bit | length)
    elif length < 65536:
        frame.append(mask_bit | 126)
        frame.extend(struct.pack("!H", length))
    else:
        frame.append(mask_bit | 127)
        frame.extend(struct.pack("!Q", length))

    if mask:
        mask_key = os.urandom(4)
        frame.extend(mask_key)
        frame.extend(_mask_payload(payload, mask_key))
    else:
        frame.extend(payload)

    return bytes(frame)


def _read_frame(sock) -> Optional[WSFrame]:
    """Read one WebSocket frame from socket."""
    try:
        header = _recv_exact(sock, 2)
        if not header:
            return None

        fin = bool(header[0] & 0x80)
        opcode = header[0] & 0x0F
        masked = bool(header[1] & 0x80)
        length = header[1] & 0x7F

        if length == 126:
            data = _recv_exact(sock, 2)
            length = struct.unpack("!H", data)[0]
        elif length == 127:
            data = _recv_exact(sock, 8)
            length = struct.unpack("!Q", data)[0]

        mask_key = None
        if masked:
            mask_key = _recv_exact(sock, 4)

        payload = _recv_exact(sock, length) if length > 0 else b""

        if masked and mask_key:
            payload = _mask_payload(payload, mask_key)

        return WSFrame(
            opcode=opcode,
            payload=payload,
            fin=fin,
            timestamp=time.time(),
        )
    except Exception:
        return None


def _recv_exact(sock, n: int) -> bytes:
    """Receive exactly n bytes."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return data


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class WSClient:
    """
    WebSocket клиент.

    >>> ws = WSClient("wss://echo.websocket.org")
    >>> ws.connect()
    >>> ws.send("hello")
    >>> frame = ws.recv()
    >>> print(frame.text)
    'hello'
    >>> ws.close()
    """

    def __init__(
        self,
        url: str,
        headers: Optional[dict] = None,
        timeout: float = 10.0,
        protocols: Optional[list[str]] = None,
    ):
        self.url = url
        self._extra_headers = headers or {}
        self._timeout = timeout
        self._protocols = protocols
        self._sock = None
        self._connected = False
        self.info: Optional[WSInfo] = None

        self._scheme, self._host, self._port, self._path, self._tls = _parse_ws_url(url)

    def connect(self) -> WSInfo:
        """Подключиться к WebSocket серверу."""
        sock = socket.create_connection((self._host, self._port), timeout=self._timeout)

        if self._tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=self._host)

        headers = dict(self._extra_headers)
        if self._protocols:
            headers["Sec-WebSocket-Protocol"] = ", ".join(self._protocols)

        request, ws_key = _build_handshake(self._host, self._port, self._path, headers)
        sock.sendall(request)

        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("No handshake response")
            response += chunk

        status, resp_headers = _parse_handshake_response(response)

        if status != 101:
            sock.close()
            raise ConnectionError(f"Handshake failed: HTTP {status}")

        self._sock = sock
        self._connected = True

        self.info = WSInfo(
            url=self.url,
            status_code=status,
            headers=resp_headers,
            protocol=resp_headers.get("sec-websocket-protocol"),
            extensions=resp_headers.get("sec-websocket-extensions", "").split(","),
            tls=self._tls,
        )
        return self.info

    def send(self, data: str | bytes, opcode: Optional[int] = None) -> None:
        """Отправить данные."""
        if not self._connected:
            raise RuntimeError("Not connected")

        if isinstance(data, str):
            payload = data.encode("utf-8")
            op = opcode or Opcode.TEXT
        else:
            payload = data
            op = opcode or Opcode.BINARY

        frame = _build_frame(op, payload, mask=True)
        self._sock.sendall(frame)

    def recv(self, timeout: Optional[float] = None) -> Optional[WSFrame]:
        """Получить один фрейм."""
        if not self._connected:
            raise RuntimeError("Not connected")

        if timeout is not None:
            self._sock.settimeout(timeout)

        frame = _read_frame(self._sock)

        # Auto-respond to ping
        if frame and frame.opcode == Opcode.PING:
            pong = _build_frame(Opcode.PONG, frame.payload, mask=True)
            self._sock.sendall(pong)

        return frame

    def ping(self, data: bytes = b"") -> None:
        """Отправить ping."""
        if not self._connected:
            raise RuntimeError("Not connected")
        frame = _build_frame(Opcode.PING, data, mask=True)
        self._sock.sendall(frame)

    def close(self, code: int = 1000, reason: str = "") -> None:
        """Закрыть соединение."""
        if self._connected:
            try:
                payload = struct.pack("!H", code) + reason.encode("utf-8")
                frame = _build_frame(Opcode.CLOSE, payload, mask=True)
                self._sock.sendall(frame)
            except Exception:
                pass
            finally:
                self._connected = False
                self._sock.close()

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()


def ws_sniff(
    url: str,
    duration: float = 10.0,
    on_frame: Optional[Callable[[WSFrame], None]] = None,
    send_after_connect: Optional[list[str]] = None,
    headers: Optional[dict] = None,
) -> WSSession:
    """
    Сниффить WebSocket трафик заданное время.

    >>> session = ws_sniff("wss://stream.binance.com:9443/ws/btcusdt@trade", duration=5)
    >>> for f in session.frames[:5]:
    ...     print(f.opcode_name, f.text[:80])
    """
    session = WSSession(url=url)
    start = time.time()

    client = WSClient(url, headers=headers)
    client.connect()

    # Отправить начальные сообщения
    if send_after_connect:
        for msg in send_after_connect:
            client.send(msg)
            session.sent_count += 1

    try:
        while (time.time() - start) < duration:
            remaining = duration - (time.time() - start)
            if remaining <= 0:
                break

            frame = client.recv(timeout=min(remaining, 2.0))
            if frame is None:
                break

            if frame.opcode == Opcode.CLOSE:
                break

            session.frames.append(frame)
            session.recv_count += 1

            if on_frame:
                on_frame(frame)

    except Exception:
        pass
    finally:
        client.close()

    session.duration_ms = (time.time() - start) * 1000
    return session


def ws_probe(url: str, timeout: float = 10.0) -> WSInfo:
    """
    Проверить WebSocket endpoint — подключиться и сразу отключиться.

    >>> info = ws_probe("wss://echo.websocket.events")
    >>> print(info.status_code, info.protocol, info.tls)
    """
    client = WSClient(url, timeout=timeout)
    info = client.connect()
    client.close()
    return info
