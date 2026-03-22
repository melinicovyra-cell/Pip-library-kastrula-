# 🍲 kastrula v0.2.0

**Сетевая кастрюля** — Python-библиотека для работы с сетью.

```
pip install kastrula
```

## Модули

| Модуль | Описание |
|--------|----------|
| `tls` | Сертификаты, JA3, JARM, cipher enum, handshake |
| `http` | HTTP/2 клиент с браузерными профилями, сессии, retry |
| `dns` | Резолвер, DoH, DoT, кэш, zone transfer |
| `scan` | TCP/UDP порты, баннеры, OS fingerprint, NSE-скрипты |
| `ws` | WebSocket подключение, сниффинг фреймов |
| `whois` | WHOIS для доменов и IP |
| `trace` | Traceroute (UDP/TCP) |
| `proxy` | Чекер, граббер, валидатор прокси |
| `export` | Отчёты в JSON/HTML/текст |
| `aio` | Async-версии всех модулей |
| `cli` | CLI с субкомандами |

## Быстрый старт

```python
from kastrula import *

# TLS
cert = grab_cert("google.com")
print(cert.subject, cert.days_left())

probe = TLSProbe("github.com")
info = probe.handshake()
print(info.protocol_version, info.cipher_name)

ciphers = cipher_enum("google.com")
jarm = jarm_fingerprint("google.com")

# HTTP с профилем браузера
with KastClient(profile="chrome_120") as client:
    resp = client.get("https://httpbin.org/ip")
    print(resp.json())

# Сессия с cookies и retry
session = KastSession(profile="firefox_121", retries=3)
session.get("https://example.com/login")
print(session.cookies)

# DNS
ips = resolve("google.com")
records = dns_records("github.com", ["A", "MX", "NS", "TXT"])

# DNS over HTTPS / TLS
ips = doh_resolve("google.com")
ips = dot_resolve("google.com")

# Сканирование
result = port_scan("example.com", ports=[22, 80, 443])
print(result.summary())

udp = udp_scan("192.168.1.1", ports=[53, 123, 161])
os_info = os_fingerprint("example.com")
scripts = run_scripts("example.com", ports=[80, 443])

# WebSocket
with WSClient("wss://echo.websocket.events") as ws:
    ws.send("hello")
    frame = ws.recv()
    print(frame.text)

session = ws_sniff("wss://stream.binance.com:9443/ws/btcusdt@trade", duration=5)

# WHOIS
info = whois("google.com")
print(info.registrar, info.days_until_expiry())
ip_info = ip_whois("8.8.8.8")

# Traceroute
result = tcp_traceroute("google.com", port=443)
print(result.summary())

# Прокси
proxies = grab_proxies()
result = check_proxies(proxies[:50], threads=30)
print(result.summary())

# Экспорт
report = Report("Scan Report", target="example.com")
report.add_section("Ports", scan_result)
report.save_html("report.html")
report.save_json("report.json")
```

## Async

```python
import asyncio
from kastrula.aio import full_recon, multi_resolve

async def main():
    # Полная разведка
    data = await full_recon("example.com")

    # Параллельный резолв
    results = await multi_resolve(["google.com", "github.com", "example.com"])

asyncio.run(main())
```

## CLI

```bash
kastrula scan example.com -p 22,80,443 --os --scripts
kastrula tls github.com
kastrula dns google.com --doh https://cloudflare-dns.com/dns-query
kastrula whois example.com
kastrula trace google.com
kastrula http httpbin.org
kastrula proxy grab --check
kastrula proxy check socks5://1.2.3.4:1080
kastrula ws wss://echo.websocket.events --sniff -d 10
kastrula recon example.com
```

На Pydroid запускай `cli.py` без аргументов — интерактивный режим.

## Зависимости

- `httpx[http2]` — HTTP/2
- `cryptography` — сертификаты
- `websockets` — WebSocket

DNS, scan, whois, trace, proxy — на чистых сокетах.

## Лицензия

MIT — KrScript
