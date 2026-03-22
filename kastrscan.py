#!/usr/bin/env python3
"""
🍲 KastrulaScan — сетевой сканер с красивым выводом
Построен на библиотеке kastrula

Использование:
    python kastrscan.py example.com
    python kastrscan.py example.com -p 22,80,443,8080
    python kastrscan.py example.com --full
    python kastrscan.py example.com --tls
    python kastrscan.py example.com --dns
"""

import sys
import time
import argparse
from datetime import datetime

# ── Цвета ──────────────────────────────────────────────────────────────────

class C:
    """ANSI-цвета для терминала."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    BG_RED  = "\033[41m"
    BG_GREEN = "\033[42m"

def colored(text, color):
    return f"{color}{text}{C.RESET}"

def bold(text):
    return f"{C.BOLD}{text}{C.RESET}"

# ── Визуальные элементы ────────────────────────────────────────────────────

LOGO = f"""{C.CYAN}{C.BOLD}
    ╔═══════════════════════════════════════╗
    ║  🍲  K A S T R U L A  S C A N  🍲    ║
    ║     сетевой сканер v1.0               ║
    ╚═══════════════════════════════════════╝{C.RESET}
"""

BOX_TL = "╭"
BOX_TR = "╮"
BOX_BL = "╰"
BOX_BR = "╯"
BOX_H  = "─"
BOX_V  = "│"
BOX_T  = "├"
BOX_B  = "┤"

def box_top(title="", width=60):
    if title:
        title_str = f" {title} "
        left = BOX_TL + BOX_H * 2
        right = BOX_H * (width - len(title_str) - 3) + BOX_TR
        return colored(left, C.GRAY) + colored(title_str, C.BOLD + C.CYAN) + colored(right, C.GRAY)
    return colored(BOX_TL + BOX_H * width + BOX_TR, C.GRAY)

def box_mid(width=60):
    return colored(BOX_T + BOX_H * width + BOX_B, C.GRAY)

def box_bottom(width=60):
    return colored(BOX_BL + BOX_H * width + BOX_BR, C.GRAY)

def box_line(text, width=60):
    clean_len = len(text.replace(C.RESET, "").replace(C.BOLD, "")
                       .replace(C.RED, "").replace(C.GREEN, "")
                       .replace(C.YELLOW, "").replace(C.BLUE, "")
                       .replace(C.MAGENTA, "").replace(C.CYAN, "")
                       .replace(C.WHITE, "").replace(C.GRAY, "")
                       .replace(C.DIM, "").replace(C.BG_RED, "")
                       .replace(C.BG_GREEN, ""))
    padding = width - clean_len - 1
    if padding < 0:
        padding = 0
    return colored(BOX_V, C.GRAY) + " " + text + " " * padding + colored(BOX_V, C.GRAY)

def progress_bar(current, total, width=30, label=""):
    filled = int(width * current / total) if total > 0 else 0
    bar = colored("█" * filled, C.GREEN) + colored("░" * (width - filled), C.GRAY)
    pct = f"{100 * current / total:.0f}%" if total > 0 else "0%"
    sys.stdout.write(f"\r  {label} [{bar}] {pct} ({current}/{total})  ")
    sys.stdout.flush()

def spinner_msg(msg):
    sys.stdout.write(f"\r  {colored('⟳', C.CYAN)} {msg}...  ")
    sys.stdout.flush()

def done_msg(msg):
    print(f"\r  {colored('✓', C.GREEN)} {msg}          ")

def fail_msg(msg):
    print(f"\r  {colored('✗', C.RED)} {msg}          ")

def warn_msg(msg):
    print(f"  {colored('⚠', C.YELLOW)} {msg}")

# ── Модуль: DNS ────────────────────────────────────────────────────────────

def scan_dns(target):
    print()
    print(box_top("DNS RECORDS", 60))
    print(box_line(f"Target: {colored(target, C.WHITE + C.BOLD)}", 60))
    print(box_mid(60))

    try:
        from kastrula import dns_records, reverse_lookup
        spinner_msg("Запрашиваю DNS записи")
        records = dns_records(target, ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"])
        done_msg(f"Получено {len(records)} записей")

        type_colors = {
            "A": C.GREEN, "AAAA": C.CYAN, "CNAME": C.YELLOW,
            "MX": C.MAGENTA, "NS": C.BLUE, "TXT": C.GRAY, "SOA": C.DIM,
        }

        if records:
            for r in records:
                tc = type_colors.get(r.rtype, C.WHITE)
                rtype = colored(f"{r.rtype:6}", tc + C.BOLD)
                ttl = colored(f"{r.ttl:>5}s", C.GRAY)
                val = r.value
                if len(val) > 45:
                    val = val[:42] + "..."
                print(box_line(f"  {rtype} {ttl}  {val}", 60))

            # Reverse lookup для первого A-записи
            a_records = [r for r in records if r.rtype == "A"]
            if a_records:
                ip = a_records[0].value
                spinner_msg(f"Reverse lookup {ip}")
                try:
                    ptrs = reverse_lookup(ip)
                    if ptrs:
                        done_msg(f"PTR: {ptrs[0]}")
                        print(box_line(f"  {colored('PTR   ', C.RED + C.BOLD)} {colored('    -', C.GRAY)}  {ptrs[0]}", 60))
                    else:
                        done_msg("PTR: нет записи")
                except Exception:
                    fail_msg("Reverse lookup не удался")
        else:
            print(box_line(colored("  Записей не найдено", C.YELLOW), 60))

    except Exception as e:
        fail_msg(f"DNS ошибка: {e}")
        print(box_line(colored(f"  Ошибка: {e}", C.RED), 60))

    print(box_bottom(60))


# ── Модуль: TLS ────────────────────────────────────────────────────────────

def scan_tls(target):
    print()
    print(box_top("TLS ANALYSIS", 60))
    print(box_line(f"Target: {colored(target + ':443', C.WHITE + C.BOLD)}", 60))
    print(box_mid(60))

    try:
        from kastrula import TLSProbe, ja3_fingerprint

        # Handshake
        spinner_msg("TLS handshake")
        probe = TLSProbe(target)
        info = probe.handshake()
        done_msg("Handshake OK")

        # Protocol & Cipher
        proto_color = C.GREEN if "1.3" in info.protocol_version else C.YELLOW
        print(box_line(f"  Protocol:  {colored(info.protocol_version, proto_color + C.BOLD)}", 60))
        print(box_line(f"  Cipher:    {colored(info.cipher_name, C.CYAN)}", 60))
        print(box_line(f"  Bits:      {colored(str(info.cipher_bits), C.WHITE)}", 60))
        print(box_line(f"  ALPN:      {colored(info.alpn or 'none', C.GRAY)}", 60))

        # Certificate
        cert = info.cert
        print(box_mid(60))
        print(box_line(colored("  📜 CERTIFICATE", C.BOLD), 60))

        cn = cert.subject.get("CN", "?")
        print(box_line(f"  CN:        {colored(cn, C.WHITE + C.BOLD)}", 60))
        print(box_line(f"  Issuer:    {colored(cert.issuer.get('O', cert.issuer.get('CN', '?')), C.CYAN)}", 60))

        days = cert.days_left()
        if days < 0:
            days_str = colored(f"EXPIRED ({abs(days)}d ago)", C.BG_RED + C.WHITE + C.BOLD)
        elif days < 30:
            days_str = colored(f"{days} дней ⚠️", C.YELLOW + C.BOLD)
        else:
            days_str = colored(f"{days} дней ✓", C.GREEN)
        print(box_line(f"  Expires:   {days_str}", 60))
        print(box_line(f"  Key:       {colored(str(cert.public_key_bits) + ' bit', C.WHITE)}", 60))

        # SANs
        if cert.san:
            sans_display = ", ".join(cert.san[:4])
            if len(cert.san) > 4:
                sans_display += f" (+{len(cert.san)-4})"
            print(box_line(f"  SANs:      {colored(sans_display, C.GRAY)}", 60))

        # SHA256
        fp_short = cert.fingerprint_sha256[:23] + "..."
        print(box_line(f"  SHA256:    {colored(fp_short, C.DIM)}", 60))

        # Chain
        if info.chain and len(info.chain) > 1:
            print(box_mid(60))
            print(box_line(colored("  🔗 CHAIN", C.BOLD), 60))
            for i, c in enumerate(info.chain):
                arrow = "└─" if i == len(info.chain) - 1 else "├─"
                cn = c.subject.get("CN", "?")
                print(box_line(f"    {colored(arrow, C.GRAY)} {cn}", 60))

        # Supported protocols
        spinner_msg("Проверяю версии TLS")
        protocols = probe.supported_protocols()
        done_msg(f"Поддерживается: {', '.join(protocols)}")
        protos_str = "  ".join(
            colored(p, C.GREEN + C.BOLD) if "1.3" in p else colored(p, C.YELLOW)
            for p in protocols
        )
        print(box_line(f"  Versions:  {protos_str}", 60))

        # JA3
        spinner_msg("JA3 fingerprint")
        try:
            ja3 = ja3_fingerprint(target)
            done_msg(f"JA3: {ja3.ja3_hash[:16]}...")
            print(box_line(f"  JA3:       {colored(ja3.ja3_hash, C.MAGENTA)}", 60))
        except Exception:
            fail_msg("JA3 не удался")

    except Exception as e:
        fail_msg(f"TLS ошибка: {e}")
        print(box_line(colored(f"  Ошибка: {e}", C.RED), 60))

    print(box_bottom(60))


# ── Модуль: Порты ──────────────────────────────────────────────────────────

def scan_ports(target, ports=None):
    print()
    print(box_top("PORT SCAN", 60))
    print(box_line(f"Target: {colored(target, C.WHITE + C.BOLD)}", 60))
    print(box_mid(60))

    try:
        from kastrula import port_scan

        if ports:
            port_list = [int(p.strip()) for p in ports.split(",")]
            port_label = f"{len(port_list)} портов"
        else:
            port_list = None
            port_label = "top ports"

        spinner_msg(f"Сканирую {port_label}")
        start = time.time()
        result = port_scan(target, ports=port_list, timeout=2.0, threads=50)
        elapsed = time.time() - start

        done_msg(f"Готово за {elapsed:.1f}s — найдено {len(result.open_ports)} открытых")

        print(box_line(f"  Host: {colored(result.ip, C.WHITE)}", 60))
        print(box_line(
            f"  Open: {colored(str(len(result.open_ports)), C.GREEN + C.BOLD)}  "
            f"Closed: {colored(str(result.closed_count), C.RED)}  "
            f"Filtered: {colored(str(result.filtered_count), C.YELLOW)}",
            60
        ))
        print(box_mid(60))

        if result.open_ports:
            # Header
            header = (
                f"  {colored('PORT', C.BOLD):>20}  "
                f"{colored('SERVICE', C.BOLD):<22}  "
                f"{colored('INFO', C.BOLD)}"
            )
            print(box_line(header, 60))
            print(box_line(colored("  " + "─" * 50, C.GRAY), 60))

            for p in result.open_ports:
                port_str = colored(f"{p.port}/tcp", C.GREEN + C.BOLD)
                svc = colored(p.service, C.CYAN)
                tls_mark = colored(" 🔒", C.YELLOW) if p.tls else "   "

                banner_short = ""
                if p.banner:
                    banner_short = p.banner.replace("\r", "").replace("\n", " ")[:25]
                    banner_short = colored(banner_short, C.GRAY)

                print(box_line(f"  {port_str:>20}  {svc:<22}{tls_mark} {banner_short}", 60))
        else:
            print(box_line(colored("  Все порты закрыты или фильтрованы", C.YELLOW), 60))

    except Exception as e:
        fail_msg(f"Scan ошибка: {e}")
        print(box_line(colored(f"  Ошибка: {e}", C.RED), 60))

    print(box_bottom(60))


# ── Модуль: HTTP ───────────────────────────────────────────────────────────

def scan_http(target):
    print()
    print(box_top("HTTP PROBE", 60))

    try:
        from kastrula import KastClient

        for scheme in ["https", "http"]:
            url = f"{scheme}://{target}"
            spinner_msg(f"Пробую {url}")

            try:
                with KastClient(profile="chrome_120") as client:
                    resp = client.head(url)

                done_msg(f"{url} → {resp.status_code}")

                status_color = C.GREEN if resp.ok else C.YELLOW if resp.status_code < 500 else C.RED
                print(box_line(f"  URL:       {colored(url, C.WHITE + C.BOLD)}", 60))
                print(box_line(f"  Status:    {colored(str(resp.status_code), status_color + C.BOLD)}", 60))
                print(box_line(f"  Server:    {colored(resp.server, C.CYAN)}", 60))
                print(box_line(f"  HTTP:      {colored(resp.http_version, C.WHITE)}", 60))
                print(box_line(f"  Time:      {colored(f'{resp.elapsed_ms:.0f}ms', C.GRAY)}", 60))

                # Interesting headers
                interesting = ["x-powered-by", "x-frame-options", "content-security-policy",
                              "strict-transport-security", "x-content-type-options"]
                found_headers = []
                for h in interesting:
                    val = resp.headers.get(h)
                    if val:
                        found_headers.append((h, val))

                if found_headers:
                    print(box_mid(60))
                    print(box_line(colored("  🛡️  SECURITY HEADERS", C.BOLD), 60))
                    for h, v in found_headers:
                        v_short = v[:35] + "..." if len(v) > 35 else v
                        print(box_line(f"  {colored(h, C.MAGENTA)}: {v_short}", 60))

                # Missing security headers
                missing = [h for h in interesting if h not in resp.headers]
                if missing:
                    print(box_line(colored(f"  Missing: {', '.join(missing[:3])}", C.YELLOW + C.DIM), 60))

            except Exception as e:
                fail_msg(f"{url} — {e}")

    except Exception as e:
        fail_msg(f"HTTP ошибка: {e}")

    print(box_bottom(60))


# ── Полный скан ────────────────────────────────────────────────────────────

def full_scan(target, ports=None):
    print(LOGO)
    print(f"  {colored('Target:', C.GRAY)} {colored(target, C.WHITE + C.BOLD)}")
    print(f"  {colored('Time:', C.GRAY)}   {colored(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), C.WHITE)}")
    print()

    total_start = time.time()

    scan_dns(target)
    scan_ports(target, ports)
    scan_tls(target)
    scan_http(target)

    total = time.time() - total_start
    print()
    print(f"  {colored('═' * 50, C.GRAY)}")
    print(f"  🍲 Сканирование завершено за {colored(f'{total:.1f}s', C.GREEN + C.BOLD)}")
    print()


# ── CLI ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="🍲 KastrulaScan — сетевой сканер",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  python kastrscan.py example.com           # полный скан
  python kastrscan.py example.com --ports 22,80,443
  python kastrscan.py example.com --dns     # только DNS
  python kastrscan.py example.com --tls     # только TLS
  python kastrscan.py example.com --http    # только HTTP
        """
    )
    parser.add_argument("target", help="Домен или IP для сканирования")
    parser.add_argument("-p", "--ports", help="Порты через запятую (22,80,443)")
    parser.add_argument("--dns", action="store_true", help="Только DNS")
    parser.add_argument("--tls", action="store_true", help="Только TLS")
    parser.add_argument("--http", action="store_true", help="Только HTTP")
    parser.add_argument("--scan", action="store_true", help="Только порты")
    parser.add_argument("--full", action="store_true", help="Полный скан (по умолчанию)")

    args = parser.parse_args()

    # Если ничего не выбрано — полный скан
    specific = args.dns or args.tls or args.http or args.scan

    if not specific:
        full_scan(args.target, args.ports)
    else:
        print(LOGO)
        if args.dns:
            scan_dns(args.target)
        if args.scan or args.ports:
            scan_ports(args.target, args.ports)
        if args.tls:
            scan_tls(args.target)
        if args.http:
            scan_http(args.target)
        print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        # Интерактивный режим для Pydroid
        print(LOGO)
        target = input("  Введи домен или IP: ").strip()
        if not target:
            print("  Нужен домен!")
            sys.exit(1)
        mode = input("  Режим (full/dns/tls/http/scan): ").strip() or "full"
        ports = None
        if mode in ("scan", "full"):
            p = input("  Порты (Enter = top): ").strip()
            if p:
                ports = p

        if mode == "dns":
            scan_dns(target)
        elif mode == "tls":
            scan_tls(target)
        elif mode == "http":
            scan_http(target)
        elif mode == "scan":
            scan_ports(target, ports)
        else:
            full_scan(target, ports)
    else:
        main()
