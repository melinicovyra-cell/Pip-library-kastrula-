#!/usr/bin/env python3
"""
kastrula CLI - subcommands for all modules.
"""

import sys
import time
import argparse
from datetime import datetime


class C:
    R = "\033[0m";  B = "\033[1m";  D = "\033[2m"
    RED = "\033[91m"; GRN = "\033[92m"; YLW = "\033[93m"
    BLU = "\033[94m"; MAG = "\033[95m"; CYN = "\033[96m"
    WHT = "\033[97m"; GRY = "\033[90m"

def c(text, color): return f"{color}{text}{C.R}"
def header(title):
    print(f"\n  {c('╭─', C.GRY)} {c(title, C.CYN + C.B)} {c('─' * max(1, 50 - len(title)), C.GRY)}")
def footer():
    print(f"  {c('╰' + '─' * 56, C.GRY)}\n")
def row(key, val, kcolor=C.GRY, vcolor=C.WHT):
    print(f"  {c('│', C.GRY)} {c(key + ':', kcolor):>28} {c(str(val), vcolor)}")
def ok(msg): print(f"  {c('│', C.GRY)} {c('✓', C.GRN)} {msg}")
def warn(msg): print(f"  {c('│', C.GRY)} {c('⚠', C.YLW)} {msg}")
def fail(msg): print(f"  {c('│', C.GRY)} {c('✗', C.RED)} {msg}")
def spin(msg):
    sys.stdout.write(f"\r  {c('│', C.GRY)} {c('⟳', C.CYN)} {msg}...\033[K")
    sys.stdout.flush()

LOGO = c("""
    ╔═══════════════════════════════════════╗
    ║  🍲  K A S T R U L A  v0.2.0  🍲     ║
    ╚═══════════════════════════════════════╝""", C.CYN + C.B)


def cmd_scan(args):
    from kastrula import port_scan, udp_scan, os_fingerprint, run_scripts
    header(f"PORT SCAN — {args.target}")
    ports = [int(p) for p in args.ports.split(",")] if args.ports else None
    spin("TCP scan")
    result = port_scan(args.target, ports=ports, timeout=args.timeout, threads=50)
    ok(f"{len(result.open_ports)} open, {result.closed_count} closed, {result.filtered_count} filtered ({result.scan_time_ms:.0f}ms)")
    row("Host", f"{result.host} ({result.ip})")
    for p in result.open_ports:
        tls = c(" 🔒", C.YLW) if p.tls else ""
        banner = p.banner.replace("\n"," ")[:30] if p.banner else ""
        print(f"  {c('│', C.GRY)}   {c(str(p.port)+'/tcp', C.GRN+C.B):>20}  {c(p.service, C.CYN):<18}{tls} {c(banner, C.GRY)}")
    if getattr(args, 'udp', False):
        spin("UDP scan"); udp = udp_scan(args.target, timeout=args.timeout)
        ok(f"UDP: {len(udp.open_ports)} open|filtered")
        for p in udp.open_ports:
            print(f"  {c('│', C.GRY)}   {c(str(p.port)+'/udp', C.YLW+C.B):>20}  {c(p.service, C.CYN)}")
    if getattr(args, 'os', False):
        spin("OS fingerprint"); guesses = os_fingerprint(args.target)
        for g in guesses: row("OS", f"{g.os_name} ({g.confidence:.0f}%)", vcolor=C.MAG)
    if getattr(args, 'scripts', False):
        spin("Scripts"); scripts = run_scripts(args.target, ports=[p.port for p in result.open_ports])
        for s in scripts:
            if s.success: print(f"  {c('│', C.GRY)}   {c(s.name, C.BLU)}({s.port}): {s.output[:50]}")
    footer()

def cmd_tls(args):
    from kastrula import TLSProbe, ja3_fingerprint, jarm_fingerprint, cipher_enum
    header(f"TLS — {args.target}:443")
    spin("Handshake"); probe = TLSProbe(args.target); hi = probe.handshake(); ok("Handshake OK")
    pc = C.GRN if "1.3" in hi.protocol_version else C.YLW
    row("Protocol", hi.protocol_version, vcolor=pc); row("Cipher", hi.cipher_name, vcolor=C.CYN)
    row("Bits", hi.cipher_bits); row("ALPN", hi.alpn or "none")
    cert = hi.cert
    row("CN", cert.subject.get("CN","?"), vcolor=C.WHT+C.B)
    row("Issuer", cert.issuer.get("O", cert.issuer.get("CN","?")), vcolor=C.CYN)
    days = cert.days_left(); dc = C.GRN if days > 30 else C.YLW if days > 0 else C.RED
    row("Expires", f"{days} days", vcolor=dc); row("Key", f"{cert.public_key_bits} bit")
    if cert.san: row("SANs", ", ".join(cert.san[:4]) + (f" (+{len(cert.san)-4})" if len(cert.san)>4 else ""))
    spin("Protocols"); protos = probe.supported_protocols(); row("Versions", " ".join(protos), vcolor=C.GRN)
    if not getattr(args, 'quick', False):
        spin("JA3")
        try: ja3 = ja3_fingerprint(args.target); row("JA3", ja3.ja3_hash, vcolor=C.MAG)
        except: warn("JA3 failed")
        spin("JARM")
        try: jarm = jarm_fingerprint(args.target); row("JARM", jarm.jarm_hash[:32]+"...", vcolor=C.MAG)
        except: warn("JARM failed")
        spin("Ciphers")
        try:
            ciphers = cipher_enum(args.target); weak = [x for x in ciphers if x.is_weak]
            row("Ciphers", f"{len(ciphers)} total, {len(weak)} weak", vcolor=C.RED if weak else C.GRN)
            for ci in ciphers[:10]:
                m = c("⚠",C.RED) if ci.is_weak else c("✓",C.GRN)
                print(f"  {c('│',C.GRY)}     {m} {c(ci.protocol,C.GRY):>12} {ci.name} ({ci.bits}bit)")
        except: warn("Cipher enum failed")
    footer()

def cmd_dns(args):
    from kastrula import lookup
    header(f"DNS — {args.target}")
    if getattr(args, 'doh', None):
        from kastrula import doh_resolve
        spin("DoH"); ips = doh_resolve(args.target, server=args.doh); ok(f"DoH: {ips}"); footer(); return
    if getattr(args, 'dot', None):
        from kastrula import dot_resolve
        spin("DoT"); ips = dot_resolve(args.target, server=args.dot); ok(f"DoT: {ips}"); footer(); return
    spin("Querying"); result = lookup(args.target, server=getattr(args,'server','8.8.8.8'), timeout=getattr(args,'timeout',5.0))
    ok(f"{len(result.records)} records in {result.response_time_ms:.0f}ms")
    tc = {"A":C.GRN,"AAAA":C.CYN,"CNAME":C.YLW,"MX":C.MAG,"NS":C.BLU,"TXT":C.GRY,"SOA":C.D}
    for r in result.records:
        val = r.value[:50]+"..." if len(r.value)>50 else r.value
        print(f"  {c('│',C.GRY)}   {c(r.rtype, tc.get(r.rtype,C.WHT)+C.B):>18} {c(str(r.ttl)+'s',C.GRY):>10}  {val}")
    footer()

def cmd_whois(args):
    import re
    header(f"WHOIS — {args.target}"); spin("Querying")
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", args.target):
        from kastrula import ip_whois; result = ip_whois(args.target); ok("IP WHOIS")
        row("Network",result.network); row("Org",result.org,vcolor=C.CYN); row("Country",result.country,vcolor=C.YLW)
        row("CIDR",result.cidr); row("Abuse",result.abuse_email,vcolor=C.MAG)
    else:
        from kastrula import whois; result = whois(args.target); ok(f"via {result.whois_server}")
        row("Registrar",result.registrar,vcolor=C.CYN); row("Created",result.creation_date or "?")
        row("Expires",result.expiration_date or "?")
        days = result.days_until_expiry()
        if days is not None:
            dc = C.GRN if days>90 else C.YLW if days>0 else C.RED; row("Days left",days,vcolor=dc)
        row("Registrant",result.registrant or "?"); row("Country",result.registrant_country or "?",vcolor=C.YLW)
        if result.nameservers: row("NS",", ".join(result.nameservers[:4]))
    if getattr(args,'raw',False): print(f"\n{result.raw[:500]}")
    footer()

def cmd_trace(args):
    from kastrula import traceroute, tcp_traceroute
    header(f"TRACEROUTE — {args.target}")
    spin("Tracing")
    result = tcp_traceroute(args.target, port=getattr(args,'port',443), max_hops=getattr(args,'hops',30))
    ok(f"{'Reached' if result.reached else 'Not reached'} in {len(result.hops)} hops ({result.total_ms:.0f}ms)")
    for hop in result.hops:
        if hop.ip:
            host_str = hop.hostname or hop.ip; rtt = c(f"{hop.rtt_ms:.1f}ms", C.GRN if hop.rtt_ms<50 else C.YLW)
            star = c(" ★",C.GRN) if hop.reached else ""
            print(f"  {c('│',C.GRY)}   {c(str(hop.ttl),C.WHT+C.B):>6}  {host_str} {rtt}{star}")
        else:
            print(f"  {c('│',C.GRY)}   {c(str(hop.ttl),C.GRY):>6}  {c('* timeout',C.GRY)}")
    footer()

def cmd_http(args):
    from kastrula import KastClient
    header(f"HTTP — {args.target}")
    profile = getattr(args,'profile','chrome_120')
    for scheme in ["https","http"]:
        url = f"{scheme}://{args.target}"; spin(url)
        try:
            with KastClient(profile=profile) as cl:
                resp = cl.head(url) if getattr(args,'head',False) else cl.get(url)
            sc = C.GRN if resp.ok else C.YLW if resp.status_code<500 else C.RED
            ok(f"{url} → {c(str(resp.status_code), sc)}"); row("Server",resp.server,vcolor=C.CYN)
            row("HTTP",resp.http_version); row("Time",f"{resp.elapsed_ms:.0f}ms")
            for h in ["strict-transport-security","x-frame-options","content-security-policy","x-powered-by"]:
                v = resp.headers.get(h)
                if v: row(h, v[:40], kcolor=C.MAG)
        except Exception as e: fail(f"{url}: {e}")
    footer()

def cmd_proxy(args):
    if getattr(args,'proxy_cmd',None) == "check":
        from kastrula import check_proxy, check_proxies
        header("PROXY CHECK")
        if getattr(args,'file',None):
            with open(args.file) as f: proxies = [l.strip() for l in f if l.strip()]
            spin(f"Checking {len(proxies)}"); result = check_proxies(proxies, timeout=getattr(args,'timeout',10), threads=30)
            ok(result.summary())
            for p in result.alive_proxies[:20]: print(f"  {c('│',C.GRY)}   {c('✓',C.GRN)} {c(p.url,C.WHT)} {c(f'{p.latency_ms:.0f}ms',C.GRY)}")
        else:
            proxy = getattr(args,'proxy_target',''); spin(f"Checking {proxy}")
            p = check_proxy(proxy, timeout=getattr(args,'timeout',10))
            if p.alive: ok(f"ALIVE — {p.latency_ms:.0f}ms"); row("IP",p.external_ip,vcolor=C.CYN)
            else: fail(f"DEAD — {p.error}")
        footer()
    elif getattr(args,'proxy_cmd',None) == "grab":
        from kastrula import grab_proxies, grab_and_check
        header("PROXY GRAB")
        if getattr(args,'check',False):
            spin("Grab & check"); result = grab_and_check(max_grab=getattr(args,'max',200), threads=30)
            ok(result.summary())
            for p in result.alive_proxies[:20]: print(f"  {c('│',C.GRY)}   {c('✓',C.GRN)} {p.url} {c(f'{p.latency_ms:.0f}ms',C.GRY)}")
        else:
            spin("Grabbing"); proxies = grab_proxies(); ok(f"Found {len(proxies)}")
            for p in proxies[:20]: print(f"  {c('│',C.GRY)}   {p}")
            if len(proxies)>20: warn(f"...+{len(proxies)-20} more")
        footer()

def cmd_ws(args):
    from kastrula import ws_probe, ws_sniff
    header(f"WEBSOCKET — {args.url}")
    if getattr(args,'sniff',False):
        spin(f"Sniffing {args.duration}s"); session = ws_sniff(args.url, duration=args.duration)
        ok(f"{session.recv_count} frames in {session.duration_ms:.0f}ms")
        for f in session.frames[:20]:
            print(f"  {c('│',C.GRY)}   {c(f.opcode_name,C.CYN):>6} {c(str(len(f.payload))+'b',C.GRY):>8}  {f.text[:60]}")
    else:
        spin("Probing"); wi = ws_probe(args.url); ok(f"Connected — HTTP {wi.status_code}")
        row("Protocol",wi.protocol or "none"); row("TLS",wi.tls)
    footer()

def cmd_recon(args):
    print(LOGO); print(f"  {c('Target:',C.GRY)} {c(args.target,C.WHT+C.B)}")
    print(f"  {c('Time:',C.GRY)}   {c(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),C.WHT)}")
    start = time.time(); ns = argparse.Namespace
    for name, func, a in [
        ("DNS", cmd_dns, ns(target=args.target, doh=None, dot=None, types=None, server="8.8.8.8", timeout=5.0)),
        ("Scan", cmd_scan, ns(target=args.target, ports=None, timeout=2.0, udp=False, os=True, scripts=True)),
        ("TLS", cmd_tls, ns(target=args.target, quick=True)),
        ("HTTP", cmd_http, ns(target=args.target, profile="chrome_120", head=True)),
        ("WHOIS", cmd_whois, ns(target=args.target, raw=False)),
    ]:
        try: func(a)
        except Exception as e: print(f"  {c(f'{name} error: {e}', C.RED)}")
    print(f"\n  {c('═'*50, C.GRY)}\n  🍲 Full recon in {c(f'{time.time()-start:.1f}s', C.GRN+C.B)}\n")


def interactive():
    print(LOGO)
    target = input("  Цель (домен/IP): ").strip()
    if not target: print("  Нужна цель!"); return
    print(f"\n  1) recon  2) scan  3) tls  4) dns  5) whois  6) trace  7) http  8) proxy grab\n")
    ch = input("  Выбор (1-8): ").strip()
    ns = argparse.Namespace
    m = {
        "1": lambda: cmd_recon(ns(target=target)),
        "2": lambda: cmd_scan(ns(target=target, ports=input("  Порты (Enter=top): ").strip() or None, timeout=2.0, udp=False, os=False, scripts=False)),
        "3": lambda: cmd_tls(ns(target=target, quick=False)),
        "4": lambda: cmd_dns(ns(target=target, doh=None, dot=None, types=None, server="8.8.8.8", timeout=5.0)),
        "5": lambda: cmd_whois(ns(target=target, raw=False)),
        "6": lambda: cmd_trace(ns(target=target, port=443, hops=30)),
        "7": lambda: cmd_http(ns(target=target, profile="chrome_120", head=False)),
        "8": lambda: cmd_proxy(ns(proxy_cmd="grab", check=True, max=50)),
    }
    func = m.get(ch)
    if func: func()
    else: print("  Неизвестная команда")


def build_parser():
    parser = argparse.ArgumentParser(prog="kastrula", description="🍲 kastrula CLI")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("scan"); p.add_argument("target"); p.add_argument("-p","--ports"); p.add_argument("-t","--timeout",type=float,default=2.0)
    p.add_argument("--udp",action="store_true"); p.add_argument("--os",action="store_true"); p.add_argument("--scripts",action="store_true")

    p = sub.add_parser("tls"); p.add_argument("target"); p.add_argument("-q","--quick",action="store_true")

    p = sub.add_parser("dns"); p.add_argument("target"); p.add_argument("--types"); p.add_argument("-s","--server",default="8.8.8.8")
    p.add_argument("-t","--timeout",type=float,default=5.0); p.add_argument("--doh",metavar="URL"); p.add_argument("--dot",metavar="IP")

    p = sub.add_parser("whois"); p.add_argument("target"); p.add_argument("--raw",action="store_true")

    p = sub.add_parser("trace"); p.add_argument("target"); p.add_argument("-p","--port",type=int,default=443); p.add_argument("--hops",type=int,default=30)

    p = sub.add_parser("http"); p.add_argument("target"); p.add_argument("--profile",default="chrome_120"); p.add_argument("--head",action="store_true")

    p = sub.add_parser("proxy"); psub = p.add_subparsers(dest="proxy_cmd")
    pc = psub.add_parser("check"); pc.add_argument("proxy_target",nargs="?"); pc.add_argument("-f","--file"); pc.add_argument("-t","--timeout",type=float,default=10.0)
    pg = psub.add_parser("grab"); pg.add_argument("--check",action="store_true"); pg.add_argument("--max",type=int,default=200)

    p = sub.add_parser("ws"); p.add_argument("url"); p.add_argument("--sniff",action="store_true"); p.add_argument("-d","--duration",type=float,default=10.0)

    p = sub.add_parser("recon"); p.add_argument("target")

    return parser

def main():
    parser = build_parser(); args = parser.parse_args()
    if not args.command: parser.print_help(); return
    cmds = {"scan":cmd_scan,"tls":cmd_tls,"dns":cmd_dns,"whois":cmd_whois,"trace":cmd_trace,"http":cmd_http,"proxy":cmd_proxy,"ws":cmd_ws,"recon":cmd_recon}
    func = cmds.get(args.command)
    if func:
        try: func(args)
        except KeyboardInterrupt: print(f"\n  {c('Прервано',C.YLW)}")
        except Exception as e: print(f"\n  {c(f'Ошибка: {e}',C.RED)}")

if __name__ == "__main__":
    if len(sys.argv) < 2: interactive()
    else: main()
