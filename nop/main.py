# nop/main.py
import argparse
import sys
import os
from nop.network.ping import ping_host
from nop.network.portscan import port_scan
from nop.network.dns import dns_lookup
from nop.network.sweep import sweep
from nop.network.geoip import geoip_lookup
from nop.network.ssl import get_ssl_info
from nop.network.traceroute import traceroute
from nop.osint.whois_lookup import whois_lookup
from nop.osint.headers import get_headers
from nop.osint.subdomains import subdomain_scan
from nop.osint.reverse_dns import reverse_dns_sweep
from nop.utils.validators import validate_target, is_valid_port, is_domain, is_cidr, is_ip, resolve
from nop.utils.output import save_json, save_txt, list_outputs, OUTPUT_DIR

BANNER = r"""
 _   _  ___  ____  
| \ | |/ _ \|  _ \ 
|  \| | | | | |_) |
| |\  | |_| |  __/ 
|_| \_|\___/|_|    

  Network OSINT Platform
"""

MENU = """
┌──────────────────────────────────────────┐
│                 COMMANDS                 │
├────────────┬─────────────────────────────┤
│ Network    │                             │
│  ping      │ <host>                      │
│  portscan  │ <host> [range]              │
│  dns       │ <host|ip> [record_type]     │
│  sweep     │ <cidr>                      │
│  geoip     │ <ip|domain>                 │
│  ssl       │ <host> [port]               │
│  traceroute│ <host>                      │
├────────────┼─────────────────────────────┤
│ OSINT      │                             │
│  whois     │ <domain>                    │
│  headers   │ <url>                       │
│  subdomains│ <domain>                    │
│  rdns      │ <cidr>                      │
├────────────┼─────────────────────────────┤
│ Output     │                             │
│  outputs   │ list saved results          │
├────────────┼─────────────────────────────┤
│  help      │ show this menu              │
│  exit      │ quit                        │
└────────────┴─────────────────────────────┘

  tip: append --save to any command to save output
  tip: append --json to any command to save as JSON
"""

def handle_command(parts):
    if not parts:
        return

    # check for output flags before routing the command
    save_as_txt  = "--save" in parts
    save_as_json = "--json" in parts
    # strip flags out so they don't confuse command parsing
    parts = [p for p in parts if p not in ("--save", "--json")]

    if not parts:
        return

    cmd = parts[0].lower()
    # buffer printed lines if saving so we can write them to file
    output_lines = []

    def out(line=""):
        # print and optionally buffer
        print(line)
        output_lines.append(line)

    match cmd:
        case "ping":
            if len(parts) < 2:
                out("Usage: ping <host> [--save] [--json]")
                return
            t = validate_target(parts[1])
            if not t["valid"]:
                out(f"  ✗  {t['error']}")
                return
            result = ping_host(parts[1])
            if result.get("alive"):
                out(f"  ✓  {result['host']} is up  |  latency: {result['latency']} ms")
            else:
                out(f"  ✗  {result['host']} is unreachable  |  {result.get('error', '')}")
            if save_as_json:
                path = save_json("ping", parts[1], result)
                print(f"  saved → {path}")
            elif save_as_txt:
                path = save_txt("ping", parts[1], output_lines)
                print(f"  saved → {path}")

        case "portscan":
            if len(parts) < 2:
                out("Usage: portscan <host> [range] [--save] [--json]")
                out("       portscan 1.1.1.1           # scans common ports")
                out("       portscan 1.1.1.1 1-65535    # scans port range")
                return
            t = validate_target(parts[1])
            if not t["valid"]:
                out(f"  ✗  {t['error']}")
                return
            host = parts[1]
            ports = None
            remaining = [p for p in parts[2:]]
            if remaining:
                try:
                    start, end = remaining[0].split("-")
                    if not is_valid_port(start) or not is_valid_port(end):
                        out("  ✗  port range must be between 1 and 65535")
                        return
                    ports = list(range(int(start), int(end) + 1))
                except ValueError:
                    out("  invalid range format — use start-end e.g. 1-1024")
                    return
            out(f"  scanning {host}...")
            result = port_scan(host, ports)
            if not result["open_ports"]:
                out(f"  no open ports found ({result['total_scanned']} scanned)")
            else:
                out(f"\n  {'PORT':<8} {'SERVICE':<14} {'BANNER'}")
                out(f"  {'─'*8} {'─'*14} {'─'*30}")
                for p in result["open_ports"]:
                    banner = p["banner"] or ""
                    out(f"  {p['port']:<8} {p['service']:<14} {banner}")
                out(f"\n  {len(result['open_ports'])} open port(s) — {result['total_scanned']} scanned")
            if save_as_json:
                path = save_json("portscan", host, result)
                print(f"  saved → {path}")
            elif save_as_txt:
                path = save_txt("portscan", host, output_lines)
                print(f"  saved → {path}")

        case "dns":
            if len(parts) < 2:
                out("Usage: dns <host|ip> [record_type] [--save] [--json]")
                out("       dns google.com          # full record dump")
                out("       dns google.com MX       # specific record type")
                out("       dns 8.8.8.8             # reverse lookup")
                return
            t = validate_target(parts[1])
            if not t["valid"]:
                out(f"  ✗  {t['error']}")
                return
            record_type = parts[2].upper() if len(parts) == 3 else None
            result = dns_lookup(parts[1], record_type)
            if "reverse" in result:
                r = result["reverse"]
                if r.get("hostname"):
                    out(f"  {r['ip']}  →  {r['hostname']}")
                else:
                    out(f"  ✗  no PTR record found  |  {r.get('error', '')}")
            elif "records" in result and isinstance(result["records"], dict):
                for rtype, values in result["records"].items():
                    out(f"\n  {rtype}")
                    for v in values:
                        out(f"    {v}")
            elif "records" in result:
                r = result["records"]
                if r.get("error"):
                    out(f"  ✗  {r['error']}")
                elif not r.get("records"):
                    out(f"  no {r['type']} records found")
                else:
                    out(f"\n  {r['type']}")
                    for v in r["records"]:
                        out(f"    {v}")
            if save_as_json:
                path = save_json("dns", parts[1], result)
                print(f"  saved → {path}")
            elif save_as_txt:
                path = save_txt("dns", parts[1], output_lines)
                print(f"  saved → {path}")

        case "sweep":
            if len(parts) < 2:
                out("Usage: sweep <cidr> [--save] [--json]")
                out("       sweep 192.168.1.0/24")
                return
            if not is_cidr(parts[1]):
                out("  ✗  invalid CIDR range — use format 192.168.1.0/24")
                return
            out(f"  sweeping {parts[1]}...")
            result = sweep(parts[1])
            if result.get("error"):
                out(f"  ✗  {result['error']}")
            elif not result["alive"]:
                out(f"  no hosts found ({result['total_scanned']} scanned)")
            else:
                out(f"\n  {'IP':<20} STATUS")
                out(f"  {'─'*20} {'─'*6}")
                for ip in result["alive"]:
                    out(f"  {ip:<20} ✓ up")
                out(f"\n  {result['total_alive']} host(s) up — {result['total_scanned']} scanned")
            if save_as_json:
                path = save_json("sweep", parts[1], result)
                print(f"  saved → {path}")
            elif save_as_txt:
                path = save_txt("sweep", parts[1], output_lines)
                print(f"  saved → {path}")

        case "geoip":
            if len(parts) < 2:
                out("Usage: geoip <ip|domain> [--save] [--json]")
                out("       geoip 1.1.1.1")
                out("       geoip google.com")
                return
            t = validate_target(parts[1])
            if not t["valid"]:
                out(f"  ✗  {t['error']}")
                return
            target = parts[1]
            if not is_ip(target):
                resolved = resolve(target)
                if not resolved:
                    out(f"  ✗  could not resolve {target}")
                    return
                out(f"  resolved {target} → {resolved}")
                target = resolved
            out(f"  looking up {target}...")
            result = geoip_lookup(target)
            if result.get("error"):
                out(f"  ✗  {result['error']}")
            else:
                out()
                for field, value in result["data"].items():
                    if value:
                        out(f"  {field.upper():<12} {value}")
            if save_as_json:
                path = save_json("geoip", target, result)
                print(f"  saved → {path}")
            elif save_as_txt:
                path = save_txt("geoip", target, output_lines)
                print(f"  saved → {path}")

        case "ssl":
            if len(parts) < 2:
                out("Usage: ssl <host> [port] [--save] [--json]")
                out("       ssl google.com")
                out("       ssl google.com 8443")
                return
            t = validate_target(parts[1])
            if not t["valid"]:
                out(f"  ✗  {t['error']}")
                return
            port = 443
            if len(parts) == 3:
                if not is_valid_port(parts[2]):
                    out("  ✗  invalid port")
                    return
                port = int(parts[2])
            out(f"  grabbing SSL info for {parts[1]}:{port}...")
            result = get_ssl_info(parts[1], port)
            if result.get("error"):
                out(f"  ✗  {result['error']}")
            else:
                expiry_warn = " ⚠ EXPIRING SOON" if 0 <= result["days_left"] <= 30 else ""
                expired_flag = " ✗ EXPIRED" if result["expired"] else ""
                out()
                out(f"  {'SUBJECT':<16} {result['subject']}")
                out(f"  {'ISSUER':<16} {result['issuer']}")
                out(f"  {'VALID FROM':<16} {result['valid_from']}")
                out(f"  {'VALID UNTIL':<16} {result['valid_until']}{expiry_warn}{expired_flag}")
                out(f"  {'DAYS LEFT':<16} {result['days_left']}")
                out(f"  {'TLS VERSION':<16} {result['tls_version']}")
                out(f"  {'CIPHER':<16} {result['cipher']}")
                if result["sans"]:
                    out(f"\n  SUBJECT ALT NAMES")
                    for san in result["sans"]:
                        out(f"    {san}")
            if save_as_json:
                path = save_json("ssl", parts[1], result)
                print(f"  saved → {path}")
            elif save_as_txt:
                path = save_txt("ssl", parts[1], output_lines)
                print(f"  saved → {path}")

        case "traceroute":
            if len(parts) < 2:
                out("Usage: traceroute <host> [--save] [--json]")
                out("       traceroute google.com")
                out("       traceroute 1.1.1.1")
                return
            t = validate_target(parts[1])
            if not t["valid"]:
                out(f"  ✗  {t['error']}")
                return
            out(f"  tracing route to {parts[1]}...")
            result = traceroute(parts[1])
            if result.get("error"):
                out(f"  ✗  {result['error']}")
            else:
                out(f"\n  {'HOP':<6} {'IP':<18} {'HOST':<40} {'RTT'}")
                out(f"  {'─'*6} {'─'*18} {'─'*40} {'─'*10}")
                for hop in result["hops"]:
                    ip   = hop["ip"] or "*"
                    host = hop["host"] or "*"
                    rtt  = f"{hop['rtt']} ms" if hop["rtt"] else "*"
                    out(f"  {hop['hop']:<6} {ip:<18} {host:<40} {rtt}")
            if save_as_json:
                path = save_json("traceroute", parts[1], result)
                print(f"  saved → {path}")
            elif save_as_txt:
                path = save_txt("traceroute", parts[1], output_lines)
                print(f"  saved → {path}")

        case "subdomains":
            if len(parts) < 2:
                out("Usage: subdomains <domain> [--save] [--json]")
                out("       subdomains google.com")
                return
            if not is_domain(parts[1]):
                out("  ✗  subdomains requires a domain name e.g. google.com")
                return
            out(f"  scanning subdomains for {parts[1]}...")
            result = subdomain_scan(parts[1])
            if not result["found"]:
                out(f"  no subdomains found ({result['total_checked']} checked)")
            else:
                out(f"\n  {'SUBDOMAIN':<45} {'IP'}")
                out(f"  {'─'*45} {'─'*16}")
                for s in result["found"]:
                    out(f"  {s['subdomain']:<45} {s['ip']}")
                out(f"\n  {result['total_found']} found — {result['total_checked']} checked")
            if save_as_json:
                path = save_json("subdomains", parts[1], result)
                print(f"  saved → {path}")
            elif save_as_txt:
                path = save_txt("subdomains", parts[1], output_lines)
                print(f"  saved → {path}")

        case "rdns":
            if len(parts) < 2:
                out("Usage: rdns <cidr> [--save] [--json]")
                out("       rdns 192.168.1.0/24")
                return
            if not is_cidr(parts[1]):
                out("  ✗  invalid CIDR range — use format 192.168.1.0/24")
                return
            out(f"  reverse DNS sweep of {parts[1]}...")
            result = reverse_dns_sweep(parts[1])
            if result.get("error"):
                out(f"  ✗  {result['error']}")
            elif not result["resolved"]:
                out(f"  no hostnames resolved ({result['total_scanned']} scanned)")
            else:
                out(f"\n  {'IP':<20} {'HOSTNAME'}")
                out(f"  {'─'*20} {'─'*40}")
                for r in result["resolved"]:
                    out(f"  {r['ip']:<20} {r['hostname']}")
                out(f"\n  {result['total_resolved']} resolved — {result['total_scanned']} scanned")
            if save_as_json:
                path = save_json("rdns", parts[1], result)
                print(f"  saved → {path}")
            elif save_as_txt:
                path = save_txt("rdns", parts[1], output_lines)
                print(f"  saved → {path}")

        case "whois":
            if len(parts) < 2:
                out("Usage: whois <domain> [--save] [--json]")
                out("       whois google.com")
                return
            if not is_domain(parts[1]):
                out("  ✗  whois requires a domain name e.g. google.com")
                return
            out(f"  looking up {parts[1]}...")
            result = whois_lookup(parts[1])
            if result.get("error"):
                out(f"  ✗  {result['error']}")
            else:
                out()
                for field, value in result["data"].items():
                    label = field.replace("_", " ").upper()
                    if isinstance(value, list):
                        out(f"  {label}")
                        for v in value:
                            out(f"    {v}")
                    else:
                        out(f"  {label:<20} {value}")
            if save_as_json:
                path = save_json("whois", parts[1], result)
                print(f"  saved → {path}")
            elif save_as_txt:
                path = save_txt("whois", parts[1], output_lines)
                print(f"  saved → {path}")

        case "headers":
            if len(parts) < 2:
                out("Usage: headers <url> [--save] [--json]")
                out("       headers google.com")
                out("       headers https://google.com")
                return
            out(f"  fetching headers for {parts[1]}...")
            result = get_headers(parts[1])
            if result.get("error"):
                out(f"  ✗  {result['error']}")
            else:
                out(f"\n  STATUS  {result['status']}")
                if result["tech"]:
                    out(f"\n  TECH STACK")
                    for k, v in result["tech"].items():
                        out(f"    {k:<30} {v}")
                else:
                    out(f"\n  TECH STACK    none detected")
                out(f"\n  SECURITY HEADERS")
                for h, info in result["security"].items():
                    if info["present"]:
                        out(f"    ✓  {h}")
                    else:
                        out(f"    ✗  {h:<40} MISSING")
            if save_as_json:
                path = save_json("headers", parts[1], result)
                print(f"  saved → {path}")
            elif save_as_txt:
                path = save_txt("headers", parts[1], output_lines)
                print(f"  saved → {path}")

        case "outputs":
            files = list_outputs()
            if not files:
                print(f"  no saved outputs found in {OUTPUT_DIR}")
            else:
                print(f"\n  saved outputs in {OUTPUT_DIR}\n")
                for f in files:
                    print(f"    {os.path.basename(f)}")
                print()

        case "help":
            print(MENU)

        case "exit":
            print("bye.")
            sys.exit(0)

        case _:
            print(f"  unknown command: '{cmd}' — type 'help' for the menu")


def interactive_mode():
    print(BANNER)
    print(MENU)
    while True:
        try:
            raw = input("nop > ").strip()
            if raw:
                handle_command(raw.split())
        except (KeyboardInterrupt, EOFError):
            print("\nbye.")
            sys.exit(0)


def cli_mode():
    parser = argparse.ArgumentParser(prog="nop")
    parser.add_argument("command")
    parser.add_argument("target", nargs="?")
    args = parser.parse_args()
    handle_command([args.command, args.target] if args.target else [args.command])


if __name__ == "__main__" or len(sys.argv) == 1:
    interactive_mode()
else:
    cli_mode()
