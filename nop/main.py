# nop/main.py
import argparse
import sys
from nop.network.ping import ping_host
from nop.network.portscan import port_scan
from nop.network.dns import dns_lookup
from nop.network.sweep import sweep
from nop.osint.whois_lookup import whois_lookup
from nop.osint.headers import get_headers
from nop.utils.validators import validate_target, is_valid_port, is_domain, is_cidr

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
├────────────┼─────────────────────────────┤
│ OSINT      │                             │
│  whois     │ <domain>                    │
│  headers   │ <url>                       │
├────────────┼─────────────────────────────┤
│  help      │ show this menu              │
│  exit      │ quit                        │
└────────────┴─────────────────────────────┘
"""

def handle_command(parts):
    if not parts:
        return
    cmd = parts[0].lower()

    match cmd:
        case "ping":
            if len(parts) < 2:
                print("Usage: ping <host>")
                return
            t = validate_target(parts[1])
            if not t["valid"]:
                print(f"  ✗  {t['error']}")
                return
            result = ping_host(parts[1])
            if result.get("alive"):
                print(f"  ✓  {result['host']} is up  |  latency: {result['latency']} ms")
            else:
                print(f"  ✗  {result['host']} is unreachable  |  {result.get('error', '')}")

        case "portscan":
            if len(parts) < 2:
                print("Usage: portscan <host> [range]")
                print("       portscan 1.1.1.1           # scans common ports")
                print("       portscan 1.1.1.1 1-65535    # scans port range")
                return
            t = validate_target(parts[1])
            if not t["valid"]:
                print(f"  ✗  {t['error']}")
                return
            host = parts[1]
            ports = None
            remaining = [p for p in parts[2:]]
            if remaining:
                try:
                    start, end = remaining[0].split("-")
                    if not is_valid_port(start) or not is_valid_port(end):
                        print("  ✗  port range must be between 1 and 65535")
                        return
                    ports = list(range(int(start), int(end) + 1))
                except ValueError:
                    print("  invalid range format — use start-end e.g. 1-1024")
                    return
            print(f"  scanning {host}...")
            result = port_scan(host, ports)
            if not result["open_ports"]:
                print(f"  no open ports found ({result['total_scanned']} scanned)")
            else:
                print(f"\n  {'PORT':<8} {'SERVICE':<14} {'BANNER'}")
                print(f"  {'─'*8} {'─'*14} {'─'*30}")
                for p in result["open_ports"]:
                    banner = p["banner"] or ""
                    print(f"  {p['port']:<8} {p['service']:<14} {banner}")
                print(f"\n  {len(result['open_ports'])} open port(s) — {result['total_scanned']} scanned")

        case "dns":
            if len(parts) < 2:
                print("Usage: dns <host|ip> [record_type]")
                print("       dns google.com          # full record dump")
                print("       dns google.com MX       # specific record type")
                print("       dns 8.8.8.8             # reverse lookup")
                return
            t = validate_target(parts[1])
            if not t["valid"]:
                print(f"  ✗  {t['error']}")
                return
            record_type = parts[2].upper() if len(parts) == 3 else None
            result = dns_lookup(parts[1], record_type)
            if "reverse" in result:
                r = result["reverse"]
                if r.get("hostname"):
                    print(f"  {r['ip']}  →  {r['hostname']}")
                else:
                    print(f"  ✗  no PTR record found  |  {r.get('error', '')}")
            elif "records" in result and isinstance(result["records"], dict):
                for rtype, values in result["records"].items():
                    print(f"\n  {rtype}")
                    for v in values:
                        print(f"    {v}")
            elif "records" in result:
                r = result["records"]
                if r.get("error"):
                    print(f"  ✗  {r['error']}")
                elif not r.get("records"):
                    print(f"  no {r['type']} records found")
                else:
                    print(f"\n  {r['type']}")
                    for v in r["records"]:
                        print(f"    {v}")

        case "sweep":
            if len(parts) < 2:
                print("Usage: sweep <cidr>")
                print("       sweep 192.168.1.0/24")
                print("       sweep 10.0.0.0/16")
                return
            if not is_cidr(parts[1]):
                print("  ✗  invalid CIDR range — use format 192.168.1.0/24")
                return
            print(f"  sweeping {parts[1]}...")
            result = sweep(parts[1])
            if result.get("error"):
                print(f"  ✗  {result['error']}")
            elif not result["alive"]:
                print(f"  no hosts found ({result['total_scanned']} scanned)")
            else:
                print(f"\n  {'IP':<20} STATUS")
                print(f"  {'─'*20} {'─'*6}")
                for ip in result["alive"]:
                    print(f"  {ip:<20} ✓ up")
                print(f"\n  {result['total_alive']} host(s) up — {result['total_scanned']} scanned")

        case "whois":
            if len(parts) < 2:
                print("Usage: whois <domain>")
                print("       whois google.com")
                return
            if not is_domain(parts[1]):
                print("  ✗  whois requires a domain name e.g. google.com")
                return
            print(f"  looking up {parts[1]}...")
            result = whois_lookup(parts[1])
            if result.get("error"):
                print(f"  ✗  {result['error']}")
            else:
                print()
                for field, value in result["data"].items():
                    label = field.replace("_", " ").upper()
                    if isinstance(value, list):
                        print(f"  {label}")
                        for v in value:
                            print(f"    {v}")
                    else:
                        print(f"  {label:<20} {value}")

        case "headers":
            if len(parts) < 2:
                print("Usage: headers <url>")
                print("       headers google.com")
                print("       headers https://google.com")
                return
            print(f"  fetching headers for {parts[1]}...")
            result = get_headers(parts[1])
            if result.get("error"):
                print(f"  ✗  {result['error']}")
                return
            print(f"\n  STATUS  {result['status']}")
            if result["tech"]:
                print(f"\n  TECH STACK")
                for k, v in result["tech"].items():
                    print(f"    {k:<30} {v}")
            else:
                print(f"\n  TECH STACK    none detected")
            print(f"\n  SECURITY HEADERS")
            for h, info in result["security"].items():
                if info["present"]:
                    print(f"    ✓  {h}")
                else:
                    print(f"    ✗  {h:<40} MISSING")

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