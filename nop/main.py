# nop/main.py
import argparse
import sys
from nop.network.ping import ping_host
from nop.network.portscan import port_scan
from nop.utils.validators import validate_target, is_valid_port

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
├────────────┼─────────────────────────────┤
│ OSINT      │                             │
│  (soon)    │                             │
├────────────┼─────────────────────────────┤
│  help      │ show this menu              │
│  exit      │ quit                        │
└────────────┴─────────────────────────────┘
"""

def handle_command(parts):
    if not parts:
        return
    cmd = parts[0].lower()

    if cmd == "ping":
        if len(parts) < 2:
            print("Usage: ping <host>")
            return
        # validate before we do anything
        t = validate_target(parts[1])
        if not t["valid"]:
            print(f"  ✗  {t['error']}")
            return
        result = ping_host(parts[1])
        if result.get("alive"):
            print(f"  ✓  {result['host']} is up  |  latency: {result['latency']} ms")
        else:
            print(f"  ✗  {result['host']} is unreachable  |  {result.get('error', '')}")

    elif cmd == "portscan":
        if len(parts) < 2:
            print("Usage: portscan <host> [range]")
            print("       portscan 1.1.1.1           # scans common ports")
            print("       portscan 1.1.1.1 1-65535    # scans port range")
            return
        # validate before we do anything
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
                # validate both ends of the range
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

    elif cmd == "help":
        print(MENU)

    elif cmd == "exit":
        print("bye.")
        sys.exit(0)

    else:
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