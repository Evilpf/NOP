# nop/main.py
import argparse
import sys
from nop.network.ping import ping_host
from nop.network.portscan import port_scan

BANNER = r"""
 _   _  ___  ____  
| \ | |/ _ \|  _ \ 
|  \| | | | | |_) |
| |\  | |_| |  __/ 
|_| \_|\___/|_|    

  Network OSINT Platform
"""

MENU = """
┌─────────────────────────────┐
│         COMMANDS            │
├────────────┬────────────────┤
│ Network    │                │
│  ping      │ <host>         │
│  portscan  │ <host> [range] │
├────────────┼────────────────┤
│ OSINT      │                │
│  (soon)    │                │
├────────────┼────────────────┤
│  help      │ show this menu │
│  exit      │ quit           │
└────────────┴────────────────┘
"""

def handle_command(parts):
    if not parts:
        return
    cmd = parts[0].lower()

    if cmd == "ping":
        if len(parts) < 2:
            print("Usage: ping <host>")
            return
        result = ping_host(parts[1])
        if result.get("alive"):
            print(f"  ✓  {result['host']} is up  |  latency: {result['latency']} ms")
        else:
            print(f"  ✗  {result['host']} is unreachable  |  {result.get('error', '')}")

    elif cmd == "portscan":
        if len(parts) < 2:
            print("Usage: portscan <host> [port-range]")
            print("       portscan 1.1.1.1           # scans common ports")
            print("       portscan 1.1.1.1 1-65535    # scans port range")
            return
        host = parts[1]
        ports = None
        if len(parts) == 3:
            try:
                start, end = parts[2].split("-")
                ports = list(range(int(start), int(end) + 1))
            except ValueError:
                print("  invalid range format — use start-end e.g. 1-1024")
                return
        print(f"  scanning {host}...")
        result = port_scan(host, ports)
        if not result["open_ports"]:
            print(f"  no open ports found ({result['total_scanned']} scanned)")
        else:
            print(f"\n  {'PORT':<8} {'SERVICE'}")
            print(f"  {'─'*8} {'─'*12}")
            for p in result["open_ports"]:
                print(f"  {p['port']:<8} {p['service']}")
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
