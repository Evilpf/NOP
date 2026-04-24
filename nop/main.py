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

        case "help":
            print(MENU)

        case "exit":
            print("bye.")
            sys.exit(0)

        case _:
            print(f"  unknown command: '{cmd}' — type 'help' for the menu")