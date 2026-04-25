import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress

def reverse_lookup_ip(ip, timeout=2):
    # try to resolve IP back to a hostname
    try:
        socket.setdefaulttimeout(timeout)
        hostname = socket.gethostbyaddr(str(ip))[0]
        return str(ip), hostname
    except (socket.herror, socket.gaierror):
        return str(ip), None
    except Exception:
        return str(ip), None

def reverse_dns_sweep(target, threads=100):
    # target can be a CIDR range or a list of IPs from a sweep
    try:
        if isinstance(target, list):
            # accept a list of IPs directly — plugs into sweep output
            ips = target
        else:
            network = ipaddress.ip_network(target, strict=False)
            ips = [str(ip) for ip in network.hosts()]
    except ValueError as e:
        return {"error": str(e)}

    if not ips:
        return {"error": "no IPs to scan"}

    results = []

    # threaded reverse lookups — DNS can be slow so parallelism helps a lot
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(reverse_lookup_ip, ip): ip for ip in ips}
        for future in as_completed(futures):
            ip, hostname = future.result()
            if hostname:
                results.append({"ip": ip, "hostname": hostname})

    # sort by IP
    results.sort(key=lambda x: list(map(int, x["ip"].split("."))))

    return {
        "total_scanned": len(ips),
        "resolved": results,
        "total_resolved": len(results)
    }