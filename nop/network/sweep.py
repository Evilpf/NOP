import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress

def ping_ip(ip, timeout=1):
    # ping each IP once with a short timeout
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), str(ip)],
            capture_output=True,
            text=True
        )
        return str(ip), result.returncode == 0
    except Exception:
        return str(ip), False

def sweep(target, threads=100):
    # expand the CIDR into a list of IPs to scan
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as e:
        return {"error": str(e)}

    hosts = list(network.hosts())
    if not hosts:
        return {"error": "no hosts in range"}

    alive = []

    # sweep all IPs in parallel — same threading pattern as portscan
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(ping_ip, ip): ip for ip in hosts}
        for future in as_completed(futures):
            ip, is_alive = future.result()
            if is_alive:
                alive.append(ip)

    # sort IPs in proper order
    alive.sort(key=lambda ip: list(map(int, ip.split("."))))

    return {
        "network": str(network),
        "total_scanned": len(hosts),
        "alive": alive,
        "total_alive": len(alive)
    }