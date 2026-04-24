import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# ports we care about by default + their services
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB"
}

# ports that need an HTTP probe to respond — everything else banners on connect
HTTP_PORTS = {80, 8080, 8443, 443}

def grab_banner(host, port, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # HTTP ports need a request to respond, other services
        # (SSH, FTP, SMTP etc.) send their banner immediately on connect
        if port in HTTP_PORTS:
            sock.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")

        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        # first line only — rest is noise
        return banner.splitlines()[0] if banner else None
    except Exception:
        return None

def scan_port(host, port, timeout=1, grab=True):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        # connect_ex returns 0 on success instead of raising an exception
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            banner = grab_banner(host, port) if grab else None
            return port, True, banner
        return port, False, None
    except Exception:
        return port, False, None

def port_scan(host, ports=None, threads=100, grab=True):
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    open_ports = []

    # ThreadPoolExecutor lets us scan multiple ports at the same time
    # instead of one by one — massively speeds up the scan
    with ThreadPoolExecutor(max_workers=threads) as executor:
        # fire off all port scans at once, map each future back to its port
        futures = {executor.submit(scan_port, host, port, grab=grab): port for port in ports}

        # as_completed yields futures as they finish, not in submission order
        for future in as_completed(futures):
            port, is_open, banner = future.result()
            if is_open:
                open_ports.append({
                    "port": port,
                    "service": COMMON_PORTS.get(port, "unknown"),
                    "banner": banner
                })

    # sort by port number so output is clean
    open_ports.sort(key=lambda x: x["port"])
    return {
        "host": host,
        "open_ports": open_ports,
        "total_scanned": len(ports)
    }