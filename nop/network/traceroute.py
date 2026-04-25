import subprocess
import re

def traceroute(host, max_hops=30, timeout=3):
    try:
        result = subprocess.run(
            ["traceroute", "-m", str(max_hops), "-w", str(timeout), host],
            capture_output=True,
            text=True
        )

        lines = result.stdout.strip().splitlines()
        hops = []

        for line in lines[1:]:  # skip the header line
            # each line looks like: " 1  router (192.168.1.1)  1.234 ms"
            # or " 2  * * *" for no response
            hop_match = re.match(r"\s*(\d+)\s+(.*)", line)
            if not hop_match:
                continue

            hop_num = int(hop_match.group(1))
            rest = hop_match.group(2).strip()

            # * * * means no response at this hop
            if rest.startswith("*"):
                hops.append({
                    "hop": hop_num,
                    "host": None,
                    "ip": None,
                    "rtt": None
                })
                continue

            # pull IP from parentheses
            ip_match = re.search(r"\((\d{1,3}(?:\.\d{1,3}){3})\)", rest)
            # pull first RTT value
            rtt_match = re.search(r"(\d+\.\d+)\s*ms", rest)
            # hostname is everything before the IP
            host_match = re.match(r"([^\(]+)", rest)

            hops.append({
                "hop": hop_num,
                "host": host_match.group(1).strip() if host_match else None,
                "ip": ip_match.group(1) if ip_match else None,
                "rtt": float(rtt_match.group(1)) if rtt_match else None
            })

        return {"target": host, "hops": hops}

    except FileNotFoundError:
        return {"target": host, "error": "traceroute not installed — run: sudo pacman -S traceroute"}
    except Exception as e:
        return {"target": host, "error": str(e)}