import subprocess
import re

def ping_host(host):
    try:
        result = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True,
            text=True,
            timeout=3
        )
        # !0 return code = host unreachable
        if result.returncode != 0:
            return {
                "host": host,
                "alive": False,
                "latency": None
            }

        output = result.stdout
        # Look for latency in output
        latency_match = re.search(r"time=(\d+\.?\d*)", output)  
        latency = None
        # convert latency
        if latency_match:
            latency = float(latency_match.group(1))

        return {
            "host": host,
            "alive": True,       
            "latency": latency
        }

    except Exception as e:
        return {
            "host": host,        
            "alive": False,
            "error": str(e)
        }
