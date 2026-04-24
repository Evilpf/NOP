import re
import socket

# standard IPv4 pattern
IPV4_PATTERN = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)

# basic domain pattern — covers most real world domains
DOMAIN_PATTERN = re.compile(
    r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

# CIDR pattern for subnet sweeps e.g. 192.168.1.0/24
CIDR_PATTERN = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}/(\d|[1-2]\d|3[0-2])$"
)

def is_ip(target):
    # check format first, then validate each octet is 0-255
    if not IPV4_PATTERN.match(target):
        return False
    return all(0 <= int(o) <= 255 for o in target.split("."))

def is_domain(target):
    return bool(DOMAIN_PATTERN.match(target))

def is_cidr(target):
    # check format then validate the IP portion
    if not CIDR_PATTERN.match(target):
        return False
    ip = target.split("/")[0]
    return is_ip(ip)

def is_valid_port(port):
    # ports must be an int between 1 and 65535
    try:
        return 1 <= int(port) <= 65535
    except (ValueError, TypeError):
        return False

def resolve(target):
    # if its already an IP just return it
    # if its a domain, resolve it to an IP
    if is_ip(target):
        return target
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None

def validate_target(target):
    # central validation used by all commands
    # returns a dict so callers know what they're working with
    if is_ip(target):
        return {"valid": True, "type": "ip", "value": target}
    if is_domain(target):
        resolved = resolve(target)
        if resolved:
            return {"valid": True, "type": "domain", "value": target, "resolved": resolved}
        return {"valid": False, "error": f"could not resolve {target}"}
    if is_cidr(target):
        return {"valid": True, "type": "cidr", "value": target}
    return {"valid": False, "error": f"invalid target: {target}"}