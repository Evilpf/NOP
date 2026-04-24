import socket
import dns.resolver
import dns.reversename

# record types we support
RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

def resolve_host(host):
    # basic A record lookup — host to IP
    try:
        ip = socket.gethostbyname(host)
        return {"host": host, "ip": ip}
    except socket.gaierror as e:
        return {"host": host, "ip": None, "error": str(e)}

def reverse_lookup(ip):
    # turn an IP back into a hostname
    try:
        reversed_name = dns.reversename.from_address(ip)
        result = dns.resolver.resolve(reversed_name, "PTR")
        return {"ip": ip, "hostname": str(result[0])}
    except Exception as e:
        return {"ip": ip, "hostname": None, "error": str(e)}

def query_records(domain, record_type="A"):
    # query any supported record type
    record_type = record_type.upper()
    if record_type not in RECORD_TYPES:
        return {"error": f"unsupported record type: {record_type} — choose from {', '.join(RECORD_TYPES)}"}
    try:
        answers = dns.resolver.resolve(domain, record_type)
        records = []
        for r in answers:
            records.append(str(r))
        return {"domain": domain, "type": record_type, "records": records}
    except dns.resolver.NXDOMAIN:
        return {"domain": domain, "type": record_type, "error": "domain does not exist"}
    except dns.resolver.NoAnswer:
        return {"domain": domain, "type": record_type, "records": []}
    except Exception as e:
        return {"domain": domain, "type": record_type, "error": str(e)}

def dns_lookup(target, record_type=None):
    # main entry point — figures out what kind of lookup to do
    # if its an IP do a reverse lookup
    # if a record type is specified query that
    # otherwise do a full dump of all record types
    from nop.utils.validators import is_ip
    if is_ip(target):
        return {"reverse": reverse_lookup(target)}
    if record_type:
        return {"records": query_records(target, record_type)}
    # no record type specified — grab everything
    results = {}
    for rt in RECORD_TYPES:
        r = query_records(target, rt)
        if r.get("records"):
            results[rt] = r["records"]
    return {"domain": target, "records": results}