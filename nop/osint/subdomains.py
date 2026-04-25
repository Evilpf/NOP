import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# common subdomain wordlist — covers most real world cases
WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "cpanel",
    "whm", "admin", "portal", "api", "dev", "staging", "test", "beta",
    "app", "mobile", "m", "shop", "store", "blog", "forum", "support",
    "help", "docs", "cdn", "static", "assets", "media", "images", "img",
    "video", "upload", "download", "files", "secure", "vpn", "remote",
    "git", "gitlab", "github", "jenkins", "ci", "jira", "confluence",
    "ns1", "ns2", "mx", "mx1", "mx2", "smtp1", "smtp2", "pop3", "imap4",
    "autodiscover", "autoconfig", "calendar", "meet", "chat", "status",
    "monitor", "grafana", "kibana", "elastic", "search", "db", "database",
    "mysql", "postgres", "redis", "mongo", "backup", "internal", "intranet",
    "extranet", "private", "public", "proxy", "gateway", "auth", "sso",
    "login", "account", "accounts", "billing", "pay", "payment", "checkout"
]

def check_subdomain(domain, sub, timeout=2):
    # try to resolve the subdomain — if it resolves it exists
    target = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(target)
        return target, ip
    except socket.gaierror:
        return target, None

def subdomain_scan(domain, wordlist=None, threads=50):
    if wordlist is None:
        wordlist = WORDLIST

    found = []

    # same threading pattern as portscan and sweep
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(check_subdomain, domain, sub): sub
            for sub in wordlist
        }
        for future in as_completed(futures):
            subdomain, ip = future.result()
            if ip:
                found.append({"subdomain": subdomain, "ip": ip})

    # sort alphabetically
    found.sort(key=lambda x: x["subdomain"])

    return {
        "domain": domain,
        "found": found,
        "total_found": len(found),
        "total_checked": len(wordlist)
    }