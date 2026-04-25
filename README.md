# NOP — Network OSINT Platform

A modular command-line tool for network reconnaissance, OSINT, and network troubleshooting.

---

## Features

- **Ping** — check host availability and measure latency
- **Port Scanner** — threaded TCP connect scan with auto banner grabbing
- **DNS Lookup** — resolve hosts, reverse lookup IPs, query any record type
- **Sweep** — ping sweep an entire subnet to discover live hosts
- **GeoIP** — geolocate an IP or domain to country, city, ISP, ASN
- **SSL** — inspect TLS certificates, expiry, issuer, SANs and cipher info
- **Traceroute** — hop by hop path to a target host
- **WHOIS** — domain registration info, registrar, dates, name servers
- **HTTP Headers** — inspect response headers, detect tech stack, flag missing security headers
- **Subdomains** — threaded brute force subdomain enumeration
- **Reverse DNS** — bulk reverse DNS lookup across a subnet
- **Output** — save any command result to JSON or plaintext with `--json` or `--save`
- **Input Validation** — all commands validate targets before execution
- **Interactive menu** — run NOP with no arguments to drop into a guided CLI
- **Modular design** — easily extend with new network, OSINT, and utility modules

---

## Installation

~~~bash
git clone https://github.com/evilpf/NOP.git
cd NOP
python -m venv venv
source venv/bin/activate  # on fish: source venv/bin/activate.fish
pip install -r requirements.txt
~~~

---

## Usage

### Interactive mode

~~~bash
python -m nop.main
~~~

Drops into the NOP prompt where you can run commands with a guided menu.

### One-shot CLI

~~~bash
python -m nop.main ping 1.1.1.1
python -m nop.main portscan 1.1.1.1
python -m nop.main portscan 1.1.1.1 1-65535
python -m nop.main dns google.com
python -m nop.main dns google.com MX
python -m nop.main dns 8.8.8.8
python -m nop.main sweep 192.168.1.0/24
python -m nop.main geoip 1.1.1.1
python -m nop.main ssl google.com
python -m nop.main traceroute google.com
python -m nop.main whois google.com
python -m nop.main headers google.com
python -m nop.main subdomains google.com
python -m nop.main rdns 192.168.1.0/24
~~~

### Saving Output

Append `--save` or `--json` to any command to save the result:

~~~bash
nop > portscan 1.1.1.1 --json       # save as JSON
nop > subdomains google.com --save   # save as plaintext
nop > outputs                        # list all saved results
~~~

Saved files go to `~/.nop/output/` and are named by command, target, and timestamp.

### Commands

| Category    | Command       | Arguments              | Description                                      |
|-------------|---------------|------------------------|--------------------------------------------------|
| **Network** | `ping`        | `<host>`               | Check if a host is alive and return latency      |
|             | `portscan`    | `<host> [range]`       | TCP connect scan with auto banner grabbing       |
|             | `dns`         | `<host\|ip> [type]`    | Resolve host, reverse lookup IP, query records   |
|             | `sweep`       | `<cidr>`               | Ping sweep a subnet to find live hosts           |
|             | `geoip`       | `<ip\|domain>`         | Geolocate an IP to country, city, ISP, ASN       |
|             | `ssl`         | `<host> [port]`        | Inspect TLS cert, expiry, SANs, cipher           |
|             | `traceroute`  | `<host>`               | Hop by hop path to a target                      |
| **OSINT**   | `whois`       | `<domain>`             | Domain registration info and name servers        |
|             | `headers`     | `<url>`                | HTTP headers, tech stack, security header audit  |
|             | `subdomains`  | `<domain>`             | Brute force subdomain enumeration                |
|             | `rdns`        | `<cidr>`               | Bulk reverse DNS lookup across a subnet          |
| **Output**  | `outputs`     | —                      | List all saved results                           |
| **Utility** | `help`        | —                      | Print the command menu                           |
|             | `exit`        | —                      | Quit NOP                                         |

### Output Flags

| Flag      | Description                              |
|-----------|------------------------------------------|
| `--save`  | Save result as plaintext to `~/.nop/output/` |
| `--json`  | Save result as JSON to `~/.nop/output/`  |

### DNS Record Types

`A` `AAAA` `MX` `NS` `TXT` `CNAME` `SOA`

~~~bash
dns google.com          # dumps all available records
dns google.com MX       # query specific record type
dns 8.8.8.8             # reverse lookup
~~~

---

## Project Structure

~~~
NOP/
├── nop/
│   ├── main.py              # Entry point + interactive menu
│   ├── network/
│   │   ├── ping.py          # ICMP ping implementation
│   │   ├── portscan.py      # Threaded TCP port scanner + banner grabbing
│   │   ├── dns.py           # DNS resolution and record queries
│   │   ├── sweep.py         # Threaded ping sweep across subnets
│   │   ├── geoip.py         # IP geolocation via ip-api.com
│   │   ├── ssl.py           # TLS certificate inspection
│   │   └── traceroute.py    # Hop by hop route tracing
│   ├── osint/
│   │   ├── whois_lookup.py  # WHOIS domain lookup
│   │   ├── headers.py       # HTTP header inspection + security audit
│   │   ├── subdomains.py    # Threaded subdomain brute force
│   │   └── reverse_dns.py   # Bulk reverse DNS across subnets
│   └── utils/
│       ├── validators.py    # Input validation for hosts, IPs, domains, ports
│       ├── output.py        # Save results to JSON or plaintext
│       └── threading.py     # Threading helpers (coming soon)
└── README.md
~~~

---

## Roadmap

### Network / Recon
- [x] Ping
- [x] Port scanning + banner grabbing
- [x] DNS enumeration
- [x] Ping sweep across subnets
- [x] IP geolocation
- [x] SSL/TLS certificate inspection
- [x] Traceroute

### OSINT
- [x] WHOIS lookup
- [x] HTTP header inspection + security audit
- [x] Subdomain enumeration
- [x] Bulk reverse DNS

### Utility
- [x] Input validation
- [x] Output to JSON / plaintext file logging
- [ ] Threading helpers

---

## License

See [LICENSE](LICENSE).