# NOP — Network OSINT Platform

A modular command-line tool for network reconnaissance, OSINT, and network troubleshooting.

---

## Features

- **Ping** — check host availability and measure latency
- **Port Scanner** — threaded TCP connect scan with auto banner grabbing
- **DNS Lookup** — resolve hosts, reverse lookup IPs, query any record type
- **Sweep** — ping sweep an entire subnet to discover live hosts
- **GeoIP** — geolocate an IP or domain to country, city, ISP, ASN
- **WHOIS** — domain registration info, registrar, dates, name servers
- **HTTP Headers** — inspect response headers, detect tech stack, flag missing security headers
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
python -m nop.main geoip google.com
python -m nop.main whois google.com
python -m nop.main headers google.com
~~~

### Commands

| Category    | Command    | Arguments           | Description                                    |
|-------------|------------|---------------------|------------------------------------------------|
| **Network** | `ping`     | `<host>`            | Check if a host is alive and return latency    |
|             | `portscan` | `<host> [range]`    | TCP connect scan with auto banner grabbing     |
|             | `dns`      | `<host\|ip> [type]` | Resolve host, reverse lookup IP, query records |
|             | `sweep`    | `<cidr>`            | Ping sweep a subnet to find live hosts         |
|             | `geoip`    | `<ip\|domain>`      | Geolocate an IP to country, city, ISP, ASN     |
| **OSINT**   | `whois`    | `<domain>`          | Domain registration info and name servers      |
|             | `headers`  | `<url>`             | HTTP headers, tech stack, security header audit|
| **Utility** | `help`     | —                   | Print the command menu                         |
|             | `exit`     | —                   | Quit NOP                                       |

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
│   │   └── geoip.py         # IP geolocation via ip-api.com
│   ├── osint/
│   │   ├── whois_lookup.py  # WHOIS domain lookup
│   │   ├── headers.py       # HTTP header inspection + security audit
│   │   ├── reverse_dns.py   # Bulk reverse DNS (coming soon)
│   │   └── subdomains.py    # Subdomain enumeration (coming soon)
│   └── utils/
│       ├── validators.py    # Input validation for hosts, IPs, domains, ports
│       ├── output.py        # JSON/file logging (coming soon)
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
- [ ] Traceroute

### OSINT
- [x] WHOIS lookup
- [x] HTTP header inspection + security audit
- [ ] Subdomain enumeration
- [ ] Bulk reverse DNS

### Utility
- [x] Input validation
- [ ] Output to JSON / file logging
- [ ] Threading helpers

---

## License

See [LICENSE](LICENSE).