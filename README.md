# NOP — Network OSINT Platform

A modular command-line tool for network reconnaissance, OSINT, and network troubleshooting.
Built for penetration testers, security researchers, and network engineers who want a fast, extensible terminal-based toolkit.

---

## Features

- **Ping** — check host availability and measure latency
- **Port Scanner** — threaded TCP connect scan with auto banner grabbing
- **DNS Lookup** — resolve hosts, reverse lookup IPs, query any record type
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
~~~

### Commands

| Category    | Command    | Arguments              | Description                                  |
|-------------|------------|------------------------|----------------------------------------------|
| **Network** | `ping`     | `<host>`               | Check if a host is alive and return latency  |
|             | `portscan` | `<host> [range]`       | TCP connect scan with auto banner grabbing   |
|             | `dns`      | `<host\|ip> [type]`    | Resolve host, reverse lookup IP, query records |
| **Utility** | `help`     | —                      | Print the command menu                       |
|             | `exit`     | —                      | Quit NOP                                     |

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
│   │   └── sweep.py         # Ping sweep (coming soon)
│   ├── osint/
│   │   ├── whois_lookup.py  # WHOIS lookup (coming soon)
│   │   ├── headers.py       # HTTP header inspection (coming soon)
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
- [ ] Ping sweep across subnets
- [ ] Traceroute

### OSINT
- [ ] WHOIS lookup
- [ ] IP geolocation
- [ ] HTTP header inspection
- [ ] Subdomain enumeration
- [ ] Bulk reverse DNS

### Utility
- [x] Input validation
- [ ] Output to JSON / file logging
- [ ] Threading helpers

---

## License

See [LICENSE](LICENSE).
