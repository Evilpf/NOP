# NOP — Network OSINT Platform

A modular command-line tool for network reconnaissance, OSINT, and network troubleshooting.

---

## Features

- **Ping** — check host availability and measure latency
- **Port Scanner** — threaded TCP connect scan with common ports and custom ranges
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
~~~

### Commands

| Category       | Command      | Arguments        | Description                              |
|----------------|--------------|------------------|------------------------------------------|
| **Network**    | `ping`       | `<host>`         | Check if a host is alive and return latency |
|                | `portscan`   | `<host> [range]` | TCP connect scan, defaults to common ports |
| **Utility**    | `help`       | —                | Print the command menu                   |
|                | `exit`       | —                | Quit NOP                                 |

---

## Project Structure

~~~
NOP/
├── nop/
│   ├── main.py            # Entry point + interactive menu
│   ├── network/
│   │   ├── ping.py        # ICMP ping implementation
│   │   └── portscan.py    # Threaded TCP port scanner
│   ├── osint/             # OSINT modules (coming soon)
│   └── utils/             # Shared utilities
└── README.md
~~~

---

## Roadmap

### Network / Recon
- [x] Ping
- [x] Port scanning
- [ ] Banner grabbing — pull service banners from open ports
- [ ] Traceroute — hop-by-hop path to a host
- [ ] DNS enumeration — resolve, reverse lookup, MX/NS/TXT records

### OSINT
- [ ] WHOIS lookup
- [ ] IP geolocation
- [ ] HTTP header inspection
- [ ] Subdomain enumeration

### Troubleshooting
- [ ] Continuous latency monitor
- [ ] MTU discovery
- [ ] Output to JSON / file logging

---

## License

See [LICENSE](LICENSE).
