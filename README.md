# NOP — Network OSINT Platform

A modular command-line tool for network reconnaissance, OSINT, and network troubleshooting.
Built for penetration testers, security researchers, and network engineers who want a fast, extensible terminal-based toolkit.

---

## Features

- **Ping** — check host availability and measure latency
- **Interactive menu** — run NOP with no arguments to drop into a guided CLI
- **Modular design** — easily extend with new network, OSINT, and utility modules

---

## Installation

```bash
git clone https://github.com/evilpf/NOP.git
cd NOP
python -m venv venv
source venv/bin/activate  # on fish: source venv/bin/activate.fish
pip install -r requirements.txt
```

---

## Usage

### Interactive mode
```bash
python -m nop.main
```
Drops into the NOP prompt where you can run commands with a guided menu.

### One-shot CLI
```bash
python -m nop.main ping 1.1.1.1
```

### Commands

| Command | Arguments | Description |
|---------|-----------|-------------|
| `ping`  | `<host>`  | Check if a host is alive and return latency |
| `help`  | —         | Print the command menu |
| `exit`  | —         | Quit NOP |

---

## Project Structure

NOP/
├── nop/
│   ├── main.py        # Entry point + interactive menu
│   ├── network/
│   │   └── ping.py    # ICMP ping implementation
│   ├── osint/         # OSINT modules (coming soon)
│   └── utils/         # Shared utilities
└── README.md

---

## Roadmap

- [ ] WHOIS lookup
- [ ] DNS enumeration
- [ ] Port scanning
- [ ] OSINT modules (username lookup, IP geolocation)
- [ ] Output to JSON / file logging
