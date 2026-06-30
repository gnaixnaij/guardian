# Guardian — Free EDR

[![Ko-fi](https://img.shields.io/badge/Sponsor-Ko--fi-FF5E5B?style=flat-square&logo=ko-fi)](https://ko-fi.com/gnaixnaij)

Lightweight, free endpoint detection and response for small teams who can't afford commercial EDR licenses.

## Quick start

```bash
pip install -r requirements.txt
python guardian.py
# Open http://127.0.0.1:5000
```

## Features

- **Process monitoring** — detects new processes, flags suspicious tooling (mimikatz, bloodhound, etc.)
- **PowerShell detection** — catches encoded commands, download cradles, and IEX patterns
- **File monitoring** — watches temp directories for new files
- **Network monitoring** — tracks active connections
- **Web dashboard** — real-time alert view in browser
- **YAML rules** — customizable detection rules

## Detection rules

Built-in rules detect:
- Known attack tools (Mimikatz, BloodHound, CrackMapExec, etc.)
- Suspicious PowerShell (encoded commands, download strings, AMSI bypasses)
- CLI download tools (curl, wget, certutil)
- New files in sensitive directories

Add custom rules in `detector/rules/` as YAML files.

## Usage

```bash
# Run with dashboard (default)
python guardian.py

# Run headless (no web UI)
python guardian.py --headless

# Run for 60 seconds then exit
python guardian.py --duration 60

# Custom port
python guardian.py --port 8080
```

## Requirements

- Python 3.8+
- Linux or Windows
- psutil for process/network monitoring

## Deploy

```bash
# Background service (Linux)
nohup python guardian.py --port 5000 &

# Or use systemd for persistence
```

## License

MIT
