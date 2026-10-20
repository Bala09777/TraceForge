# TraceForge

TraceForge is a Python-based Linux authentication-event monitoring and incident-correlation prototype.

## Features
- Live system journal monitoring
- Authentication-failure pattern detection
- Synthetic test-event separation
- IPv4 and IPv6 source-address extraction
- Configurable time-window and threshold correlation
- JSON and CSV incident reports
- Automated unit tests using Python's standard library

## Requirements
- Linux with systemd journal access
- Python 3.10 or newer
- No third-party Python packages required

## Usage

Start monitoring:

    python3 traceforge.py monitor

Generate synthetic test events:

    python3 traceforge.py simulate --count 3

Analyze alerts:

    python3 traceforge.py analyze --window 5 --threshold 3

Export incidents:

    python3 traceforge.py export

Run tests:

    python3 -m unittest discover -s tests -v

## Output
- alerts.jsonl
- incidents.json
- incidents.csv

## Limitations
This is an educational prototype. A matching log pattern does not prove an attack occurred. Real detection depends on available journal records and should be validated against known test data before operational use.
