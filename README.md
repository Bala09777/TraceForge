# TraceForge

TraceForge is a Python-based Linux authentication monitoring and incident-correlation prototype built to explore how system authentication logs can be turned into useful security alerts.

## Features

- Live monitoring of the system journal
- SSH authentication-failure pattern detection
- IPv4 and IPv6 source-address extraction
- Clear separation of real and synthetic test events
- Configurable time-window and threshold correlation
- JSON incident reports and CSV export
- Automated unit tests using Python's standard library

## How It Works

1. Read authentication-related events from the Linux system journal.
2. Identify patterns associated with failed authentication.
3. Store matching events in `alerts.jsonl`.
4. Correlate events using a configurable time window and threshold.
5. Generate incident reports in JSON and CSV formats.

## Requirements

- Linux with systemd journal access
- Python 3.10 or newer
- Appropriate permissions to read system journal entries
- No third-party Python packages required

## Usage

Start live monitoring:

    python3 traceforge.py monitor

Generate labelled synthetic test events:

    python3 traceforge.py simulate --count 3

Analyze events with a 5-minute window and threshold of 3:

    python3 traceforge.py analyze --window 5 --threshold 3

Export incidents to CSV:

    python3 traceforge.py export

Run the automated tests:

    python3 -m unittest discover -s tests -v

## Validation

During local testing on Kali Linux:

- Started the SSH service and generated controlled failed login attempts against localhost.
- Verified real SSH-related journal patterns were recorded as `SSH_AUTH_LOG_PATTERN`.
- Confirmed captured real events were marked `simulated: false`.
- Ran incident correlation and generated a JSON report.
- Exported the resulting incidents to CSV.

These results validate the tested local workflow, not detection of every SSH attack or activity from external hosts.

## Output Files

- `alerts.jsonl` — recorded alert events
- `incidents.json` — correlated incident report
- `incidents.csv` — CSV export of incidents

Generated runtime reports and local backups are not intended to be committed as source code.

## Limitations

TraceForge is an educational prototype, not a production SIEM or a complete intrusion-detection system.

- A matching log pattern does not prove an attack occurred.
- A single authentication attempt may generate multiple journal messages.
- Event counts may represent log records rather than unique login attempts.
- Detection depends on journal availability, parsing rules, and the configured correlation window.
- External-host monitoring and production readiness require further testing.

## Project Goal

Explore Linux authentication monitoring, event parsing, incident correlation, and security-report generation through practical testing.
