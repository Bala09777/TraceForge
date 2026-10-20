#!/usr/bin/env python3
"""TraceForge: a small Linux authentication-event monitoring prototype."""

import argparse
import csv
import ipaddress
import json
import re
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
ALERTS_FILE = BASE_DIR / "alerts.jsonl"
INCIDENTS_FILE = BASE_DIR / "incidents.json"
CSV_FILE = BASE_DIR / "incidents.csv"

PATTERNS = (
    "failed password",
    "authentication failure",
    "invalid user",
    "failed login",
    "authentication failed",
)

IP_PATTERNS = (
    re.compile(
        r"\bfrom\s+([0-9a-fA-F:.]+)\s+port\s+\d+\b",
        re.IGNORECASE,
    ),
    re.compile(r"\brhost=([0-9a-fA-F:.]+)\b", re.IGNORECASE),
)

CSV_COLUMNS = (
    "incident_type",
    "severity",
    "host",
    "process",
    "source_ip",
    "event_count",
    "first_seen_utc",
    "last_seen_utc",
    "evidence_type",
    "simulated",
    "recommended_action",
)


def utc_now():
    return datetime.now(timezone.utc)


def parse_time(record):
    value = datetime.fromisoformat(record["timestamp_utc"])
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value


def extract_source_ip(message):
    """Extract and validate an IP address from a familiar log format."""
    for pattern in IP_PATTERNS:
        match = pattern.search(message)
        if match:
            candidate = match.group(1)
            try:
                return str(ipaddress.ip_address(candidate))
            except ValueError:
                continue
    return None


def build_alert(event):
    """Convert a journal event into an alert, or return None."""
    message = str(event.get("MESSAGE", ""))
    lower = message.lower()

    if not any(pattern in lower for pattern in PATTERNS):
        return None

    simulated = "TRACEFORGE_TEST" in message
    process_name = str(event.get("_COMM", "unknown"))

    # Test events are allowed from any process. Real SSH evidence must
    # originate from sshd and match one of the patterns above.
    if not simulated and process_name != "sshd":
        return None

    raw_timestamp = event.get("__REALTIME_TIMESTAMP")
    if raw_timestamp:
        timestamp = datetime.fromtimestamp(
            int(raw_timestamp) / 1_000_000,
            tz=timezone.utc,
        ).isoformat()
    else:
        timestamp = utc_now().isoformat()

    return {
        "timestamp_utc": timestamp,
        "severity": "TEST" if simulated else "MEDIUM",
        "event_type": "AUTHENTICATION_FAILURE_PATTERN",
        "evidence_type": (
            "SIMULATED_TEST_EVENT"
            if simulated else "SSH_AUTH_LOG_PATTERN"
        ),
        "process": process_name,
        "systemd_unit": event.get("_SYSTEMD_UNIT", "unknown"),
        "source_ip": extract_source_ip(message),
        "message": message,
        "host": event.get("_HOSTNAME", "unknown"),
        "simulated": simulated,
    }


def append_jsonl(path, record):
    with path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(record) + "\n")


def load_jsonl(path):
    records = []
    malformed = 0

    if not path.exists():
        return records, malformed

    with path.open(encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                if isinstance(record, dict):
                    records.append(record)
                else:
                    malformed += 1
            except json.JSONDecodeError:
                malformed += 1

    return records, malformed


def make_incident(key, events):
    host, process, evidence_type, source_ip = key
    simulated = evidence_type == "SIMULATED_TEST_EVENT"

    return {
        "incident_type": "REPEATED_AUTH_FAILURE_PATTERN",
        "severity": "TEST" if simulated else "MEDIUM",
        "evidence_type": evidence_type,
        "host": host,
        "process": process,
        "source_ip": source_ip,
        "event_count": len(events),
        "first_seen_utc": events[0]["timestamp_utc"],
        "last_seen_utc": events[-1]["timestamp_utc"],
        "evidence_messages": [item.get("message", "") for item in events],
        "simulated": simulated,
        "recommended_action": (
            "Test scenario only; no real remediation needed."
            if simulated else
            "Validate the source and activity; follow incident response policy."
        ),
    }


def correlate_alerts(alerts, window_minutes=5, threshold=3):
    """Group matching events into incidents within a sliding time window."""
    if window_minutes <= 0:
        raise ValueError("window_minutes must be greater than zero")
    if threshold < 1:
        raise ValueError("threshold must be at least one")

    groups = defaultdict(list)

    for alert in alerts:
        if alert.get("event_type") != "AUTHENTICATION_FAILURE_PATTERN":
            continue

        try:
            parse_time(alert)
        except (KeyError, TypeError, ValueError):
            continue

        key = (
            alert.get("host", "unknown"),
            alert.get("process", "unknown"),
            alert.get("evidence_type", "unknown"),
            alert.get("source_ip"),
        )
        groups[key].append(alert)

    incidents = []
    window = timedelta(minutes=window_minutes)

    for key, events in groups.items():
        events.sort(key=parse_time)
        current = []

        for event in events:
            if current and parse_time(event) - parse_time(current[0]) > window:
                if len(current) >= threshold:
                    incidents.append(make_incident(key, current))
                current = []

            current.append(event)

        if len(current) >= threshold:
            incidents.append(make_incident(key, current))

    incidents.sort(key=lambda item: item["first_seen_utc"])
    return incidents


def monitor():
    print("[TraceForge] Live journal monitor started.")
    print("[TraceForge] Real SSH patterns and controlled test events.")
    print(f"[TraceForge] Alerts: {ALERTS_FILE}")
    command = [
        "journalctl", "--follow", "--lines=0", "--output=json"
    ]

    try:
        with subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=None,
            text=True,
            bufsize=1,
        ) as process:
            if process.stdout is None:
                raise RuntimeError("Could not read journal output")

            for line in process.stdout:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                alert = build_alert(event)
                if alert is None:
                    continue

                append_jsonl(ALERTS_FILE, alert)
                print("\n[TRACEFORGE ALERT]")
                print(json.dumps(alert, indent=2), flush=True)

    except KeyboardInterrupt:
        print("\n[TraceForge] Monitoring stopped.")
    except FileNotFoundError:
        print("ERROR: journalctl was not found.", file=sys.stderr)
        sys.exit(1)


def simulate(count):
    """Append clearly labelled synthetic events for local testing."""
    for number in range(1, count + 1):
        message = (
            "TRACEFORGE_TEST: Failed password for demo "
            "from 192.0.2.10 port 2222"
        )
        event = {
            "MESSAGE": message,
            "_COMM": "traceforge-sim",
            "_SYSTEMD_UNIT": "traceforge-demo.service",
            "_HOSTNAME": "traceforge-lab",
            "__REALTIME_TIMESTAMP": str(time.time_ns() // 1000),
        }
        alert = build_alert(event)
        if alert is not None:
            append_jsonl(ALERTS_FILE, alert)
        print(f"[{number}/{count}] Added simulated test event.")
        time.sleep(0.05)

    print(f"Simulation complete. Alert log: {ALERTS_FILE}")


def analyze(window_minutes, threshold):
    alerts, malformed = load_jsonl(ALERTS_FILE)
    incidents = correlate_alerts(
        alerts,
        window_minutes=window_minutes,
        threshold=threshold,
    )

    report = {
        "generated_utc": utc_now().isoformat(),
        "source": str(ALERTS_FILE),
        "window_minutes": window_minutes,
        "threshold": threshold,
        "alerts_reviewed": len(alerts),
        "malformed_lines_skipped": malformed,
        "incident_count": len(incidents),
        "incidents": incidents,
        "note": (
            "Event patterns are evidence for review, not proof of a "
            "successful attack. TEST events are synthetic."
        ),
    }

    INCIDENTS_FILE.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(report, indent=2))
    print(f"\nSaved report: {INCIDENTS_FILE}")


def export_csv():
    if not INCIDENTS_FILE.exists():
        print("No incidents.json. Run 'analyze' first.", file=sys.stderr)
        return 1

    try:
        report = json.loads(INCIDENTS_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as error:
        print(f"Cannot read incident report: {error}", file=sys.stderr)
        return 1

    incidents = report.get("incidents", [])
    with CSV_FILE.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for incident in incidents:
            writer.writerow({
                column: incident.get(column, "")
                for column in CSV_COLUMNS
            })

    print(f"Exported {len(incidents)} incident(s) to {CSV_FILE}")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="TraceForge Linux authentication-event monitoring prototype"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("monitor", help="Monitor live system journal events")

    simulation_parser = subparsers.add_parser(
        "simulate", help="Add labelled synthetic test events"
    )
    simulation_parser.add_argument(
        "--count", type=int, default=3,
        help="Number of test events to add (default: 3)",
    )

    analyze_parser = subparsers.add_parser(
        "analyze", help="Correlate saved alerts into incidents"
    )
    analyze_parser.add_argument("--window", type=int, default=5)
    analyze_parser.add_argument("--threshold", type=int, default=3)

    subparsers.add_parser("export", help="Export incidents.json to CSV")

    args = parser.parse_args()

    if args.command == "monitor":
        monitor()
    elif args.command == "simulate":
        if args.count < 1 or args.count > 1000:
            parser.error("--count must be between 1 and 1000")
        simulate(args.count)
    elif args.command == "analyze":
        if args.window < 1 or args.threshold < 1:
            parser.error("--window and --threshold must be positive")
        analyze(args.window, args.threshold)
    elif args.command == "export":
        return export_csv()

    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
