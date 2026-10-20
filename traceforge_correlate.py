#!/usr/bin/env python3
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

INPUT = Path("alerts.jsonl")
OUTPUT = Path("incidents.json")
WINDOW_MINUTES = 5
THRESHOLD = 3


def parse_time(alert):
    return datetime.fromisoformat(alert["timestamp_utc"])


def make_incident(host, process, evidence_type, events):
    simulated = evidence_type == "SIMULATED_TEST_EVENT"
    return {
        "incident_type": "REPEATED_AUTH_FAILURE_PATTERN",
        "severity": "TEST" if simulated else "MEDIUM",
        "evidence_type": evidence_type,
        "host": host,
        "process": process,
        "event_count": len(events),
        "first_seen_utc": events[0]["timestamp_utc"],
        "last_seen_utc": events[-1]["timestamp_utc"],
        "evidence_messages": [e["message"] for e in events],
        "simulated": simulated,
        "recommended_action": (
            "Test scenario only; no real remediation needed."
            if simulated else
            "Review source, validate activity, and follow incident response policy."
        ),
    }


def correlate_alerts(alerts, window_minutes=WINDOW_MINUTES,
                     threshold=THRESHOLD):
    groups = defaultdict(list)

    for alert in alerts:
        if alert.get("event_type") != "AUTHENTICATION_FAILURE_PATTERN":
            continue
        key = (
            alert.get("host", "unknown"),
            alert.get("process", "unknown"),
            alert.get("evidence_type", "unknown"),
        )
        groups[key].append(alert)

    incidents = []
    window = timedelta(minutes=window_minutes)

    for (host, process, evidence_type), events in groups.items():
        events.sort(key=parse_time)
        current = []

        for event in events:
            if current and parse_time(event) - parse_time(current[0]) > window:
                if len(current) >= threshold:
                    incidents.append(
                        make_incident(host, process, evidence_type, current)
                    )
                current = []
            current.append(event)

        if len(current) >= threshold:
            incidents.append(
                make_incident(host, process, evidence_type, current)
            )

    return incidents


def main():
    if not INPUT.exists():
        print("No alerts.jsonl found. Run the live monitor first.")
        return

    alerts = []
    for line in INPUT.read_text(encoding="utf-8").splitlines():
        try:
            alerts.append(json.loads(line))
        except json.JSONDecodeError:
            print("Warning: skipped malformed JSON alert line.")

    incidents = correlate_alerts(alerts)

    result = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "source": str(INPUT),
        "window_minutes": WINDOW_MINUTES,
        "threshold": THRESHOLD,
        "alerts_reviewed": len(alerts),
        "incidents": incidents,
        "note": "Event patterns are evidence, not proof of a successful attack.",
    }

    OUTPUT.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    print(f"\nSaved report: {OUTPUT.resolve()}")


if __name__ == "__main__":
    main()
