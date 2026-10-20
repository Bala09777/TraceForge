#!/usr/bin/env python3
import csv
import json
from pathlib import Path

SOURCE = Path("incidents.json")
OUTPUT = Path("incidents.csv")

def main():
    if not SOURCE.exists():
        print("incidents.json not found. Run traceforge_correlate.py first.")
        return

    with SOURCE.open(encoding="utf-8") as file:
        report = json.load(file)

    incidents = report.get("incidents", [])
    columns = [
        "incident_type",
        "severity",
        "host",
        "process",
        "event_count",
        "first_seen_utc",
        "last_seen_utc",
        "evidence_type",
        "simulated",
        "recommended_action",
    ]

    with OUTPUT.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        for incident in incidents:
            writer.writerow({
                column: incident.get(column, "")
                for column in columns
            })

    print(f"Exported {len(incidents)} incident(s) to {OUTPUT.resolve()}")

if __name__ == "__main__":
    main()
