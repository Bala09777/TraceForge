#!/usr/bin/env python3
"""Explainable anomaly checks for captured DNS metadata."""

import json
import math
from collections import Counter
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent
EVENTS_FILE = ROOT / "network_events.jsonl"
ALERTS_FILE = ROOT / "alerts.jsonl"

def load_events():
    events = []
    try:
        with EVENTS_FILE.open(encoding="utf-8") as f:
            for line in f:
                try:
                    event = json.loads(line)
                except (json.JSONDecodeError, TypeError):
                    continue
                if (
                    isinstance(event, dict)
                    and event.get("evidence_type") == "LIVE_TSHARK_DNS_METADATA"
                    and event.get("event_type") == "DNS_QUERY"
                    and event.get("domain")
                ):
                    events.append(event)
    except FileNotFoundError:
        print(f"DNS event file not found: {EVENTS_FILE}")
    return events


def calculate_entropy(value):
    """Shannon entropy in bits per character."""
    import math
    from collections import Counter

    if not value:
        return 0.0
    counts = Counter(value.lower())
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def inspect_domain(domain):
    """Return review indicators, not a maliciousness verdict."""
    indicators = []
    labels = domain.rstrip(".").lower().split(".")

    # Synthetic TraceForge test domains are not production anomaly evidence.
    if any(label.startswith(("traceforge-test-", "tf-test-", "tf-check-"))
           for label in labels):
        return indicators

    for label in labels[:-2]:
        if len(label) >= 30:
            indicators.append({
                "indicator": "LONG_DNS_LABEL",
                "label_length": len(label),
                "label_sample": label[:48],
                "reason": "A DNS label is 30 or more characters long."
            })
        if len(label) >= 20 and calculate_entropy(label) >= 3.5:
            indicators.append({
                "indicator": "HIGH_ENTROPY_DNS_LABEL",
                "label_length": len(label),
                "label_entropy": round(calculate_entropy(label), 3),
                "label_sample": label[:48],
                "reason": "A long DNS label has high character entropy."
            })
    return indicators

def main():
    events = load_events()
    if not events:
        print("No live DNS query events found. Start the DNS monitor first.")
        return

    domain_counts = Counter(
        str(e["domain"]).lower().rstrip(".") for e in events
    )
    source_counts = Counter(
        str(e.get("source_ip", "unknown")) for e in events
    )

    alerts = []
    # Conservative, explainable threshold for this current event sample.
    for domain, count in domain_counts.items():
        if count >= 30:
            alerts.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "alert_type": "DNS_HIGH_QUERY_COUNT",
                "severity": "medium",
                "domain": domain,
                "event_count": count,
                "evidence_type": "LIVE_TSHARK_DNS_METADATA",
                "reason": f"Observed {count} DNS queries for the same domain in the available log sample.",
                "simulated": False,
            })

    for source_ip, count in source_counts.items():
        if count >= 100:
            alerts.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "alert_type": "DNS_HIGH_QUERY_VOLUME",
                "severity": "medium",
                "source_ip": source_ip,
                "event_count": count,
                "evidence_type": "LIVE_TSHARK_DNS_METADATA",
                "reason": f"Observed {count} DNS queries from this source in the available log sample.",
                "simulated": False,
            })

    print(f"DNS query events analyzed: {len(events)}")
    print(f"Unique queried domains: {len(domain_counts)}")
    print(f"Source addresses: {len(source_counts)}")
    indicators_found = []
    for domain in domain_counts:
        for indicator in inspect_domain(domain):
            indicators_found.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "alert_type": indicator["indicator"],
                "severity": "low",
                "domain": domain,
                "evidence_type": "LIVE_TSHARK_DNS_METADATA",
                "reason": indicator["reason"],
                "details": indicator,
                "simulated": False,
            })

    print(f"Candidate alerts: {len(alerts)}")
    print(f"Domain-label indicators: {len(indicators_found)}")

    # Append only new indicators; preserve existing alert records.
    existing_keys = set()
    if ALERTS_FILE.exists():
        with ALERTS_FILE.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    old_item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(old_item, dict):
                    alert_type = old_item.get("alert_type")
                    domain = old_item.get("domain")
                    if alert_type in {"DNS_HIGH_QUERY_COUNT", "DNS_HIGH_QUERY_VOLUME"}:
                        third_key = old_item.get("source_ip")
                    else:
                        third_key = (old_item.get("details") or {}).get("label_sample")
                    existing_keys.add((alert_type, domain, third_key))

    saved = 0
    with ALERTS_FILE.open("a", encoding="utf-8") as f:
        for indicator in indicators_found:
            details = indicator.get("details") or {}
            key = (
                indicator.get("alert_type"),
                indicator.get("domain"),
                details.get("label_sample"),
            )
            if key in existing_keys:
                continue
            f.write(json.dumps(indicator) + "\n")
            existing_keys.add(key)
            saved += 1
            print(json.dumps(indicator, indent=2))

    print(f"New DNS indicators persisted: {saved}")


    if alerts:
        saved_threshold_alerts = 0
        with ALERTS_FILE.open("a", encoding="utf-8") as f:
            for alert in alerts:
                # Stable key prevents the same threshold alert being appended
                # again when the detector is rerun on the same event sample.
                key = (
                    alert.get("alert_type"),
                    alert.get("domain"),
                    alert.get("source_ip"),
                )
                if key in existing_keys:
                    continue

                f.write(json.dumps(alert) + "\n")
                existing_keys.add(key)
                saved_threshold_alerts += 1
                print(json.dumps(alert, indent=2))

        print(f"New DNS threshold alerts persisted: {saved_threshold_alerts}")
    else:
        print("No events crossed the current thresholds.")

    print("Note: These are heuristic candidates, not proof of malicious activity.")

if __name__ == "__main__":
    main()
