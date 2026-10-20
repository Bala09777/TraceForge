#!/usr/bin/env python3
import ipaddress
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

OUTPUT = Path("alerts.jsonl")

PATTERNS = (
    "failed password",
    "authentication failure",
    "invalid user",
    "failed login",
    "authentication failed",
)

SOURCE_IP_PATTERN = re.compile(
    r"\bfrom\s+([0-9a-fA-F:.]+)\s+port\s+\d+\b"
    r"|\brhost=([0-9a-fA-F:.]+)\b",
    re.IGNORECASE,
)


def extract_source_ip(message):
    match = SOURCE_IP_PATTERN.search(message)
    if not match:
        return None

    candidate = match.group(1) or match.group(2)

    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def main():
    print("[TraceForge] Live journal monitor started.")
    print("[TraceForge] Monitoring SSH authentication failure patterns.")
    print("[TraceForge] Press Ctrl+C to stop.")
    print(f"[TraceForge] Alert log: {OUTPUT.resolve()}")

    cmd = ["journalctl", "--follow", "--lines=0", "--output=json"]

    try:
        with subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=None,
            text=True,
            bufsize=1,
        ) as proc:
            if proc.stdout is None:
                raise RuntimeError("Unable to read journal output")

            for line in proc.stdout:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                message = str(event.get("MESSAGE", ""))
                lower = message.lower()

                if not any(pattern in lower for pattern in PATTERNS):
                    continue

                simulated = "TRACEFORGE_TEST" in message
                process_name = str(event.get("_COMM", "unknown"))

                # Keep controlled test events separate from real evidence.
                if simulated:
                    evidence_type = "SIMULATED_TEST_EVENT"
                    severity = "TEST"
                else:
                    # Only treat sshd-originated messages as SSH evidence.
                    if process_name != "sshd":
                        continue

                    evidence_type = "SSH_AUTH_LOG_PATTERN"
                    severity = "MEDIUM"

                raw_ts = event.get("__REALTIME_TIMESTAMP")

                if raw_ts:
                    timestamp = datetime.fromtimestamp(
                        int(raw_ts) / 1_000_000,
                        tz=timezone.utc,
                    ).isoformat()
                else:
                    timestamp = datetime.now(timezone.utc).isoformat()

                alert = {
                    "timestamp_utc": timestamp,
                    "severity": severity,
                    "event_type": "AUTHENTICATION_FAILURE_PATTERN",
                    "evidence_type": evidence_type,
                    "process": process_name,
                    "systemd_unit": event.get("_SYSTEMD_UNIT", "unknown"),
                    "source_ip": extract_source_ip(message),
                    "message": message,
                    "host": event.get("_HOSTNAME", "unknown"),
                    "simulated": simulated,
                }

                with OUTPUT.open("a", encoding="utf-8") as file:
                    file.write(json.dumps(alert) + "\n")

                print("\n[TRACEFORGE ALERT]")
                print(json.dumps(alert, indent=2), flush=True)

    except KeyboardInterrupt:
        print("\n[TraceForge] Monitoring stopped.")
    except FileNotFoundError:
        print("ERROR: journalctl not found.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
