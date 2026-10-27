#!/usr/bin/env python3
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "network_events.jsonl"
INTERFACE = "eth0"

def main():
    if not shutil.which("tshark"):
        sys.exit("ERROR: tshark not found")

    cmd = [
        "tshark", "-l", "-n", "-i", INTERFACE,
        "-f", "udp port 53 or tcp port 53",
        "-T", "fields",
        "-E", "separator=\t",
        "-e", "frame.time_epoch",
        "-e", "ip.src", "-e", "ipv6.src",
        "-e", "ip.dst", "-e", "ipv6.dst",
        "-e", "dns.flags.response",
        "-e", "dns.qry.name", "-e", "dns.qry.type",
    ]

    print(f"[TraceForge] Capturing DNS metadata on {INTERFACE}")
    print(f"[TraceForge] Writing events to {OUTPUT}")
    print("[TraceForge] Ctrl+C stops capture.")

    try:
        with subprocess.Popen(
            cmd, stdout=subprocess.PIPE, text=True, bufsize=1
        ) as proc:
            for line in proc.stdout or []:
                fields = line.rstrip("\n").split("\t")
                fields += [""] * (8 - len(fields))
                ts, src4, src6, dst4, dst6, response, domain, qtype = fields[:8]

                if not domain:
                    continue

                event = {
                    "timestamp_utc": (
                        datetime.fromtimestamp(float(ts), timezone.utc).isoformat()
                        if ts else datetime.now(timezone.utc).isoformat()
                    ),
                    "event_type": "DNS_RESPONSE" if response.strip().lower() in {"1", "true"} else "DNS_QUERY",
                    "evidence_type": "LIVE_TSHARK_DNS_METADATA",
                    "interface": INTERFACE,
                    "source_ip": src4 or src6 or None,
                    "destination_ip": dst4 or dst6 or None,
                    "domain": domain,
                    "query_type": qtype or "unknown",
                    "simulated": False,
                }

                with OUTPUT.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(event) + "\n")

                print(json.dumps(event), flush=True)

            if proc.returncode:
                sys.exit(proc.returncode)
    except KeyboardInterrupt:
        print("\n[TraceForge] DNS monitor stopped.")
    except FileNotFoundError:
        sys.exit("ERROR: tshark could not start")

if __name__ == "__main__":
    main()
