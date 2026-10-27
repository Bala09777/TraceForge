"""SHA-256 evidence manifest and verification."""
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PRIVATE = Path(__file__).resolve().parent / "instance"
MANIFEST = PRIVATE / "evidence_manifest.json"
SOURCES = ("alerts.jsonl", "incidents.json", "incidents.csv")


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def current_evidence():
    result = []
    for name in SOURCES:
        path = ROOT / name
        if path.is_file():
            stat = path.stat()
            result.append({
                "file": name,
                "sha256": digest(path),
                "size_bytes": stat.st_size,
                "modified_utc": datetime.fromtimestamp(
                    stat.st_mtime, timezone.utc
                ).isoformat(),
            })
        else:
            result.append({"file": name, "status": "not present"})
    return result


def create_manifest():
    PRIVATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not MANIFEST.exists():
        payload = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "algorithm": "SHA-256",
            "evidence": current_evidence(),
            "note": "Baseline snapshot; create a new snapshot only after reviewing evidence changes.",
        }
        fd = os.open(MANIFEST, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
            f.write("\n")
    return verify_manifest()


def verify_manifest():
    if not MANIFEST.is_file():
        return {
            "status": "NO_BASELINE",
            "message": "No baseline exists. Create one after reviewing current evidence.",
            "items": [],
        }
    try:
        baseline = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"status": "ERROR", "message": "Manifest unreadable.", "items": []}

    original = {
        x["file"]: x.get("sha256")
        for x in baseline.get("evidence", [])
        if isinstance(x, dict) and x.get("sha256")
    }
    current = {x["file"]: x for x in current_evidence()}
    items = []
    for name in SOURCES:
        now = current.get(name, {})
        expected = original.get(name)
        actual = now.get("sha256")
        if expected is None and actual is None:
            state = "NOT_PRESENT_AT_BASELINE"
        elif expected is None:
            state = "NEW_FILE"
        elif actual is None:
            state = "MISSING"
        elif expected == actual:
            state = "MATCH"
        else:
            state = "CHANGED"
        items.append({
            "file": name,
            "status": state,
            "expected_sha256": expected,
            "current_sha256": actual,
        })
    statuses = {x["status"] for x in items}
    overall = "MATCH" if statuses <= {"MATCH", "NOT_PRESENT_AT_BASELINE"} else "REVIEW_REQUIRED"
    return {
        "status": overall,
        "algorithm": "SHA-256",
        "baseline_created_at": baseline.get("created_at"),
        "items": items,
        "message": (
            "Hashes match the stored baseline."
            if overall == "MATCH"
            else "Evidence differs from the baseline or is missing. Investigate before trusting it."
        ),
    }
