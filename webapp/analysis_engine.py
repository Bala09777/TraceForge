"""Explainable anomaly analysis for TraceForge incident records."""
import math
from collections import Counter
from datetime import datetime, timezone

try:
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True
except ImportError:
    IsolationForest = None
    ML_AVAILABLE = False


def _features(item):
    events = item.get("events", [])
    count = len(events) if isinstance(events, list) else 0
    try:
        count = int(item.get("event_count", count) or count)
    except (ValueError, TypeError):
        pass
    simulated = (
        item.get("simulated") is True
        or str(item.get("evidence_type", "")).upper() == "SIMULATED_TEST_EVENT"
    )
    return {
        "count": max(0, count),
        "has_ip": bool(item.get("source_ip") or item.get("src_ip")),
        "simulated": simulated,
        "process": str(item.get("process", "unknown")),
        "host": str(item.get("host", item.get("hostname", "unknown"))),
    }


def analyze_incidents(incidents):
    """Return explainable scores; scores are triage hints, not proof."""
    incidents = [x for x in incidents if isinstance(x, dict)]
    features = [_features(x) for x in incidents]
    counts = Counter(f["process"] for f in features)
    scores = [0.0] * len(incidents)
    reasons = [[] for _ in incidents]
    methods = "explainable_rules"

    if ML_AVAILABLE and len(incidents) >= 8:
        matrix = [[
            math.log1p(f["count"]),
            int(f["has_ip"]),
            math.log1p(counts[f["process"]]),
        ] for f in features]
        try:
            model = IsolationForest(
                n_estimators=100, contamination="auto", random_state=42
            )
            model.fit(matrix)
            raw = model.decision_function(matrix)
            scores = [
                max(0.0, min(100.0, (0.15 - float(v)) * 250))
                for v in raw
            ]
            methods = "isolation_forest_plus_rules"
        except (ValueError, TypeError):
            methods = "explainable_rules"

    for i, f in enumerate(features):
        why = []
        rule_score = 0
        if f["count"] >= 20:
            rule_score += 45
            why.append("High event-record volume (20+)")
        elif f["count"] >= 10:
            rule_score += 30
            why.append("Elevated event-record volume (10+)")
        elif f["count"] >= 5:
            rule_score += 15
            why.append("Multiple event records (5+)")
        if not f["has_ip"]:
            why.append("Source IP unavailable; attribution is limited")
        if f["simulated"]:
            why.append("Synthetic test evidence; not a confirmed real attack")
        if f["count"] == 0:
            why.append("Event count unavailable or zero")
        if methods == "explainable_rules":
            scores[i] = float(rule_score)
        else:
            scores[i] = min(100.0, max(scores[i], rule_score))
        if not why:
            why.append("No high-volume rule triggered")
        reasons[i] = why

    results = []
    for item, score, why in zip(incidents, scores, reasons):
        result = dict(item)
        result["risk_score"] = round(score, 1)
        result["risk_band"] = (
            "HIGH" if score >= 60 else
            "MEDIUM" if score >= 25 else "LOW"
        )
        result["risk_reasons"] = why
        result["analysis_method"] = methods
        result["score_is_proof"] = False
        results.append(result)

    return {
        "method": methods,
        "ml_library_available": ML_AVAILABLE,
        "incident_count": len(results),
        "incidents": sorted(
            results, key=lambda x: x["risk_score"], reverse=True
        ),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "disclaimer": "Risk scores prioritize review; they are not proof of malicious activity.",
    }
