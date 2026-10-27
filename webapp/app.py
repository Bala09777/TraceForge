import csv
import io
import json
import os
import secrets
import time
from collections import Counter
from pathlib import Path
from functools import wraps

from flask import (
    Flask, abort, make_response, redirect, render_template,
    request, session, url_for, Response
)
from werkzeug.security import check_password_hash
from analysis_engine import analyze_incidents
from integrity import create_manifest, verify_manifest

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = Path(__file__).resolve().parent / "instance" / "config.json"

# Prefer deployment environment variables; fall back to the private local config.
CONFIG = {
    "secret_key": os.environ.get("TRACEFORGE_SECRET_KEY"),
    "password_hash": os.environ.get("TRACEFORGE_PASSWORD_HASH"),
}

if not CONFIG["secret_key"] or not CONFIG["password_hash"]:
    if CONFIG_PATH.is_file():
        with CONFIG_PATH.open(encoding="utf-8") as f:
            local_config = json.load(f)
        CONFIG["secret_key"] = CONFIG["secret_key"] or local_config.get("secret_key")
        CONFIG["password_hash"] = CONFIG["password_hash"] or local_config.get("password_hash")

if not CONFIG.get("secret_key") or not CONFIG.get("password_hash"):
    raise RuntimeError(
        "Admin config missing. Set TRACEFORGE_SECRET_KEY and TRACEFORGE_PASSWORD_HASH "
        "or run .venv/bin/python webapp/setup_admin.py locally."
    )

app = Flask(__name__)
app.secret_key = CONFIG["secret_key"]
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Enable only when HTTPS is configured.
    SESSION_COOKIE_SECURE=os.environ.get("TRACEFORGE_HTTPS", "0") == "1",
    MAX_CONTENT_LENGTH=16 * 1024,
)

LOGIN_ATTEMPTS = {}
MAX_ATTEMPTS = 8
LOCK_SECONDS = 300


def read_json(path, default):
    try:
        with path.open(encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError, TypeError):
        return default


def read_alerts():
    result = []
    path = ROOT / "alerts.jsonl"
    try:
        with path.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                    if isinstance(item, dict):
                        result.append(item)
                except ValueError:
                    continue
    except OSError:
        pass
    return result[-500:]


def read_incidents():
    raw = read_json(ROOT / "incidents.json", [])
    if isinstance(raw, dict):
        raw = raw.get("incidents", [])
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict)][-500:]



def read_network_events():
    """Read recent DNS metadata captured by the local tshark monitor."""
    result = []
    path = ROOT / "network_events.jsonl"
    try:
        with path.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                if (
                    isinstance(item, dict)
                    and item.get("evidence_type") == "LIVE_TSHARK_DNS_METADATA"
                ):
                    result.append(item)
    except OSError:
        pass
    return result[-100:]

def dashboard_data():
    alerts = read_alerts()
    incidents = read_incidents()
    hosts = set()
    ips = set()
    for item in incidents + alerts:
        host = item.get("host") or item.get("hostname")
        ip = item.get("source_ip") or item.get("src_ip")
        if host:
            hosts.add(str(host))
        if ip:
            ips.add(str(ip))

    return {
        "alerts": alerts,
        "incidents": incidents,
        "network_events": read_network_events(),
        "alert_count": len(alerts),
        "incident_count": len(incidents),
        "host_count": len(hosts),
        "source_count": len(ips),
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def authenticated(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper


@app.before_request
def security_checks():
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if not session.get("authenticated") and request.endpoint != "login":
            abort(403)
        submitted = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not secrets.compare_digest(submitted, expected):
            abort(400, "CSRF validation failed.")


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; "
        "img-src 'self' data:; object-src 'none'; base-uri 'self'; "
        "frame-ancestors 'none'; form-action 'self'"
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/login", methods=["GET", "POST"])
def login():
    ip = request.remote_addr or "unknown"
    state = LOGIN_ATTEMPTS.get(ip, {"count": 0, "until": 0})
    now = time.time()

    if state["until"] > now:
        return render_template(
            "login.html", csrf_token=session.setdefault("csrf_token", secrets.token_urlsafe(32)),
            error="Too many failed attempts. Wait a few minutes."
        ), 429

    error = ""
    session.setdefault("csrf_token", secrets.token_urlsafe(32))

    if request.method == "POST":
        password = request.form.get("password", "")
        if len(password) > 1024:
            password = ""
        if check_password_hash(CONFIG["password_hash"], password):
            LOGIN_ATTEMPTS.pop(ip, None)
            session.clear()
            session["authenticated"] = True
            session["csrf_token"] = secrets.token_urlsafe(32)
            return redirect(url_for("dashboard"))

        state["count"] += 1
        if state["count"] >= MAX_ATTEMPTS:
            state["until"] = now + LOCK_SECONDS
        LOGIN_ATTEMPTS[ip] = state
        error = "Invalid credentials."

    return render_template("login.html", csrf_token=session["csrf_token"], error=error)


@app.post("/logout")
@authenticated
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
@authenticated
def dashboard():
    data = dashboard_data()
    return render_template(
        "dashboard.html",
        data=data,
        csrf_token=session["csrf_token"],
    )


@app.get("/api/dashboard")
@authenticated
def api_dashboard():
    return dashboard_data()


@app.get("/export/incidents.csv")
@authenticated
def export_csv():
    incidents = read_incidents()
    output = io.StringIO()
    fields = ["timestamp", "host", "process", "source_ip", "evidence_type", "event_count", "risk_score"]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()

    for incident in incidents:
        row = dict(incident)
        events = incident.get("events", [])
        row.setdefault("event_count", len(events) if isinstance(events, list) else "")
        writer.writerow(row)

    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = 'attachment; filename="traceforge-incidents.csv"'
    return response


@app.errorhandler(400)
def bad_request(error):
    return render_template("error.html", code=400, message="Request validation failed."), 400


@app.errorhandler(403)
def forbidden(error):
    return render_template("error.html", code=403, message="Access denied."), 403


@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", code=404, message="Page not found."), 404



@app.get("/analysis")
@authenticated
def analysis_page():
    result = analyze_incidents(read_incidents())
    return render_template(
        "analysis.html", result=result, csrf_token=session["csrf_token"]
    )


@app.get("/integrity")
@authenticated
def integrity_page():
    result = verify_manifest()
    return render_template(
        "integrity.html", result=result, csrf_token=session["csrf_token"]
    )


@app.post("/integrity/baseline")
@authenticated
def integrity_baseline():
    # This creates a baseline only if one does not already exist.
    create_manifest()
    return redirect(url_for("integrity_page"))


@app.get("/export/analysis.json")
@authenticated
def export_analysis():
    result = analyze_incidents(read_incidents())
    response = make_response(json.dumps(result, indent=2))
    response.headers["Content-Type"] = "application/json; charset=utf-8"
    response.headers["Content-Disposition"] = 'attachment; filename="traceforge-analysis.json"'
    return response

if __name__ == "__main__":
    # Local-only development mode. Use a production WSGI server for LAN deployment.
    app.run(host="127.0.0.1", port=5050, debug=False)
