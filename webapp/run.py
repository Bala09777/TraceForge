"""Waitress launch entry point for TraceForge."""
import os
from ipaddress import ip_address

from app import app


def main():
    try:
        from waitress import serve
    except ImportError:
        raise SystemExit(
            "Waitress is missing. Install it with: .venv/bin/pip install waitress"
        )

    host = os.environ.get("TRACEFORGE_BIND", "127.0.0.1")
    port = int(os.environ.get("TRACEFORGE_PORT", os.environ.get("PORT", "5050")))

    if not 1 <= port <= 65535:
        raise SystemExit("TRACEFORGE_PORT must be between 1 and 65535.")

    if host not in ("127.0.0.1", "localhost", "0.0.0.0"):
        try:
            ip_address(host)
        except ValueError:
            raise SystemExit("TRACEFORGE_BIND must be a valid IP address.")

    if host == "0.0.0.0":
        print(
            "WARNING: listening on all interfaces. Use only on a trusted, "
            "firewalled network; HTTP does not encrypt credentials."
        )

    serve(app, host=host, port=port, threads=4)


if __name__ == "__main__":
    main()
